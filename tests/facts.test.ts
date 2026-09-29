import assert from "node:assert/strict";
import test from "node:test";
import { describeActionFacts, mentionsCredentials } from "../extensions/auto-mode.ts";

function bash(command: string): string {
	return JSON.stringify({ toolName: "bash", input: { command } });
}

function factMap(facts: string): Record<string, string> {
	const map: Record<string, string> = {};
	for (const line of facts.split("\n")) {
		const index = line.indexOf(": ");
		if (index > 0) map[line.slice(0, index)] = line.slice(index + 2);
	}
	return map;
}

// The first action pi-automode blocked in session 01a0dc0c.
const SESSION_PROBE = bash(
	"timeout 25 ssh -o BatchMode=yes -o ConnectTimeout=15 prod-proxy 'hostname; whoami; ls ~/proxy/ | head -20' 2>&1 | head -30",
);

test("describeActionFacts marks a read-only ssh probe on a trusted host", () => {
	const facts = factMap(describeActionFacts(SESSION_PROBE, ["prod-proxy"]));
	assert.equal(facts.parser, "ok");
	assert.equal(facts.commands, "timeout, ssh, head");
	assert.equal(facts.local_file_writes, "none");
	assert.equal(
		facts.remote_shell,
		"ssh host=prod-proxy trusted=true commands=hostname, whoami, ls, head read_only=true",
	);
	assert.equal(facts.read_only, "true");
});

test("describeActionFacts reports an unlisted ssh host as untrusted", () => {
	const facts = factMap(describeActionFacts(SESSION_PROBE, []));
	assert.match(facts.remote_shell!, /host=prod-proxy trusted=false /);
	// Trust is about scope, not mutation, so read_only is unchanged.
	assert.equal(facts.read_only, "true");
});

test("describeActionFacts normalizes user@host and case before the trust check", () => {
	const facts = factMap(
		describeActionFacts(bash("ssh deploy@Prod-Proxy uptime"), ["prod-proxy"]),
	);
	assert.match(facts.remote_shell!, /host=prod-proxy trusted=true /);
});

test("describeActionFacts never marks a writing remote command read-only", () => {
	for (const command of [
		"ssh prod-proxy 'rm -rf ~/proxy'",
		"ssh prod-proxy 'ls > listing.txt'",
		"ssh prod-proxy 'docker compose restart'",
		// Nested remote shells are not followed.
		"ssh prod-proxy 'ssh other-host ls'",
		// Unsafe forms of otherwise read-only commands.
		"ssh prod-proxy 'find / -name x -delete'",
		"ssh prod-proxy 'sort -o out.txt in.txt'",
		// Dynamic words cannot be verified.
		"ssh prod-proxy \"ls $(touch /tmp/x)\"",
	]) {
		const facts = factMap(describeActionFacts(bash(command), ["prod-proxy"]));
		assert.match(facts.remote_shell!, /read_only=unverified$/, command);
		assert.equal(facts.read_only, "unverified", command);
	}
});

test("a read-only search for a secret is read-only but names a credential", () => {
	// Second blocked action in session 01a0dc0c. sed substitutions only print, so
	// it is read-only; the credential guard keeps it on the normal intent threshold.
	const command = bash("ssh prod-proxy 'cd ~/proxy && grep -n master_key config.yaml | sed \"s/:.*/: <redacted>/\"'");
	assert.equal(factMap(describeActionFacts(command, ["prod-proxy"])).read_only, "true");
	assert.equal(mentionsCredentials(command), true);
});

test("describeActionFacts does not verify ssh forms that run or expose more", () => {
	for (const command of [
		"ssh prod-proxy",
		"ssh -L 8080:localhost:80 prod-proxy ls",
		"ssh -o ProxyCommand='nc evil 22' prod-proxy ls",
		"ssh -o StrictHostKeyChecking=no prod-proxy ls",
		"ssh -F ./ssh_config prod-proxy ls",
	]) {
		const facts = factMap(describeActionFacts(bash(command), ["prod-proxy"]));
		assert.match(facts.remote_shell!, /read_only=unverified$/, command);
		assert.equal(facts.read_only, "unverified", command);
	}
});

test("describeActionFacts verifies only read-only curl forms", () => {
	for (const command of [
		"curl -s http://localhost:4000/metrics/",
		"curl -sSL https://api.github.com/repos/nodejs/node/releases/latest",
		"curl -s -o /dev/null -w '%{http_code}\\n' http://localhost:4000/metrics",
		"curl -s -D - -o /dev/null http://localhost:4000/metrics",
		"curl --silent --max-time 5 -H 'Accept: text/plain' http://localhost:8080/health",
		"curl -I https://example.com",
	]) {
		assert.equal(factMap(describeActionFacts(bash(command), [])).read_only, "true", command);
	}
	for (const command of [
		"curl -o page.html https://example.com",
		"curl -sO https://example.com/file.tar.gz",
		"curl -X POST https://example.com/api",
		"curl -d 'a=1' https://example.com/api",
		"curl --data-binary @file https://example.com/api",
		"curl -F file=@x https://example.com/upload",
		"curl -T x https://example.com/upload",
		"curl -k https://example.com",
		"curl -K ./curlrc https://example.com",
		"curl -c jar.txt https://example.com",
		"curl -D headers.txt https://example.com",
		"curl --trace out.txt https://example.com",
		"curl --json '{}' https://example.com/api",
	]) {
		assert.equal(factMap(describeActionFacts(bash(command), [])).read_only, "unverified", command);
	}
});

test("describeActionFacts says where a remote read's redirect writes", () => {
	const facts = describeActionFacts(
		bash("ssh -o BatchMode=yes prod-proxy 'curl -s http://localhost:4000/metrics/' > /tmp/m.txt; wc -l /tmp/m.txt"),
		["prod-proxy"],
	);
	const map = factMap(facts);
	assert.equal(map.local_file_writes, "/tmp/m.txt");
	assert.equal(
		map.write_location,
		"local only: the local shell writes /tmp/m.txt on this machine; the remote command writes nothing",
	);
	// The whole action still writes a file, so it is not read-only.
	assert.equal(map.read_only, "unverified");
	// No line when the remote command is not verified or there is no local write.
	assert.doesNotMatch(
		describeActionFacts(bash("ssh prod-proxy 'rm -rf x' > /tmp/m.txt"), []),
		/write_location/,
	);
	assert.doesNotMatch(describeActionFacts(SESSION_PROBE, []), /write_location/);
	assert.doesNotMatch(describeActionFacts(bash("ls > out.txt"), []), /write_location/);
});

test("describeActionFacts reports local file redirects and ignores fd duplication", () => {
	const writes = factMap(describeActionFacts(bash("ls -la > out.txt"), []));
	assert.equal(writes.local_file_writes, "out.txt");
	assert.equal(writes.read_only, "unverified");

	const dup = factMap(describeActionFacts(bash("cat README.md 2>&1 | head -5 2>/dev/null"), []));
	assert.equal(dup.local_file_writes, "none");
	assert.equal(dup.read_only, "true");
	assert.equal(dup.remote_shell, undefined);
});

test("describeActionFacts does not mark non-allowlisted local commands read-only", () => {
	const facts = factMap(describeActionFacts(bash("npm install && ls"), []));
	assert.equal(facts.commands, "npm, ls");
	assert.equal(facts.read_only, "unverified");
});

test("describeActionFacts reports a parse failure as unverified", () => {
	const facts = factMap(describeActionFacts(bash("ls 'unterminated"), []));
	assert.equal(facts.parser, "failed");
	assert.equal(facts.read_only, "unverified");
});

test("describeActionFacts returns none for non-bash or unreadable actions", () => {
	assert.equal(
		describeActionFacts(JSON.stringify({ toolName: "write", input: { path: "a" } }), []),
		"",
	);
	assert.equal(describeActionFacts("not json", []), "");
	assert.equal(
		describeActionFacts(JSON.stringify({ toolName: "bash", input: {} }), []),
		"",
	);
});

// --- SQL -------------------------------------------------------------------

function sqlLine(command: string): string | undefined {
	return factMap(describeActionFacts(bash(command), ["prod-proxy"])).sql;
}

const VIA_DOCKER = "ssh prod-proxy 'sudo -n docker exec -i app_db psql -U app -d app -P pager=off' <<'SQL' 2>&1 | head -60";

test("describeActionFacts reports read-only SQL sent to a database client", () => {
	assert.equal(
		sqlLine(`${VIA_DOCKER}\nSELECT date_trunc('day', created_at), count(*)\nFROM sessions -- recent\nWHERE created_at > now() - interval '3 days'\nGROUP BY 1;\nSQL`),
		"client=psql statements=SELECT read_only=true",
	);
	assert.equal(
		sqlLine("ssh prod-proxy 'sudo -n docker exec app_db psql -U app -d app -c \"\\d sessions\"'"),
		"client=psql statements=\\d read_only=true",
	);
	assert.equal(
		sqlLine(`${VIA_DOCKER}\n\\echo === counts ===\nWITH s AS (SELECT 1 AS n) SELECT n FROM s;\nEXPLAIN SELECT 1;\nSQL`),
		"client=psql statements=\\echo, WITH, EXPLAIN read_only=true",
	);
	// A write word inside a string literal is data, not a statement.
	assert.equal(
		sqlLine(`${VIA_DOCKER}\nSELECT count(*) FROM audit WHERE action = 'delete' OR note = 'drop table x';\nSQL`),
		"client=psql statements=SELECT read_only=true",
	);
	assert.equal(sqlLine("mysql -h db -e 'select count(*) from orders'"), "client=mysql statements=SELECT read_only=true");
	// No database client, no sql line; naming a client is not running it.
	assert.equal(sqlLine("ssh prod-proxy 'uptime'"), undefined);
	assert.equal(sqlLine("ssh prod-proxy 'which psql; man mysql | head'"), undefined);
	assert.equal(sqlLine("kubectl exec -i db-0 -- psql -U app -c 'select 1'"), "client=psql statements=SELECT read_only=true");
});

test("describeActionFacts never marks writing or unknown SQL read-only", () => {
	for (const body of [
		"DELETE FROM sessions WHERE created_at < now();",
		"SELECT count(*) FROM sessions;\nDELETE FROM sessions WHERE user_id IS NULL;",
		"UPDATE users SET role = 'admin';",
		"TRUNCATE sessions;",
		"WITH gone AS (DELETE FROM sessions RETURNING id) SELECT count(*) FROM gone;",
		"SELECT * INTO sessions_copy FROM sessions;",
		"SELECT pg_terminate_backend(1234);",
		"EXPLAIN ANALYZE DELETE FROM sessions;",
		"SELECT 1 FOR UPDATE;",
		"\\copy sessions TO '/tmp/sessions.csv' CSV",
		"\\! rm -rf /tmp/x",
		"CALL cleanup();",
	]) {
		const line = sqlLine(`${VIA_DOCKER}\n${body}\nSQL`);
		assert.match(line ?? "", /read_only=unverified$/, body);
	}
	// SQL that cannot be read.
	assert.match(sqlLine("psql -U app -f cleanup.sql") ?? "", /read_only=unverified$/);
	assert.match(sqlLine("psql -U app") ?? "", /read_only=unverified$/);
	// An unquoted heredoc expands $(...) before psql sees it.
	assert.match(
		sqlLine("ssh prod-proxy 'psql -U app' <<SQL\nSELECT $(cat /tmp/q);\nSQL") ?? "",
		/read_only=unverified$/,
	);
});

test("a verified read-only SQL call through sudo and docker exec counts as read-only", () => {
	const select = factMap(describeActionFacts(
		bash(`${VIA_DOCKER}\nSELECT count(*) FROM sessions;\nSQL`),
		["prod-proxy"],
	));
	assert.match(select.remote_shell!, /read_only=true$/);
	assert.equal(select.read_only, "true");
	const kubectl = factMap(describeActionFacts(
		bash("kubectl exec -i -n prod db-0 -- psql -U app -c 'select 1'"),
		[],
	));
	assert.equal(kubectl.read_only, "true");
	for (const command of [
		`${VIA_DOCKER}\nDELETE FROM sessions;\nSQL`,
		// Only exec into an existing container; run starts one.
		"docker run --rm postgres psql -h db -c 'select 1'",
		// A sudo option outside the safe set.
		"sudo -s psql -c 'select 1'",
		// psql options that write files.
		"psql -o /tmp/out.txt -c 'select 1'",
		"psql -L /tmp/session.log -c 'select 1'",
		"mysql --tee=/tmp/t.log -e 'select 1'",
		// sqlite3 creates a missing database file.
		"sqlite3 app.db 'select 1'",
		// Unknown SQL.
		"psql -f cleanup.sql",
	]) {
		assert.equal(factMap(describeActionFacts(bash(command), [])).read_only, "unverified", command);
	}
});


// --- python HTTP reads -------------------------------------------------------

function python(body: string, opener = "python3 - <<'PY'"): string {
	return bash(`cd /tmp/paa-fix\n${opener}\n${body}\nPY`);
}

// The MR lookup that prompted in session 01a0d6e5 at 13:47.
const MR_READ = [
	"import json, urllib.request, os",
	'hdr = {"PRIVATE-TOKEN": os.environ[\'PRIVATE_TOKEN\']}',
	'P = "http://gitserver.mnl.azeus.com/api/v4/projects/719"',
	'd = json.load(urllib.request.urlopen(urllib.request.Request(f"{P}/merge_requests/116", headers=hdr), timeout=60))',
	'print(f"  MR !116: {d[\'title\']}")',
	'c = json.load(urllib.request.urlopen(urllib.request.Request(f"{P}/merge_requests/116/commits", headers=hdr), timeout=60))',
	"lines = (d['description'] or '').splitlines()",
	"for i, l in enumerate(lines[:48], 1):",
	'    print(f"{i:>4}: {l}")',
].join("\n");

test("describeActionFacts verifies a python script that only sends GET requests", () => {
	const facts = factMap(describeActionFacts(python(MR_READ), []));
	assert.equal(facts.python_http, "requests=GET only hosts=gitserver.mnl.azeus.com read_only=true");
	assert.equal(facts.read_only, "true");
});

test("describeActionFacts does not verify python that writes, sends a body, or runs code", () => {
	const writes = [
		// A PUT with a body, as the MR description updates did.
		MR_READ.replace("headers=hdr), timeout", 'data=json.dumps({"description": "x"}).encode(), headers=hdr, method="PUT"), timeout'),
		// A positional body makes urlopen send a POST.
		MR_READ.replace("headers=hdr), timeout=60)", 'headers=hdr), b"x", timeout=60)'),
		MR_READ.replace("headers=hdr)", "hdr, b\"x\")"),
		`${MR_READ}\nopen('/tmp/out.md', 'w').write(d['description'])`,
		`${MR_READ}\nimport subprocess\nsubprocess.run(['rm', '-rf', 'x'])`,
		`${MR_READ}\nos.system('rm -rf x')`,
		`${MR_READ}\nf = os.remove\nf('x')`,
		`${MR_READ}\ngetattr(os, 'sys' + 'tem')('x')`,
		`${MR_READ}\n[os.remove][0]('x')`,
		`${MR_READ}\nexec("import shutil")`,
		`${MR_READ}\nimport requests`,
		`${MR_READ}\n__import__('os').remove('x')`,
		`${MR_READ}\nprint(f"{os.remove('x')}")`,
	];
	for (const body of writes) {
		const facts = factMap(describeActionFacts(python(body), []));
		assert.equal(facts.read_only, "unverified", body);
		assert.match(facts.python_http ?? "read_only=unverified", /read_only=unverified/, body);
	}
	// An unquoted heredoc lets the shell expand the script first.
	assert.equal(factMap(describeActionFacts(python(MR_READ, "python3 - <<PY"), [])).read_only, "unverified");
	// A script file, `-c`, or a redirect out is not a verified stdin script.
	assert.equal(factMap(describeActionFacts(python(MR_READ, "python3 - > /tmp/o <<'PY'"), [])).read_only, "unverified");
	assert.equal(factMap(describeActionFacts(bash("python3 fetch.py"), [])).read_only, "unverified");
	// Without an HTTP call there is no python_http line; an allowlisted script still only reads.
	const plain = factMap(describeActionFacts(python("print(1)"), []));
	assert.equal(plain.python_http, undefined);
	assert.equal(plain.read_only, "true");
});

test("mentionsCredentials flags reads that name a secret, not env references or auth headers", () => {
	for (const command of [
		`ssh -o BatchMode=yes loki-litellm 'grep -n "master_key" ~/litellm/config.yaml | head -5'`,
		"cat .env",
		"grep -r API_KEY src/",
		"grep password config/app.yml",
		"cat ~/.ssh/id_rsa.pub",
		"jq .token ~/.pi/agent/auth.json",
		"grep -rn secret .",
	]) {
		assert.equal(mentionsCredentials(bash(command)), true, command);
	}
	for (const command of [
		`python3 - <<'PY'\nhdr = {"PRIVATE-TOKEN": os.environ['PRIVATE_TOKEN']}\nPY`,
		'curl -s -H "Authorization: Bearer $GITLAB_TOKEN" https://gitserver/api/v4/projects',
		'curl -s -H "PRIVATE-TOKEN: ${PRIVATE_TOKEN}" http://gitserver.mnl.azeus.com/api/v4/merge_requests/1',
		"curl -s http://localhost:4000/metrics",
		"grep -n tokenize src/lexer.ts",
	]) {
		assert.equal(mentionsCredentials(bash(command)), false, command);
	}
});

test("describeActionFacts verifies read-only git subcommands only", () => {
	for (const command of [
		"git status --porcelain",
		"git diff --stat origin/master...HEAD | sed 's/^/  /'",
		"git log --oneline -5",
		"git show 65979e4 --stat",
		"git rev-parse HEAD | cut -c1-8",
		"git -C /tmp/paa-fix diff --name-only",
		"git branch --show-current",
		"git ls-files code-lab",
		"git blame -L 10,20 src/a.js",
	]) {
		assert.equal(factMap(describeActionFacts(bash(command), [])).read_only, "true", command);
	}
	for (const command of [
		"git commit -m x",
		"git push origin HEAD",
		"git checkout origin/master -- file",
		"git diff --output=/tmp/x.diff",
		"git diff --ext-diff",
		"git -c core.pager='rm -rf ~' log",
		"git -c alias.x='!rm -rf ~' x",
		"git branch -D feature",
		"git branch new-branch",
		"git log --exec='touch x'",
		"git --git-dir=/other/.git log",
		"git diff origin/master...HEAD > /tmp/net.diff",
	]) {
		assert.equal(factMap(describeActionFacts(bash(command), [])).read_only, "unverified", command);
	}
});

test("describeActionFacts verifies sed only for substitutions and line printing", () => {
	for (const command of [
		"git diff --stat | sed 's/^/  /'",
		"sed -n '10,20p' src/a.js",
		"sed -n '$p' log.txt",
		"sed -E 's|/tmp/[^ ]+|<tmp>|g; s/x/y/' notes.txt",
		"cut -c1-8 ids.txt | tr a-z A-Z | uniq | nl",
	]) {
		assert.equal(factMap(describeActionFacts(bash(command), [])).read_only, "true", command);
	}
	for (const command of [
		"sed -i '' 's/a/b/' file.js",
		"sed --in-place 's/a/b/' file.js",
		"sed 's/a/b/w /tmp/out' file.js",
		"sed 's/a/b/e' file.js",
		"sed -n '1w /tmp/out' file.js",
		"sed -f script.sed file.js",
		"sed '1d' file.js > file.js",
		"sed 'e rm -rf ~' file",
	]) {
		assert.equal(factMap(describeActionFacts(bash(command), [])).read_only, "unverified", command);
	}
});
