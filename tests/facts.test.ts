import assert from "node:assert/strict";
import test from "node:test";
import { describeActionFacts } from "../extensions/auto-mode.ts";

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
		// Second blocked action in session 01a0dc0c: sed is not on the read-only list.
		"ssh prod-proxy 'cd ~/proxy && grep -n master_key config.yaml | sed \"s/:.*/: <redacted>/\"'",
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

