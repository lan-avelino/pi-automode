import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
	CreatedPaths,
	birthTimesUsable,
	leadingCdDirectory,
	planAction,
	planActionOrPrefix,
	planActionPrefix,
	restoresData,
	scopeLine,
	type ClaimSet,
} from "../extensions/auto-mode/created-paths.ts";
import { FakeFs } from "./fake-fs.ts";

const SESSION = JSON.parse(
	readFileSync(new URL("./fixtures/session-01a0d6e5-commands.json", import.meta.url), "utf8"),
) as Record<"creation" | "refresh_1451" | "refresh_1457", string>;

test("planAction accepts the worktree creation from session 01a0d6e5", () => {
	assert.deepEqual(planAction(SESSION.creation), {
		creations: [
			{ path: "/tmp/paa-r2", how: "git worktree add" },
			{ path: "/tmp/paa-r1", how: "git worktree add" },
			{ path: "/tmp/review-callbound.diff", how: "redirect" },
			{ path: "/tmp/review-mcplife.diff", how: "redirect" },
		],
		removals: [],
		writes: ["/tmp/review-callbound.diff", "/tmp/review-mcplife.diff"],
		links: [],
	});
});

test("planAction accepts both worktree refreshes from session 01a0d6e5", () => {
	for (const command of [SESSION.refresh_1451, SESSION.refresh_1457]) {
		assert.deepEqual(planAction(command), {
			creations: [
				{ path: "/tmp/paa-r1", how: "git worktree add" },
				{ path: "/tmp/review2-mcplife-delta.diff", how: "redirect" },
				{ path: "/tmp/review2-mcplife-net.diff", how: "redirect" },
			],
			removals: ["/tmp/paa-r1"],
			writes: ["/tmp/review2-mcplife-delta.diff", "/tmp/review2-mcplife-net.diff"],
			links: ["/tmp/paa-r1/code-lab/tools/code-review/node_modules"],
		});
	}
});

test("planAction reads each table row and its options", () => {
	assert.deepEqual(planAction("mkdir -p -v /tmp/a /tmp/b")?.creations, [
		{ path: "/tmp/a", how: "mkdir" },
		{ path: "/tmp/b", how: "mkdir" },
	]);
	assert.deepEqual(planAction("rm -rfv -- /tmp/a /tmp/b")?.removals, ["/tmp/a", "/tmp/b"]);
	assert.deepEqual(planAction("rm --recursive --force /tmp/a")?.removals, ["/tmp/a"]);
	assert.deepEqual(planAction("git -C /work/repo worktree remove -f -f /tmp/w")?.removals, ["/tmp/w"]);
	assert.deepEqual(planAction("git worktree add --lock -f /tmp/w")?.creations, [
		{ path: "/tmp/w", how: "git worktree add" },
	]);
	assert.deepEqual(planAction("ln --symbolic --force --no-dereference ../x /tmp/w/link")?.links, ["/tmp/w/link"]);
	assert.deepEqual(planAction("ln -s ../x /tmp/w/link")?.links, ["/tmp/w/link"]);
	assert.deepEqual(planAction("git worktree list --porcelain"), {
		creations: [],
		removals: [],
		writes: [],
		links: [],
	});
	assert.deepEqual(planAction("{ git diff a..b; git log -1; } > /tmp/x.diff")?.writes, ["/tmp/x.diff"]);
	assert.deepEqual(planAction("cat /tmp/a >> /tmp/b 2>&1")?.writes, ["/tmp/b"]);
	assert.deepEqual(planAction("echo hi > /dev/null")?.writes, []);
});

test("planAction refuses actions whose effects it cannot read", () => {
	for (const command of [
		// T1: the link is a folder above a created path.
		"ln -s ~/proj /tmp/p && mkdir /tmp/p/x",
		// T21: the link replaces a written file.
		"ln -sf ~/thesis /tmp/claimed.diff && echo x > /tmp/claimed.diff",
		// T8 without a verified leading cd, and T6: relative and dot-dot paths.
		"rm -rf build",
		"mkdir out",
		"echo x > out.log",
		"ln -s /x link",
		"git worktree add wt HEAD",
		"rm -rf /tmp/paa-r1/evil/../package.json",
		"rm -rf /tmp/./x",
		"rm -rf /tmp/x/",
		"echo x > ~/notes.txt",
		"rm -rf /tmp/*.diff",
		"rm -rf /tmp/x?",
		"rm -rf /tmp/{a,b}",
		"rm -rf $HOME/x",
		'echo x > "$OUT"',
		// T12: names with a path, assignments, wrappers.
		"/tmp/evil/mkdir /tmp/x",
		"PATH=/tmp/evil mkdir /tmp/x",
		"PATH=/tmp/evil; mkdir /tmp/x",
		"env mkdir /tmp/x",
		"command mkdir /tmp/x",
		"exec mkdir /tmp/x",
		"timeout 5 mkdir /tmp/x",
		"nice mkdir /tmp/x",
		"sudo rm -rf /tmp/x",
		"printf -v PATH /tmp/evil && mkdir /tmp/x",
		'printf "$FMT" x',
		"$CMD /tmp/x",
		// T13: hard links.
		"ln ~/thesis /tmp/x && rm ~/thesis && echo > /tmp/x",
		"ln -f /tmp/a /tmp/b",
		// A forced link without -n follows a symlink to a folder and replaces
		// a file inside it.
		"ln -sf ../x /tmp/w/link",
		"ln --symbolic --force ../x /tmp/w/link",
		// Operands after `--` are names, not options.
		"ln -sf -- -n /tmp/w/link",
		"ln -- -s /tmp/x",
		// T14: options outside the tables.
		"git -c core.hooksPath=/tmp/h worktree add /tmp/w",
		"git --git-dir=/x worktree add /tmp/w",
		"git worktree add -B main /tmp/w",
		"git worktree add -b topic /tmp/w",
		"git worktree add /tmp/w HEAD extra",
		"git worktree remove /tmp/a /tmp/b",
		"git worktree prune",
		"mkdir -m 700 /tmp/x",
		"rm -i /tmp/x",
		"ln -s -t /tmp/dir ../x",
		"ln -s /tmp/only-one",
		// T23: nested shells, background jobs, functions.
		"bash -c 'rm -rf /tmp/x'",
		"sh -c 'mkdir /tmp/x'",
		"eval 'mkdir /tmp/x'",
		"sleep 9 && mv ~/thesis /tmp/x &",
		"f() { mkdir /tmp/x; }; f",
		// Commands that may change files.
		"mv ~/thesis /tmp/x",
		"cp -p ~/a /tmp/b",
		"touch /tmp/x",
		"npm test",
		"python3 -c 'print(1)' > /tmp/x",
		"echo x | tee /tmp/x",
		"find /tmp -delete",
		// Write targets that are not plain paths.
		"echo x >&/tmp/x/../y",
		"echo x 3>/tmp/x/",
		// The parser could not read it.
		"echo 'unterminated",
	]) {
		assert.equal(planAction(command), undefined, command);
	}
});

/** A filesystem with `/tmp` -> `/private/tmp`, as on macOS, and a home folder made long ago. */
function setup() {
	const fs = new FakeFs();
	fs.mkdir("/private").mkdir("/private/tmp").symlink("/tmp", "/private/tmp");
	fs.mkdir("/home").mkdir("/home/u").write("/home/u/thesis.md", 50).mkdir("/home/u/old-wt");
	fs.tick();
	const paths = new CreatedPaths({ fs, now: () => new Date(fs.clock) });
	paths.setUsable(true);
	return { fs, paths };
}

let callCount = 0;

/**
 * Run one bash action through the record: claims, the pending entry, the
 * effect on the filesystem, and `tool_result`. Returns the claims Jev saw.
 */
async function run(
	{ fs, paths }: ReturnType<typeof setup>,
	command: string,
	effect: () => void,
	options: { input?: Record<string, unknown>; resultInput?: Record<string, unknown> } = {},
): Promise<ClaimSet> {
	const plan = planAction(command);
	assert.ok(plan, `guard refused ${command}`);
	const id = `call-${++callCount}`;
	const input = options.input ?? { command };
	const claims = await paths.claimsFor(plan);
	await paths.prepare(id, plan, input, claims);
	fs.tick(5);
	effect();
	fs.tick(5);
	await paths.complete(id, options.resultInput ?? input);
	paths.release(id);
	return claims;
}

/** A worktree as `git worktree add` leaves it: the folder, then its files. */
function addWorktree(fs: FakeFs, path: string) {
	fs.mkdir(path).write(`${path}/.git`).mkdir(`${path}/src`).write(`${path}/src/a.js`, 3);
}

test("a worktree the agent added gets a folder claim when it is removed", async () => {
	const env = setup();
	await run(env, "git worktree add -q --detach /tmp/paa-r1 ee0c617", () => addWorktree(env.fs, "/tmp/paa-r1"));
	env.fs.tick();
	const claims = await env.paths.claimsFor(planAction("git worktree remove --force /tmp/paa-r1")!);
	assert.equal(claims.lines.length, 1);
	assert.match(
		claims.lines[0]!,
		/^created_this_session: \/tmp\/paa-r1 \(folder; absent before and present after the agent's git worktree add at \d{4}-\d\d-\d\d \d\d:\d\d; every entry inside was created after the folder\)$/,
	);
	assert.equal(claims.claims[0]!.folderRemoval, true);
});

test("a file the agent wrote gets a file claim when it is overwritten", async () => {
	const env = setup();
	await run(env, "git diff a..b > /tmp/review.diff", () => env.fs.write("/tmp/review.diff", 10));
	const claims = await env.paths.claimsFor(planAction("git diff a..c > /tmp/review.diff")!);
	assert.deepEqual(claims.lines.map((line) => line.replace(/ at [^;]+;/, " at T;")), [
		"created_this_session: /tmp/review.diff (file; absent before and present after the agent's redirect at T; size and change time match the agent's last recorded write)",
	]);
});

test("the full refresh from session 01a0d6e5 keeps its claims across two refreshes", async () => {
	const env = setup();
	await run(env, SESSION.creation, () => {
		addWorktree(env.fs, "/tmp/paa-r2");
		addWorktree(env.fs, "/tmp/paa-r1");
		env.fs.write("/tmp/review-callbound.diff").write("/tmp/review-mcplife.diff");
	});
	const refresh = () => {
		env.fs.rm("/tmp/paa-r1");
		addWorktree(env.fs, "/tmp/paa-r1");
		env.fs.mkdir("/tmp/paa-r1/code-lab").mkdir("/tmp/paa-r1/code-lab/tools").mkdir("/tmp/paa-r1/code-lab/tools/code-review");
		env.fs.symlink("/tmp/paa-r1/code-lab/tools/code-review/node_modules", "/work/node_modules");
		env.fs.write("/tmp/review2-mcplife-delta.diff", 7).write("/tmp/review2-mcplife-net.diff", 9);
	};
	const first = await run(env, SESSION.refresh_1451, refresh);
	assert.deepEqual(first.claims.map((claim) => claim.path), ["/tmp/paa-r1"]);
	env.fs.tick();
	const second = await run(env, SESSION.refresh_1457, refresh);
	assert.deepEqual(second.claims.map((claim) => claim.path), [
		"/tmp/paa-r1",
		"/tmp/review2-mcplife-delta.diff",
		"/tmp/review2-mcplife-net.diff",
	]);
	env.fs.tick();
	const third = await env.paths.claimsFor(planAction(SESSION.refresh_1457)!);
	assert.equal(third.claims.length, 3);
});

test("paths that existed before the action are never recorded", async () => {
	const env = setup();
	// T3: an old file moved or hard-linked into the path while the action runs.
	await run(env, "echo x > /tmp/x", () => env.fs.mv("/home/u/thesis.md", "/tmp/x"));
	env.fs.mv("/tmp/x", "/home/u/thesis.md");
	await run(env, "echo x > /tmp/y", () => env.fs.link("/home/u/thesis.md", "/tmp/y"));
	// The path already existed.
	await run(env, "git worktree add /home/u/old-wt HEAD", () => {});
	for (const command of ["echo z > /tmp/x", "echo z > /tmp/y", "git worktree remove /home/u/old-wt"]) {
		assert.deepEqual((await env.paths.claimsFor(planAction(command)!)).lines, [], command);
	}
});

test("a parent swapped for a symlink during the action records nothing (T2)", async () => {
	const env = setup();
	env.fs.mkdir("/tmp/p");
	env.fs.tick();
	await run(env, "mkdir /tmp/p/x", () => {
		env.fs.mv("/tmp/p", "/tmp/p-old");
		env.fs.symlink("/tmp/p", "/home/u");
		env.fs.mkdir("/home/u/x");
	});
	assert.deepEqual(env.paths.recordedPaths(), []);
});

test("an edit by someone else ends a file claim for good (T4)", async () => {
	const env = setup();
	await run(env, "echo a > /tmp/r.diff", () => env.fs.write("/tmp/r.diff", 1));
	env.fs.tick();
	env.fs.write("/tmp/r.diff", 1); // same size, new change time
	assert.deepEqual((await env.paths.claimsFor(planAction("echo b > /tmp/r.diff")!)).lines, []);
	// The agent's own write does not bring it back.
	await run(env, "echo b > /tmp/r.diff", () => env.fs.write("/tmp/r.diff", 2));
	assert.deepEqual((await env.paths.claimsFor(planAction("echo c > /tmp/r.diff")!)).lines, []);
});

test("a recorded folder deleted and recreated by someone else loses its claim (T7)", async () => {
	const env = setup();
	await run(env, "mkdir /tmp/s", () => env.fs.mkdir("/tmp/s"));
	env.fs.tick();
	env.fs.rm("/tmp/s").mkdir("/tmp/s");
	assert.deepEqual((await env.paths.claimsFor(planAction("rm -rf /tmp/s")!)).lines, []);
});

test("an old file moved into a recorded folder blocks the folder claim (T9, T10)", async () => {
	for (const remove of ["rm -rf /tmp/s", "rm -rf /tmp/s && mkdir /tmp/s"]) {
		const env = setup();
		await run(env, "mkdir /tmp/s", () => env.fs.mkdir("/tmp/s"));
		env.fs.tick();
		env.fs.mv("/home/u/thesis.md", "/tmp/s/thesis.md");
		assert.deepEqual((await env.paths.claimsFor(planAction(remove)!)).lines, [], remove);
	}
	const env = setup();
	await run(env, "git worktree add /tmp/w HEAD", () => addWorktree(env.fs, "/tmp/w"));
	env.fs.tick();
	env.fs.mv("/home/u/old-wt", "/tmp/w/src/old-wt");
	assert.deepEqual((await env.paths.claimsFor(planAction("git worktree remove --force /tmp/w")!)).lines, []);
});

test("the contents walk refuses other devices, hard links, special files, and too many entries", async () => {
	const cases: Array<[string, (fs: FakeFs) => void]> = [
		["other device", (fs) => fs.mkdir("/tmp/s/mnt", { dev: 2 })],
		["hard link", (fs) => fs.write("/tmp/s/a").link("/tmp/s/a", "/tmp/s/b")],
		["fifo", (fs) => fs.fifo("/tmp/s/pipe")],
	];
	for (const [label, change] of cases) {
		const env = setup();
		await run(env, "mkdir /tmp/s", () => env.fs.mkdir("/tmp/s"));
		env.fs.tick();
		change(env.fs);
		assert.deepEqual((await env.paths.claimsFor(planAction("rm -rf /tmp/s")!)).lines, [], label);
	}
	const fs = new FakeFs();
	fs.mkdir("/tmp");
	const paths = new CreatedPaths({ fs, now: () => new Date(fs.clock), maxWalkEntries: 3 });
	paths.setUsable(true);
	await run({ fs, paths }, "mkdir /tmp/s", () => fs.mkdir("/tmp/s").write("/tmp/s/a").write("/tmp/s/b"));
	assert.equal((await paths.claimsFor(planAction("rm -rf /tmp/s")!)).lines.length, 1);
	fs.write("/tmp/s/c").write("/tmp/s/d");
	assert.deepEqual((await paths.claimsFor(planAction("rm -rf /tmp/s")!)).lines, [], "cap");
	const aborted = new AbortController();
	aborted.abort();
	assert.deepEqual((await paths.claimsFor(planAction("rm -rf /tmp/s/a")!, aborted.signal)).lines, [], "abort");
});

test("one unclaimed removal or existing write target cancels every claim (T18, T22)", async () => {
	const env = setup();
	await run(env, "echo a > /tmp/r.diff", () => env.fs.write("/tmp/r.diff"));
	await run(env, "mkdir /tmp/s", () => env.fs.mkdir("/tmp/s"));
	for (const command of [
		"rm -rf /tmp/s; rm -rf /home/u/old-wt",
		"git worktree remove --force /home/u/old-wt; git diff > /tmp/r.diff",
		"echo x > /home/u/thesis.md; echo y > /tmp/r.diff",
	]) {
		assert.deepEqual((await env.paths.claimsFor(planAction(command)!)).lines, [], command);
	}
	// A removal operand that does not exist deletes nothing and is fine.
	assert.equal((await env.paths.claimsFor(planAction("rm -rf /tmp/gone; echo y > /tmp/r.diff")!)).lines.length, 1);
});

test("a link may replace only an entry inside a folder the action removes under a claim (T25)", async () => {
	const env = setup();
	await run(env, "echo a > /tmp/r.diff", () => env.fs.write("/tmp/r.diff"));
	await run(env, "mkdir /tmp/s", () => {
		env.fs.mkdir("/tmp/s").mkdir("/tmp/s/dir").write("/tmp/s/file");
		env.fs.symlink("/tmp/s/out", "/home/u");
	});
	env.fs.tick();
	for (const command of [
		// Replaces a user file next to a claimed write.
		"ln -sfn /x /home/u/thesis.md; echo y > /tmp/r.diff",
		// Inside the claimed folder, but the folder is not removed.
		"ln -sfn /x /tmp/s/file; echo y > /tmp/r.diff",
		// A real folder: even -n puts the link inside it.
		"ln -sfn /x /tmp/s/dir; rm -rf /tmp/s",
	]) {
		assert.deepEqual((await env.paths.claimsFor(planAction(command)!)).lines, [], command);
	}
	// Replacing the agent's own entries in a folder it removes keeps the claim.
	for (const link of ["/tmp/s/file", "/tmp/s/out", "/tmp/s/new"]) {
		const command = `ln -sfn /x ${link}; rm -rf /tmp/s`;
		assert.equal((await env.paths.claimsFor(planAction(command)!)).lines.length, 1, command);
	}
});

test("a link through another spelling of /tmp cannot reroute a claimed write (T21)", async () => {
	const env = setup();
	await run(env, "echo a > /tmp/claimed.diff", () => env.fs.write("/tmp/claimed.diff"));
	const command = "ln -sfn /home/u/thesis.md /private/tmp/claimed.diff && echo x > /tmp/claimed.diff";
	assert.ok(planAction(command), "the strings differ, so only the real paths show the clash");
	assert.deepEqual((await env.paths.claimsFor(planAction(command)!)).lines, []);
});

test("the second check fails when a claimed file changes after the claims were made (T20)", async () => {
	const env = setup();
	await run(env, "echo a > /tmp/r.diff", () => env.fs.write("/tmp/r.diff"));
	const claims = await env.paths.claimsFor(planAction("echo b > /tmp/r.diff")!);
	assert.equal(claims.lines.length, 1);
	assert.equal(await env.paths.recheck(claims), true);
	env.fs.tick();
	env.fs.touchCtime("/tmp/r.diff");
	assert.equal(await env.paths.recheck(claims), false);
});

test("a call whose input changed after pi-automode saw it records nothing (T16)", async () => {
	const env = setup();
	await run(env, "echo a > /tmp/r.diff", () => env.fs.write("/tmp/r.diff"), {
		resultInput: { command: "echo a > /tmp/other.diff" },
	});
	assert.deepEqual((await env.paths.claimsFor(planAction("echo b > /tmp/r.diff")!)).lines, []);
});

test("nothing is recorded where birth times are missing or the probe has not passed", async () => {
	const env = setup();
	await run(env, "echo a > /tmp/zero.diff", () => env.fs.write("/tmp/zero.diff", 1, { birthtimeMs: 0 }));
	assert.deepEqual((await env.paths.claimsFor(planAction("echo b > /tmp/zero.diff")!)).lines, []);
	env.paths.setUsable(false);
	await run(env, "echo a > /tmp/off.diff", () => env.fs.write("/tmp/off.diff"));
	env.paths.setUsable(true);
	assert.deepEqual((await env.paths.claimsFor(planAction("echo b > /tmp/off.diff")!)).lines, []);
});

test("the record keeps the newest entries within its cap and clear() empties it", async () => {
	const fs = new FakeFs();
	fs.mkdir("/tmp");
	const paths = new CreatedPaths({ fs, now: () => new Date(fs.clock), maxRecords: 2 });
	paths.setUsable(true);
	for (const name of ["a", "b", "c"]) {
		await run({ fs, paths }, `echo x > /tmp/${name}`, () => fs.write(`/tmp/${name}`));
	}
	const claimed = async (name: string) =>
		(await paths.claimsFor(planAction(`echo y > /tmp/${name}`)!)).lines.length;
	assert.deepEqual([await claimed("a"), await claimed("b"), await claimed("c")], [0, 1, 1]);
	paths.clear();
	assert.equal(await claimed("c"), 0);
});

test("a folder removal waits for running calls that could change files (T11)", () => {
	const { paths } = setup();
	const removal = { readOnly: false, paths: ["/private/tmp/s"], protects: ["/private/tmp/s"] };
	// The `mv` was checked first and has not finished.
	assert.equal(paths.admit("mv", { readOnly: false }), undefined);
	assert.match(paths.admit("rm", removal) ?? "", /Another action is still running/);
	paths.release("mv");
	assert.equal(paths.admit("rm", removal), undefined);
	// Now the removal runs: later calls that may change files wait for it.
	assert.match(paths.admit("mv2", { readOnly: false }) ?? "", /changing a session-created path/);
	assert.match(
		paths.admit("inside", { readOnly: false, paths: ["/private/tmp/s/x"] }) ?? "",
		/changing a session-created path/,
	);
	assert.equal(paths.admit("read", { readOnly: true }), undefined);
	assert.equal(paths.admit("other-worktree", { readOnly: false, paths: ["/private/tmp/paa-r2"] }), undefined);
	paths.release("rm");
	assert.equal(paths.admit("mv2", { readOnly: false }), undefined);
});

test("a claimed file refresh waits for running calls that could change it (T26)", () => {
	const { paths } = setup();
	const refresh = { readOnly: false, paths: ["/private/tmp/r.diff", "/private/tmp/gone"], protects: ["/private/tmp/r.diff", "/private/tmp/gone"] };
	assert.equal(paths.admit("swap", { readOnly: false }), undefined);
	assert.match(paths.admit("rm", refresh) ?? "", /Another action is still running/);
	paths.release("swap");
	assert.equal(paths.admit("rm", refresh), undefined);
	// A guarded call that recreates the missing operand waits too.
	assert.match(
		paths.admit("mkdir", { readOnly: false, paths: ["/private/tmp/gone"] }) ?? "",
		/changing a session-created path/,
	);
});

test("two guarded refreshes of different worktrees run together", () => {
	const { paths } = setup();
	const refresh = (name: string) => ({
		readOnly: false,
		paths: [`/private/tmp/${name}`, `/private/tmp/${name}.diff`],
		protects: [`/private/tmp/${name}`],
	});
	assert.equal(paths.admit("p/1", refresh("paa-r2")), undefined);
	assert.equal(paths.admit("p/2", refresh("paa-r1")), undefined);
	assert.match(paths.admit("p/3", refresh("paa-r1")) ?? "", /still running|changing a session-created path/);
});

test("a codemode parent does not block its own nested removal, and agent_end clears running calls", () => {
	const { paths } = setup();
	assert.equal(paths.admit("parent", { readOnly: false }), undefined);
	const removal = { readOnly: false, paths: ["/private/tmp/s"], protects: ["/private/tmp/s"] };
	assert.equal(paths.admit("parent/1", removal), undefined);
	assert.match(paths.admit("sibling", { readOnly: false }) ?? "", /changing a session-created path/);
	paths.endTurn();
	assert.equal(paths.admit("sibling", { readOnly: false }), undefined);
});

test("birth times are trusted on macOS, probed on Linux, and refused elsewhere (T19)", async () => {
	const probe = (births: number[], fail = false) => {
		let call = 0;
		return {
			async mkdtemp() {
				if (fail) throw new Error("EACCES");
				return "/tmp/probe";
			},
			async writeFile() {},
			async chmod() {},
			async rm() {},
			async wait() {},
			async stat() {
				return { birthtimeMs: births[call++]! };
			},
		};
	};
	assert.equal(await birthTimesUsable("darwin", probe([])), true);
	assert.equal(await birthTimesUsable("win32", probe([5, 5])), false);
	assert.equal(await birthTimesUsable("linux", probe([5, 5])), true);
	// libuv without statx reports the change time, which chmod moves.
	assert.equal(await birthTimesUsable("linux", probe([5, 9])), false);
	assert.equal(await birthTimesUsable("linux", probe([0, 0])), false);
	assert.equal(await birthTimesUsable("linux", probe([], true)), false);
});

test("on the real filesystem, a git worktree the agent added is claimed and an old file moved in is not", async (t) => {
	const { execFileSync } = await import("node:child_process");
	const { mkdtempSync, renameSync, rmSync, writeFileSync } = await import("node:fs");
	const { tmpdir } = await import("node:os");
	const { join } = await import("node:path");
	const { NODE_CREATED_PATHS_FS } = await import("../extensions/auto-mode/created-paths.ts");
	if (!await birthTimesUsable()) {
		t.skip("this platform does not report real birth times");
		return;
	}
	const base = mkdtempSync(join(tmpdir(), "pi-automode-created-"));
	try {
		const git = (...args: string[]) =>
			execFileSync("git", ["-c", "user.email=t@t", "-c", "user.name=t", ...args], { cwd: join(base, "repo"), stdio: "pipe" });
		execFileSync("git", ["init", "-q", join(base, "repo")]);
		writeFileSync(join(base, "repo", "a.txt"), "a");
		git("add", "a.txt");
		git("commit", "-q", "-m", "a");
		writeFileSync(join(base, "old.txt"), "made before the worktree");
		await new Promise((resolve) => setTimeout(resolve, 20));

		const paths = new CreatedPaths({ fs: NODE_CREATED_PATHS_FS });
		paths.setUsable(true);
		const worktree = join(base, "wt");
		const add = `git worktree add -q --detach ${worktree} HEAD`;
		const plan = planAction(add)!;
		await paths.prepare("add", plan, { command: add }, await paths.claimsFor(plan));
		git("worktree", "add", "-q", "--detach", worktree, "HEAD");
		await paths.complete("add", { command: add });

		const remove = planAction(`git worktree remove --force ${worktree}`)!;
		assert.equal((await paths.claimsFor(remove)).lines.length, 1);
		renameSync(join(base, "old.txt"), join(worktree, "old.txt"));
		assert.deepEqual((await paths.claimsFor(remove)).lines, []);
	} finally {
		rmSync(base, { recursive: true, force: true });
	}
});

// Revision: relative operands after a leading cd.

const SESSION_DIR = "/Users/dev/projects/data-migration";
const SESSION_RM_SELFTEST = `cd "${SESSION_DIR}" && rm .selftest.ps1 && wc -l probes.ps1`;
const SESSION_RM_OUTPUTS = `cd "${SESSION_DIR}" && rm -rf .r3-out .r3-compat-out _native.log _compat.log && timeout 400 pwsh -NoProfile -File ./.r3-test.ps1 2>&1 | tail -45`;
const SESSION_RM_ALL =
	`cd "${SESSION_DIR}" && rm -rf .r3-out .r3-compat-out .r3-token.txt .r3-compat.ps1 .mock3.ps1 .r3-test.ps1 _native.log _compat.log && python3 -c "print(1)" && pwsh -NoProfile -Command 'Write-Host hi'`;

test("a leading cd to a plain absolute folder resolves relative operands (T8)", () => {
	assert.deepEqual(planAction("cd /tmp/paa-r1 && rm -rf build")?.removals, ["/tmp/paa-r1/build"]);
	assert.deepEqual(planAction("cd /tmp/w && mkdir -p out .cache")?.creations, [
		{ path: "/tmp/w/out", how: "mkdir" },
		{ path: "/tmp/w/.cache", how: "mkdir" },
	]);
	assert.deepEqual(planAction("cd /tmp/w && echo x > out.log 2>&1")?.writes, ["/tmp/w/out.log"]);
	assert.deepEqual(planAction("cd /tmp/w && ln -sfn /x link")?.links, ["/tmp/w/link"]);
	assert.deepEqual(planAction("cd /tmp/w && git worktree add wt HEAD")?.creations, [
		{ path: "/tmp/w/wt", how: "git worktree add" },
	]);
	assert.deepEqual(planAction("cd /tmp/w && git worktree remove --force wt")?.removals, ["/tmp/w/wt"]);
	// Absolute operands stay as they are, and a pipe or group after the && is fine.
	assert.deepEqual(planAction("cd /tmp/w && rm -rf /tmp/x build | tail -1")?.removals, ["/tmp/x", "/tmp/w/build"]);
	assert.deepEqual(planAction("cd /tmp/w && { rm a; rm b; } 2>&1 | tail")?.removals, ["/tmp/w/a", "/tmp/w/b"]);
	assert.deepEqual(planAction("cd /tmp/w && rm -- -odd")?.removals, ["/tmp/w/-odd"]);
	// Quoted folder names with spaces.
	assert.deepEqual(planAction(SESSION_RM_SELFTEST)?.removals, [`${SESSION_DIR}/.selftest.ps1`]);
});

test("relative operands stay refused unless a lone leading cd && verifies the folder (T8)", () => {
	for (const command of [
		// The cd is not joined by && alone.
		"cd /tmp/w; rm -rf build",
		"cd /tmp/w || true && rm -rf build",
		"cd /tmp/w && rm -rf build || rm -rf other",
		"cd /tmp/w && rm -rf build; rm -rf other",
		"cd /tmp/w\nrm -rf build",
		"cd /tmp/w | rm -rf build",
		"cd /tmp/w & rm -rf build",
		"true && cd /tmp/w && rm -rf build",
		"(cd /tmp/w && rm -rf build)",
		"{ cd /tmp/w && rm -rf build; }",
		"cd /tmp/w > /tmp/log && rm -rf build",
		// Another directory change later in the action.
		"cd /tmp/w && cd /tmp/y && rm -rf build",
		"cd /tmp/w && pushd /tmp/y && rm -rf build",
		"cd /tmp/w && popd && rm -rf build",
		"cd /tmp/w && echo $(cd /tmp/y; pwd) && rm -rf build",
		"cd /tmp/w && command cd /tmp/y && rm -rf build",
		"cd /tmp/w && env -C /tmp/y rm -rf build",
		// A cd the guard cannot verify.
		"cd -P /tmp/w && rm -rf build",
		"cd -L /tmp/w && rm -rf build",
		"cd - && rm -rf build",
		"cd && rm -rf build",
		"cd /tmp/w/../y && rm -rf build",
		"cd /tmp/w/ && rm -rf build",
		"cd relative && rm -rf build",
		"cd ~/proj && rm -rf build",
		"cd $HOME && rm -rf build",
		'cd "$DIR" && rm -rf build',
		"cd /tmp/a /tmp/b && rm -rf build",
		"cd /tmp/*/w && rm -rf build",
		"CDPATH=/x cd /tmp/w && rm -rf build",
		"/usr/bin/cd /tmp/w && rm -rf build",
		// A relative operand that does not stay a plain path.
		"cd /tmp/w && rm -rf ../build",
		"cd /tmp/w && rm -rf .",
		"cd /tmp/w && rm -rf ./build",
		"cd /tmp/w && rm -rf build/",
		"cd /tmp/w && rm -rf a/../b",
		"cd /tmp/w && rm -rf *.log",
		"cd /tmp/w && rm -rf build?",
		"cd /tmp/w && rm -rf {a,b}",
		"cd /tmp/w && rm -rf $OUT",
		"cd /tmp/w && rm -rf ~/build",
		"cd /tmp/w && rm -rf ~",
		"cd /tmp/w && rm -rf ''",
		"cd /tmp/w && echo x > ../out.log",
		"cd /tmp/w && echo x > $OUT",
		// `git -C` moves the base of its own relative paths.
		"cd /tmp/w && git -C /tmp/y worktree add wt HEAD",
		"cd /tmp/w && git -C /tmp/y worktree remove --force wt",
	]) {
		assert.equal(planAction(command), undefined, command);
	}
	// A cd that is not first, or the same action without one, resolves nothing,
	// but its absolute operands stay as before.
	assert.deepEqual(planAction("cd /tmp/w && rm -rf /tmp/x")?.removals, ["/tmp/x"]);
	assert.deepEqual(planAction("cd /tmp/w; rm -rf /tmp/x")?.removals, ["/tmp/x"]);
});

test("leadingCdDirectory returns the verified folder only", () => {
	assert.equal(leadingCdDirectory("cd /tmp/w && rm -rf build"), "/tmp/w");
	assert.equal(leadingCdDirectory(SESSION_RM_OUTPUTS), SESSION_DIR);
	assert.equal(leadingCdDirectory(SESSION_RM_ALL), SESSION_DIR);
	assert.equal(leadingCdDirectory("cd /tmp/w; rm -rf build"), undefined);
	assert.equal(leadingCdDirectory("cd /tmp/w && cd /tmp/y"), undefined);
	assert.equal(leadingCdDirectory("cd -P /tmp/w && ls"), undefined);
	assert.equal(leadingCdDirectory("rm -rf build"), undefined);
});

test("the verbatim session commands: only the fully guarded one gets a plan", () => {
	assert.ok(planAction(SESSION_RM_SELFTEST));
	// `timeout`, `pwsh`, and `python3` are outside the guard: no plan, no claims.
	assert.equal(planAction(SESSION_RM_OUTPUTS), undefined);
	assert.equal(planAction(SESSION_RM_ALL), undefined);
	assert.deepEqual(
		planAction(`cd "${SESSION_DIR}" && rm -rf .r3-out .r3-compat-out _native.log _compat.log`)?.removals,
		[".r3-out", ".r3-compat-out", "_native.log", "_compat.log"].map((name) => `${SESSION_DIR}/${name}`),
	);
});

// Revision: the write tool.

/** One `write` or `edit` call through the record. */
async function runTool(
	{ fs, paths }: ReturnType<typeof setup>,
	tool: "write" | "edit",
	path: string,
	effect: () => void,
	options: { input?: Record<string, unknown>; resultInput?: Record<string, unknown> } = {},
): Promise<void> {
	const id = `call-${++callCount}`;
	const input = options.input ?? { path, content: "x" };
	await paths.prepareFileTool(id, tool, path, input);
	fs.tick(5);
	effect();
	fs.tick(5);
	await paths.complete(id, options.resultInput ?? input);
	paths.release(id);
}

const claimLines = async (env: ReturnType<typeof setup>, command: string) =>
	(await env.paths.claimsFor(planAction(command)!)).lines;

test("a file the write tool created is claimed, with its own wording", async () => {
	const env = setup();
	await runTool(env, "write", "/tmp/note.md", () => env.fs.write("/tmp/note.md", 4));
	env.fs.tick();
	const lines = await claimLines(env, "rm /tmp/note.md");
	assert.equal(lines.length, 1);
	assert.match(
		lines[0]!,
		/^created_this_session: \/tmp\/note\.md \(file; absent before and present after the agent's write tool call at \d{4}-\d\d-\d\d \d\d:\d\d; size and change time match the agent's last recorded write\)$/,
	);
});

test("write and edit by the agent keep a write-recorded file claimed", async () => {
	const env = setup();
	await runTool(env, "write", "/tmp/note.md", () => env.fs.write("/tmp/note.md", 4));
	env.fs.tick();
	await runTool(env, "edit", "/tmp/note.md", () => env.fs.write("/tmp/note.md", 9), { input: { path: "/tmp/note.md", edits: [] } });
	env.fs.tick();
	assert.equal((await claimLines(env, "rm /tmp/note.md")).length, 1);
	await runTool(env, "write", "/tmp/note.md", () => env.fs.write("/tmp/note.md", 2));
	env.fs.tick();
	assert.equal((await claimLines(env, "rm /tmp/note.md")).length, 1);
	// A file a bash redirect recorded is refreshed the same way.
	await run(env, "echo a > /tmp/r.diff", () => env.fs.write("/tmp/r.diff", 1));
	env.fs.tick();
	await runTool(env, "edit", "/tmp/r.diff", () => env.fs.write("/tmp/r.diff", 8));
	env.fs.tick();
	assert.equal((await claimLines(env, "rm /tmp/r.diff")).length, 1);
});

test("a user edit before the agent's write or edit ends the claim, and the record goes (T4)", async () => {
	for (const tool of ["write", "edit"] as const) {
		const env = setup();
		await runTool(env, "write", "/tmp/note.md", () => env.fs.write("/tmp/note.md", 4));
		env.fs.tick();
		env.fs.write("/tmp/note.md", 4); // the user, same size, new change time
		env.fs.tick();
		await runTool(env, tool, "/tmp/note.md", () => env.fs.write("/tmp/note.md", 6));
		env.fs.tick();
		assert.deepEqual(await claimLines(env, "rm /tmp/note.md"), [], tool);
		assert.deepEqual(env.paths.recordedPaths(), [], tool);
	}
});

test("a user edit before the agent deletes a write-recorded file means no claim", async () => {
	const env = setup();
	await runTool(env, "write", "/tmp/note.md", () => env.fs.write("/tmp/note.md", 4));
	env.fs.tick();
	env.fs.touchCtime("/tmp/note.md");
	assert.deepEqual(await claimLines(env, "rm /tmp/note.md"), []);
	assert.deepEqual(env.paths.recordedPaths(), []);
});

test("the write tool records nothing for existing files, missing parents, or edits of unrecorded files", async () => {
	const env = setup();
	await runTool(env, "write", "/home/u/thesis.md", () => env.fs.write("/home/u/thesis.md", 60));
	await runTool(env, "write", "/tmp/missing/dir/x.md", () => env.fs.mkdir("/tmp/missing").mkdir("/tmp/missing/dir").write("/tmp/missing/dir/x.md"));
	await runTool(env, "edit", "/tmp/e.md", () => env.fs.write("/tmp/e.md"));
	await runTool(env, "write", "relative.md", () => env.fs.write("/tmp/relative.md"));
	assert.deepEqual(env.paths.recordedPaths(), []);
});

test("a write onto a symlink, dangling or not, records nothing", async () => {
	const env = setup();
	env.fs.symlink("/tmp/dangling", "/home/u/missing-target").symlink("/tmp/alias", "/home/u/thesis.md");
	env.fs.tick();
	await runTool(env, "write", "/tmp/dangling", () => {});
	await runTool(env, "write", "/tmp/alias", () => env.fs.write("/home/u/thesis.md", 70));
	assert.deepEqual(env.paths.recordedPaths(), []);
});

test("write-tool threats: swapped parent, moved-in file, hard link, changed input record nothing (T2, T3, T16)", async () => {
	const cases: Array<[string, (fs: FakeFs) => void, Record<string, unknown>?]> = [
		["swapped parent", (fs) => {
			fs.mv("/tmp/p", "/tmp/p-old");
			fs.symlink("/tmp/p", "/home/u");
			fs.write("/home/u/x.md");
		}],
		["moved-in old file", (fs) => fs.mv("/home/u/thesis.md", "/tmp/p/x.md")],
		["hard link", (fs) => fs.link("/home/u/thesis.md", "/tmp/p/x.md")],
		["changed input", (fs) => fs.write("/tmp/p/x.md"), { path: "/tmp/p/x.md", content: "other" }],
	];
	for (const [label, change, resultInput] of cases) {
		const env = setup();
		env.fs.mkdir("/tmp/p");
		env.fs.tick();
		await runTool(env, "write", "/tmp/p/x.md", () => change(env.fs), resultInput ? { resultInput } : {});
		assert.deepEqual(env.paths.recordedPaths(), [], label);
	}
});

test("a write-recorded file replaced by another object during the call loses its record", async () => {
	const env = setup();
	await runTool(env, "write", "/tmp/note.md", () => env.fs.write("/tmp/note.md", 4));
	env.fs.tick();
	// Pi writes in place; a different inode means the agent's call did not do it.
	await runTool(env, "write", "/tmp/note.md", () => env.fs.rm("/tmp/note.md").write("/tmp/note.md", 4));
	env.fs.tick();
	assert.deepEqual(await claimLines(env, "rm /tmp/note.md"), []);
	assert.deepEqual(env.paths.recordedPaths(), []);
});

test("an edit with changed input drops the record it would have refreshed", async () => {
	const env = setup();
	await runTool(env, "write", "/tmp/note.md", () => env.fs.write("/tmp/note.md", 4));
	env.fs.tick();
	await runTool(env, "edit", "/tmp/note.md", () => env.fs.write("/tmp/note.md", 5), {
		resultInput: { path: "/tmp/other.md", edits: [] },
	});
	assert.deepEqual(env.paths.recordedPaths(), []);
});

// Revision: the directory snapshot around bash calls.

const WORK = "/work/proj";

/**
 * The session folder with two entries of the user's, after the session-start
 * baseline: C records only in a folder that had one (both entries are tainted).
 */
async function workEnv() {
	const env = setup();
	env.fs.mkdir("/work").mkdir(WORK).write(`${WORK}/keep.txt`, 5).mkdir(`${WORK}/old-dir`);
	env.fs.tick();
	await env.paths.baseline(WORK);
	return env;
}

/** One bash call as the snapshot sees it: `dirs` listed before, the effect, then the result. */
async function runSnapshot(
	{ fs, paths }: ReturnType<typeof setup>,
	command: string,
	dirs: string[],
	effect: () => void,
	options: { plan?: boolean; prefix?: boolean; input?: Record<string, unknown>; resultInput?: Record<string, unknown> } = {},
): Promise<ClaimSet> {
	const id = `call-${++callCount}`;
	const input = options.input ?? { command };
	const planned = options.prefix ? planActionOrPrefix(command) : options.plan ? { plan: planAction(command)! } : undefined;
	const plan = planned?.plan;
	if (options.plan) assert.ok(plan, `guard refused ${command}`);
	const claims = plan ? await paths.claimsFor(plan, undefined, (planned as { scope?: string }).scope) : { claims: [], lines: [] };
	await paths.prepare(id, plan, input, claims, dirs);
	fs.tick(5);
	effect();
	fs.tick(5);
	await paths.complete(id, options.resultInput ?? input);
	paths.release(id);
	return claims;
}

test("new top-level files and folders an unguarded bash call leaves in the folder are recorded", async () => {
	const env = await workEnv();
	await runSnapshot(env, "pwsh -File ./run.ps1", [WORK], () => {
		env.fs.mkdir(`${WORK}/.r3-out`).write(`${WORK}/.r3-out/a.json`).write(`${WORK}/_native.log`, 9);
	});
	env.fs.tick();
	const lines = await claimLines(env, `rm -rf ${WORK}/.r3-out ${WORK}/_native.log`);
	assert.equal(lines.length, 2);
	assert.match(lines[0]!, /\(folder; absent before and present after the agent's bash command at /);
	assert.match(lines[1]!, /\(file; absent before and present after the agent's bash command at /);
	// Entries that were there before are not recorded.
	assert.deepEqual(await claimLines(env, `rm ${WORK}/keep.txt`), []);
	assert.deepEqual(env.paths.recordedPaths().sort(), [`${WORK}/.r3-out`, `${WORK}/_native.log`]);
});

test("the snapshot is top level only", async () => {
	const env = await workEnv();
	await runSnapshot(env, "pwsh -File ./run.ps1", [WORK], () => {
		env.fs.write(`${WORK}/old-dir/deep.txt`);
		env.fs.mkdir(`${WORK}/new-dir`).write(`${WORK}/new-dir/inner.txt`);
	});
	assert.deepEqual(env.paths.recordedPaths(), [`${WORK}/new-dir`]);
});

test("the snapshot never records symlinks, hard links, or files moved in (T3)", async () => {
	const env = await workEnv();
	env.fs.write("/home/u/linked.txt", 3).mkdir("/home/u/dir-moved");
	env.fs.tick();
	await runSnapshot(env, "pwsh -File ./run.ps1", [WORK], () => {
		env.fs.symlink(`${WORK}/link`, "/home/u/thesis.md");
		env.fs.link("/home/u/linked.txt", `${WORK}/hard.txt`);
		env.fs.mv("/home/u/thesis.md", `${WORK}/moved.md`);
		env.fs.mv("/home/u/dir-moved", `${WORK}/moved-dir`);
		env.fs.fifo(`${WORK}/pipe`);
	});
	assert.deepEqual(env.paths.recordedPaths(), []);
});

test("a new file with a second link is not recorded, and neither is its twin", async () => {
	const env = await workEnv();
	await runSnapshot(env, "pwsh -File ./run.ps1", [WORK], () => {
		env.fs.write(`${WORK}/a.txt`).link(`${WORK}/a.txt`, `${WORK}/b.txt`);
	});
	assert.deepEqual(env.paths.recordedPaths(), []);
});

test("a recorded entry replaced by something the snapshot rejects loses its record", async () => {
	const env = await workEnv();
	await runSnapshot(env, "pwsh -File ./run.ps1", [WORK], () => env.fs.write(`${WORK}/out.log`));
	assert.deepEqual(env.paths.recordedPaths(), [`${WORK}/out.log`]);
	env.fs.tick();
	await runSnapshot(env, "pwsh -File ./run.ps1", [WORK], () => {
		env.fs.rm(`${WORK}/out.log`);
		env.fs.mv("/home/u/thesis.md", `${WORK}/out.log`);
	});
	assert.deepEqual(env.paths.recordedPaths(), []);
	// A recorded entry the call removed is dropped too.
	await runSnapshot(env, "pwsh -File ./run.ps1", [WORK], () => env.fs.write(`${WORK}/b.log`));
	await runSnapshot(env, "rm b.log", [WORK], () => env.fs.rm(`${WORK}/b.log`));
	assert.deepEqual(env.paths.recordedPaths(), []);
});

test("the same folder reached through another path records nothing (T2)", async () => {
	const env = await workEnv();
	await runSnapshot(env, "pwsh -File ./run.ps1", [WORK], () => {
		// Same inode, but WORK is now a symlink to it.
		env.fs.mv(WORK, "/work/proj-moved");
		env.fs.symlink(WORK, "/work/proj-moved");
		env.fs.write(`${WORK}/out.log`);
	});
	assert.deepEqual(env.paths.recordedPaths(), []);
});

test("a folder recorded by the snapshot still needs the contents walk, so mv into it cannot launder a file (T9)", async () => {
	const env = await workEnv();
	await runSnapshot(env, "mkdir out && pwsh -File x.ps1", [WORK], () => env.fs.mkdir(`${WORK}/out`));
	env.fs.tick();
	assert.equal((await claimLines(env, `rm -rf ${WORK}/out`)).length, 1);
	env.fs.mv("/home/u/thesis.md", `${WORK}/out/thesis.md`);
	assert.deepEqual(await claimLines(env, `rm -rf ${WORK}/out`), []);
});

test("a file recorded by the snapshot loses its claim after an outside edit (T4)", async () => {
	const env = await workEnv();
	await runSnapshot(env, "pwsh -File ./run.ps1", [WORK], () => env.fs.write(`${WORK}/out.log`, 3));
	env.fs.tick();
	env.fs.touchCtime(`${WORK}/out.log`);
	assert.deepEqual(await claimLines(env, `rm ${WORK}/out.log`), []);
});

test("a parent swapped for a symlink between the two listings records nothing (T2)", async () => {
	const env = await workEnv();
	await runSnapshot(env, "pwsh -File ./run.ps1", [WORK], () => {
		env.fs.mv(WORK, "/work/proj-old");
		env.fs.symlink(WORK, "/home/u");
		env.fs.write(`${WORK}/out.log`);
	});
	assert.deepEqual(env.paths.recordedPaths(), []);
	// A folder replaced by another folder with the same name has another inode.
	const other = await workEnv();
	await runSnapshot(other, "pwsh -File ./run.ps1", [WORK], () => {
		other.fs.rm(WORK).mkdir(WORK).write(`${WORK}/out.log`);
	});
	assert.deepEqual(other.paths.recordedPaths(), []);
});

test("input changed by another extension means the snapshot records nothing (T16)", async () => {
	const env = await workEnv();
	await runSnapshot(env, "pwsh -File ./run.ps1", [WORK], () => env.fs.write(`${WORK}/out.log`), {
		resultInput: { command: "something else" },
	});
	assert.deepEqual(env.paths.recordedPaths(), []);
});

test("a path the call removed and recreated is recorded as the new object", async () => {
	const env = await workEnv();
	await runSnapshot(env, "pwsh -File ./run.ps1", [WORK], () => env.fs.mkdir(`${WORK}/.r3-out`));
	env.fs.tick();
	const first = await claimLines(env, `rm -rf ${WORK}/.r3-out`);
	assert.equal(first.length, 1);
	// Removed in the guarded prefix under a claim and recreated by the script.
	for (let run = 0; run < 3; run++) {
		await runSnapshot(env, `cd ${WORK} && rm -rf .r3-out && pwsh -File ./run.ps1`, [WORK], () => {
			env.fs.rm(`${WORK}/.r3-out`).mkdir(`${WORK}/.r3-out`).write(`${WORK}/.r3-out/a.json`);
		}, { plan: true, prefix: true });
		env.fs.tick();
		assert.equal((await claimLines(env, `rm -rf ${WORK}/.r3-out`)).length, 1, `run ${run}`);
	}
	// Unclaimed, the same recreation is a same-name replacement and is refused.
	await runSnapshot(env, "pwsh -File ./run.ps1", [WORK], () => {
		env.fs.rm(`${WORK}/.r3-out`).mkdir(`${WORK}/.r3-out`);
	});
	env.fs.tick();
	assert.deepEqual(await claimLines(env, `rm -rf ${WORK}/.r3-out`), []);
});

test("rename-replacing a pre-existing user file is not a creation (sed -i, perl -i, atomic saves)", async () => {
	const env = await workEnv();
	// `sed -i '' s/a/b/ keep.txt` writes a temp file and renames it over keep.txt:
	// a new inode with a new birth time, but the content is the user's.
	await runSnapshot(env, "sed -i '' s/a/b/ keep.txt", [WORK], () => {
		env.fs.rm(`${WORK}/keep.txt`).write(`${WORK}/keep.txt`, 2);
	});
	assert.deepEqual(env.paths.recordedPaths(), []);
	env.fs.tick();
	assert.deepEqual(await claimLines(env, `rm ${WORK}/keep.txt`), []);
	// The same for a folder replaced under the same name.
	await runSnapshot(env, "pwsh x", [WORK], () => env.fs.rm(`${WORK}/old-dir`).mkdir(`${WORK}/old-dir`));
	assert.deepEqual(env.paths.recordedPaths(), []);
});

test("rename-replacing a recorded file whose record went stale records nothing and drops the record", async () => {
	const env = await workEnv();
	await runSnapshot(env, "pwsh x", [WORK], () => env.fs.write(`${WORK}/out.log`, 3));
	env.fs.tick();
	env.fs.touchCtime(`${WORK}/out.log`); // the user changed it
	env.fs.tick();
	await runSnapshot(env, "perl -pi -e 's/a/b/' out.log", [WORK], () => {
		env.fs.rm(`${WORK}/out.log`).write(`${WORK}/out.log`, 4);
	});
	assert.deepEqual(env.paths.recordedPaths(), []);
});

test("an agent-owned file rewritten atomically by an unguarded script loses its record (fails safe)", async () => {
	// The listing cannot tell the script's rewrite from a user edit made in the
	// same window, so only a path this action claimed may be replaced.
	const env = await workEnv();
	await runSnapshot(env, "pwsh x", [WORK], () => env.fs.write(`${WORK}/out.log`, 3));
	env.fs.tick();
	await runSnapshot(env, "pwsh y", [WORK], () => env.fs.rm(`${WORK}/out.log`).write(`${WORK}/out.log`, 4));
	env.fs.tick();
	assert.deepEqual(await claimLines(env, `rm ${WORK}/out.log`), []);
	assert.deepEqual(env.paths.recordedPaths(), []);
});

test("a path claimed by the action may be recreated by it", async () => {
	const env = await workEnv();
	await runSnapshot(env, "pwsh x", [WORK], () => env.fs.mkdir(`${WORK}/o`));
	env.fs.tick();
	const command = `cd ${WORK} && rm -rf o && pwsh y`;
	const planned = planActionOrPrefix(command)!;
	const claims = await env.paths.claimsFor(planned.plan, undefined, planned.scope);
	assert.equal(claims.claims.length, 1);
	const id = "claimed-recreate";
	await env.paths.prepare(id, planned.plan, { command }, claims, [WORK]);
	env.fs.tick(5);
	env.fs.rm(`${WORK}/o`).mkdir(`${WORK}/o`);
	env.fs.tick(5);
	await env.paths.complete(id, { command });
	assert.deepEqual(env.paths.recordedPaths(), [`${WORK}/o`]);
});

test("a same-named entry that was only touched, not recreated, is not recorded", async () => {
	const env = await workEnv();
	await runSnapshot(env, "pwsh -File ./run.ps1", [WORK], () => env.fs.write(`${WORK}/keep.txt`, 99));
	assert.deepEqual(env.paths.recordedPaths(), []);
});

test("a path a guarded plan already records is not recorded twice", async () => {
	const env = await workEnv();
	const command = `cd ${WORK} && echo hi > out.log && wc -l keep.txt`;
	await runSnapshot(env, command, [WORK], () => env.fs.write(`${WORK}/out.log`, 3).write(`${WORK}/extra.txt`), { plan: true });
	env.fs.tick();
	const lines = await claimLines(env, `rm ${WORK}/out.log ${WORK}/extra.txt`);
	assert.equal(lines.length, 2);
	assert.match(lines[0]!, /agent's redirect at/);
	assert.match(lines[1]!, /agent's bash command at/);
});

test("a guarded removal that recreates nothing expires its record, and the snapshot adds none", async () => {
	const env = await workEnv();
	await runSnapshot(env, "pwsh -File ./run.ps1", [WORK], () => env.fs.write(`${WORK}/a.log`));
	env.fs.tick();
	await runSnapshot(env, `cd ${WORK} && rm a.log`, [WORK], () => env.fs.rm(`${WORK}/a.log`), { plan: true });
	assert.deepEqual(env.paths.recordedPaths(), []);
});

test("directories are deduplicated by real path, and a missing or oversized one is skipped", async () => {
	const fs = new FakeFs();
	fs.mkdir("/private").mkdir("/private/tmp").symlink("/tmp", "/private/tmp").mkdir("/private/tmp/d");
	fs.tick();
	let listings = 0;
	const counting = Object.assign(Object.create(fs), {
		readdir: (path: string) => (listings++, fs.readdir(path)),
	}) as FakeFs;
	const paths = new CreatedPaths({ fs: counting, now: () => new Date(fs.clock), maxSnapshotEntries: 3 });
	paths.setUsable(true);
	await paths.baseline("/tmp/d");
	listings = 0;
	const env = { fs, paths } as ReturnType<typeof setup>;
	await runSnapshot(env, "pwsh x", ["/tmp/d", "/private/tmp/d", "/missing"], () => fs.write("/tmp/d/a"));
	// One listing before and one after.
	assert.equal(listings, 2);
	assert.deepEqual(paths.recordedPaths(), ["/private/tmp/d/a"]);
	fs.tick();
	// A listing over the cap before the call is skipped.
	fs.write("/tmp/d/b").write("/tmp/d/c").write("/tmp/d/d");
	await runSnapshot(env, "pwsh x", ["/tmp/d"], () => fs.write("/tmp/d/e"));
	assert.deepEqual(paths.recordedPaths(), ["/private/tmp/d/a"]);
	// So is one that grows over it during the call.
	fs.rm("/tmp/d/b").rm("/tmp/d/c").rm("/tmp/d/d").rm("/tmp/d/e");
	await runSnapshot(env, "pwsh x", ["/tmp/d"], () => fs.write("/tmp/d/f").write("/tmp/d/g").write("/tmp/d/h"));
	assert.deepEqual(paths.recordedPaths(), ["/private/tmp/d/a"]);
});

test("pending snapshots are dropped on release and endTurn, and stay bounded", async () => {
	const fs = new FakeFs();
	fs.mkdir("/d");
	fs.tick();
	const paths = new CreatedPaths({ fs, now: () => new Date(fs.clock), maxPending: 2 });
	paths.setUsable(true);
	await paths.baseline("/d");
	const none = { claims: [], lines: [] };
	for (const id of ["a", "b", "c"]) await paths.prepare(id, undefined, { id }, none, ["/d"]);
	fs.tick(5);
	fs.write("/d/x");
	fs.tick(5);
	await paths.complete("a", { id: "a" }); // evicted by the cap
	paths.release("b");
	await paths.complete("b", { id: "b" });
	assert.deepEqual(paths.recordedPaths(), []);
	await paths.complete("c", { id: "c" }); // control: still pending
	assert.deepEqual(paths.recordedPaths(), ["/d/x"]);
	await paths.prepare("d", undefined, { id: "d" }, none, ["/d"]);
	paths.endTurn();
	fs.write("/d/y");
	await paths.complete("d", { id: "d" });
	assert.deepEqual(paths.recordedPaths(), ["/d/x"]);
});

test("nothing is snapshotted when birth times are not usable", async () => {
	const env = await workEnv();
	env.paths.setUsable(false);
	await runSnapshot(env, "pwsh x", [WORK], () => env.fs.write(`${WORK}/out.log`));
	env.paths.setUsable(true);
	assert.deepEqual(env.paths.recordedPaths(), []);
});

test("session commands: write-recorded and snapshot-recorded scratch files are claimed by the guarded commands", async () => {
	const env = setup();
	let fs = env.fs;
	fs.mkdir("/Users").mkdir("/Users/dev");
	let path = "/Users/dev";
	for (const part of ["projects", "data-migration"]) {
		path += `/${part}`;
		fs.mkdir(path);
	}
	fs.write(`${SESSION_DIR}/probes.ps1`, 100);
	fs.tick();
	await env.paths.baseline(SESSION_DIR);
	// Pi's write tool made .selftest.ps1 and a bash script made the outputs.
	await runTool(env, "write", `${SESSION_DIR}/.selftest.ps1`, () => fs.write(`${SESSION_DIR}/.selftest.ps1`, 20));
	fs.tick();
	await runSnapshot(env, SESSION_RM_OUTPUTS, [SESSION_DIR], () => {
		fs.mkdir(`${SESSION_DIR}/.r3-out`).mkdir(`${SESSION_DIR}/.r3-compat-out`);
		fs.write(`${SESSION_DIR}/_native.log`, 4).write(`${SESSION_DIR}/_compat.log`, 4);
	});
	fs.tick();
	const selftest = await claimLines(env, SESSION_RM_SELFTEST);
	assert.equal(selftest.length, 1);
	assert.match(selftest[0]!, /\.selftest\.ps1 \(file; absent before and present after the agent's write tool call/);
	const outputs = await claimLines(env, `cd "${SESSION_DIR}" && rm -rf .r3-out .r3-compat-out _native.log _compat.log`);
	assert.equal(outputs.length, 4);
	// A pre-existing file in the same action cancels every claim.
	assert.deepEqual(await claimLines(env, `cd "${SESSION_DIR}" && rm -rf .r3-out probes.ps1`), []);
});

// Revision: the guarded prefix.

const PREFIX_CD = `cd "${SESSION_DIR}"`;

test("a guarded prefix gets a plan, with the first unanalysed command named", () => {
	const outputs = planActionOrPrefix(SESSION_RM_OUTPUTS);
	assert.deepEqual(outputs?.plan.removals, [".r3-out", ".r3-compat-out", "_native.log", "_compat.log"].map((name) => `${SESSION_DIR}/${name}`));
	assert.equal(outputs?.scope, "timeout");
	assert.equal(outputs?.noClaims, undefined);
	const all = planActionOrPrefix(SESSION_RM_ALL);
	assert.equal(all?.plan.removals.length, 8);
	assert.equal(all?.scope, "python3");
	// A fully guarded action keeps its whole plan and has no scope.
	assert.equal(planActionOrPrefix(SESSION_RM_SELFTEST)?.scope, undefined);
	assert.deepEqual(planActionOrPrefix(SESSION_RM_SELFTEST)?.plan, planAction(SESSION_RM_SELFTEST));
	// `;` and `||` are fine joins, and the first unanalysed item may be a pipeline.
	assert.deepEqual(planActionOrPrefix("rm -rf /w/a; pwsh s.ps1 | tail")?.plan.removals, ["/w/a"]);
	assert.deepEqual(planActionOrPrefix("rm -rf /w/a || pwsh s.ps1")?.plan.removals, ["/w/a"]);
	assert.deepEqual(planActionOrPrefix("mkdir /w/o && echo x > /w/f && ./run.sh --all")?.plan.creations, [
		{ path: "/w/o", how: "mkdir" },
		{ path: "/w/f", how: "redirect" },
	]);
	// The reroute rule holds for the prefix: a created folder above a written path.
	assert.equal(planActionOrPrefix("mkdir /w/o && echo x > /w/o/f && ./run.sh"), undefined);
	assert.equal(planActionOrPrefix("rm -rf /w/a && ./run.sh")?.scope, "run.sh");
});

test("the scope name is plain text, whatever the command is called", () => {
	assert.equal(planActionOrPrefix("rm -rf /w/a && 'a`b' x")?.scope, "a command");
	assert.equal(planActionOrPrefix("rm -rf /w/a && for f in x; do pwsh $f; done")?.scope, "a command");
	assert.equal(planActionOrPrefix("rm -rf /w/a && { pwsh s.ps1; }")?.scope, "a command");
	assert.equal(
		scopeLine("timeout"),
		"created_this_session_scope: claims cover only commands before `timeout`; pi-automode did not analyse that command or anything after it",
	);
});

test("only a leading run of top-level simple commands is a prefix", () => {
	for (const command of [
		// The first item is unguarded: an empty prefix.
		"pwsh s.ps1 && rm -rf /w/a",
		"npm test; rm -rf /w/a",
		// Compounds, pipelines, and groups are never prefix items.
		"for f in x; do rm -rf /w/a; done && pwsh s.ps1",
		"if true; then rm -rf /w/a; fi; pwsh s.ps1",
		"rm -rf /w/a | pwsh s.ps1",
		"(rm -rf /w/a) && pwsh s.ps1",
		"{ rm -rf /w/a; } && pwsh s.ps1",
		"{ rm -rf /w/a && pwsh s.ps1; } > /w/a/out",
		"! rm -rf /w/a && pwsh s.ps1",
		// Structure the guard refuses anywhere in the action.
		"rm -rf /w/a && (pwsh s.ps1) &",
		"rm -rf /w/a && sleep 1 & pwsh s.ps1",
		"rm -rf /w/a && bash -c 'rm -rf ~/x'",
		'rm -rf /w/a && sh -c "$X"',
		'rm -rf /w/a && eval "$X"',
		"rm -rf /w/a && trap 'rm -rf ~/x' EXIT",
		"rm -rf /w/a && command exec pwsh s.ps1",
		"rm -rf /w/a && f() { pwsh; }; f",
		"rm -rf /w/a && coproc pwsh",
		"rm -rf /w/a && pwsh 'unterminated",
		// Prefix items that break the reroute rule or the path rules.
		"ln -s ~/proj /w/p && mkdir /w/p/x && pwsh s.ps1",
		"rm -rf ../a && pwsh s.ps1",
		"rm -rf a && pwsh s.ps1",
	]) {
		assert.equal(planActionOrPrefix(command), undefined, command);
	}
});

test("a relative operand in a prefix resolves only after a leading cd joined by && alone", () => {
	assert.deepEqual(planActionOrPrefix("cd /w && rm -rf a && pwsh s.ps1")?.plan.removals, ["/w/a"]);
	assert.deepEqual(planActionOrPrefix("cd /w && mkdir out && echo x > f && pwsh s.ps1")?.plan.creations, [
		{ path: "/w/out", how: "mkdir" },
		{ path: "/w/f", how: "redirect" },
	]);
	// The relative item is not reached through && alone, or a later cd moves the base.
	for (const command of [
		"cd /w; rm -rf a && pwsh s.ps1",
		"cd /w\nrm -rf a && pwsh s.ps1",
		"cd /w && true || rm -rf a && pwsh s.ps1",
		"cd /w && cd /x && rm -rf a && pwsh s.ps1",
		"cd /w && rm -rf a && pwsh s.ps1 && cd /x",
		"cd /w && rm -rf a && (cd /x; pwsh s.ps1)",
		"cd -P /w && rm -rf a && pwsh s.ps1",
		"cd /w/../x && rm -rf a && pwsh s.ps1",
		"cd /w && pwsh s.ps1; rm -rf a",
		"cd /w > /log && rm -rf a && pwsh s.ps1",
	]) {
		const planned = planActionOrPrefix(command);
		assert.deepEqual(planned?.plan.removals ?? [], [], command);
	}
	// A relative operand after a `;` that follows an && run is not resolved either.
	assert.equal(planActionOrPrefix("cd /w && rm -rf /w/x; rm -rf a; pwsh s.ps1")?.noClaims, true);
});

/** Claims the way the hook computes them: no claims when the rest is suspect. */
async function prefixClaims(env: ReturnType<typeof setup>, command: string): Promise<string[]> {
	const planned = planActionOrPrefix(command);
	if (!planned || planned.noClaims) return [];
	return (await env.paths.claimsFor(planned.plan, undefined, planned.scope)).lines;
}

async function prefixEnv() {
	const env = await workEnv();
	await runSnapshot(env, "pwsh -File ./run.ps1", [WORK], () => {
		env.fs.mkdir(`${WORK}/a`).write(`${WORK}/a.log`, 3);
	});
	env.fs.tick();
	return env;
}

test("prefix claims: the removal in the prefix is claimed and the scope line follows", async () => {
	const env = await prefixEnv();
	const lines = await prefixClaims(env, `rm -rf ${WORK}/a && pwsh s.ps1`);
	assert.equal(lines.length, 2);
	assert.match(lines[0]!, /^created_this_session: \/work\/proj\/a \(folder;/);
	assert.equal(lines[1], scopeLine("pwsh"));
	// No removal in the prefix: no claims, so no scope line either.
	assert.deepEqual(await prefixClaims(env, "mkdir /work/proj/new && pwsh s.ps1"), []);
	assert.deepEqual(await prefixClaims(env, `cd ${WORK} && rm -rf a a.log && timeout 9 pwsh x 2>&1 | tail -4`)
		.then((found) => found.length), 3);
});

test("prefix threats: no claims when the rest could delete, move, or reroute (T27-T36)", async () => {
	const env = await prefixEnv();
	const a = `${WORK}/a`;
	for (const command of [
		// T27 a loop or pipeline is not a prefix.
		`rm -rf ${a}; for f in x; do rm -rf ${a}; pwsh s.ps1; done`,
		`for f in x; do rm -rf ${a}; pwsh s.ps1; done`,
		`rm -rf ${a} | pwsh s.ps1`,
		// T28 a visible deletion or move in the rest.
		`rm -rf ${a} && pwsh s.ps1 && rm -rf /home/u/thesis.md`,
		`rm -rf ${a} && mv /home/u/thesis.md ${a}`,
		`rm -rf ${a} && find /home -name x -delete`,
		`rm -rf ${a} && find /home -name x -exec touch {} +`,
		`rm -rf ${a} && pwsh s.ps1 | xargs rm`,
		`rm -rf ${a} && timeout 5 rm -rf /home/u/x`,
		`rm -rf ${a} && git clean -fdx`,
		`rm -rf ${a} && git -C /home worktree remove --force old-wt`,
		`rm -rf ${a} && git rm -rf x`,
		`rm -rf ${a} && rmdir /home/u/old-wt`,
		`rm -rf ${a} && unlink /home/u/thesis.md`,
		`rm -rf ${a} && shred /home/u/thesis.md`,
		`rm -rf ${a} && $CMD x`,
		// T29 an unguarded command first: an empty prefix.
		`pwsh s.ps1 && rm -rf ${a}`,
		// T30 background, nested shell, eval, trap, exec.
		`rm -rf ${a} && (pwsh s.ps1) &`,
		`rm -rf ${a} && sleep 1 & pwsh s.ps1`,
		`rm -rf ${a} && bash -c 'rm -rf ~/x'`,
		`rm -rf ${a} && eval "$X"`,
		`rm -rf ${a} && trap 'rm -rf ~/x' EXIT`,
		`rm -rf ${a} && exec pwsh s.ps1`,
		// T31 a redirect on a compound that wraps the prefix, or one in the rest.
		`{ rm -rf ${a} && pwsh s.ps1; } > ${a}/out`,
		`rm -rf ${a} && pwsh s.ps1 > /home/u/thesis.md`,
		`rm -rf ${a} && for f in x; do pwsh $f; done > /home/u/thesis.md`,
		// T32 relative operands without a verified cd.
		`cd ${WORK}; rm -rf a && pwsh s.ps1`,
		`cd ${WORK} && cd /x && rm -rf a && pwsh s.ps1`,
		`cd ${WORK} && true || rm -rf a; pwsh s.ps1`,
	]) {
		assert.deepEqual(await prefixClaims(env, command), [], command);
	}
	// Controls: the same prefix without the threat has claims.
	assert.equal((await prefixClaims(env, `rm -rf ${a} && pwsh s.ps1 > /dev/null 2>&1`)).length, 2);
	assert.equal((await prefixClaims(env, `rm -rf ${a} && pwsh s.ps1 2>&1 | tail -3`)).length, 2);
});

test("an unclaimed existing prefix removal cancels every claim, claimed ones included (T33)", async () => {
	const env = await prefixEnv();
	for (const command of [
		`rm -rf ${WORK}/a /home/u/thesis.md && pwsh s.ps1`,
		`rm -rf ${WORK}/a && rm -rf /home/u/old-wt && pwsh s.ps1`,
		`rm -rf ${WORK}/a; echo x > /home/u/thesis.md; pwsh s.ps1`,
		`rm -rf /home/u/old-wt || rm -rf ${WORK}/a && pwsh s.ps1`,
	]) {
		assert.deepEqual(await prefixClaims(env, command), [], command);
	}
	// A missing operand deletes nothing and is fine.
	assert.equal((await prefixClaims(env, `rm -rf ${WORK}/gone ${WORK}/a && pwsh s.ps1`)).length, 2);
});

test("a prefix folder claim still needs the contents walk (T34)", async () => {
	const env = await prefixEnv();
	env.fs.mv("/home/u/thesis.md", `${WORK}/a/thesis.md`);
	assert.deepEqual(await prefixClaims(env, `rm -rf ${WORK}/a && pwsh s.ps1`), []);
});

test("a prefix creation is recorded under today's rules, and the rest's entries by the snapshot", async () => {
	const planned = planActionPrefix(`mkdir ${WORK}/out && echo x > ${WORK}/f.txt && pwsh s.ps1`)!;
	assert.deepEqual(planned.plan.creations, [{ path: `${WORK}/out`, how: "mkdir" }, { path: `${WORK}/f.txt`, how: "redirect" }]);
	const prepared = await workEnv();
	const id = "prefix-call";
	const input = { command: "x" };
	await prepared.paths.prepare(id, planned.plan, input, { claims: [], lines: [] }, [WORK]);
	prepared.fs.tick(5);
	prepared.fs.mkdir(`${WORK}/out`).write(`${WORK}/f.txt`).write(`${WORK}/made-by-script.txt`);
	prepared.fs.tick(5);
	await prepared.paths.complete(id, input);
	assert.deepEqual(prepared.paths.recordedPaths().sort(), [
		`${WORK}/f.txt`,
		`${WORK}/made-by-script.txt`,
		`${WORK}/out`,
	]);
	const by = async (command: string) => (await prefixClaims(prepared, command)).join("\n");
	assert.match(await by(`rm -rf ${WORK}/out && pwsh x`), /out \(folder; absent before and present after the agent's mkdir/);
	assert.match(await by(`rm ${WORK}/made-by-script.txt && pwsh x`), /agent's bash command/);
});

test("a here-doc body cannot hide commands from the prefix check or the rest-scan", () => {
	const noClaims = (command: string) => {
		const planned = planActionOrPrefix(command);
		return planned === undefined || planned.noClaims === true;
	};
	// The body's `$(rm …)` is positioned after its owner's range and before the rest.
	assert.equal(planActionPrefix("rm -rf /w/a && cat <<EOF\n$(rm -rf /home/u/thesis.md)\nEOF\npwsh x.ps1"), undefined);
	// Even a benign body on a prefix item is refused: fail closed, no attribution.
	assert.equal(planActionPrefix("rm -rf /w/a && cat <<EOF\n$(date)\nEOF\npwsh x.ps1"), undefined);
	// A body owned by the first unanalysed command is part of the rest and is scanned.
	assert.equal(noClaims("rm -rf /w/a && pwsh - <<EOF\n$(rm -rf /home/u/thesis.md)\nEOF\n"), true);
	assert.equal(noClaims("rm -rf /w/a && pwsh - <<EOF; true\n$(rm -rf /home/u/thesis.md)\nEOF\n"), true);
	// A here-string's substitution sits inside its item: the item fails the guard.
	assert.equal(noClaims('rm -rf /w/a && cat <<<"$(rm -rf ~/x)" && pwsh x'), true);
	// With an absolute path the whole action is guarded, and the substitution's
	// removal is a plan removal that the removal rule must claim.
	assert.deepEqual(
		planActionOrPrefix('rm -rf /w/a && cat <<<"$(rm -rf /home/u/thesis.md)"')?.plan.removals,
		["/w/a", "/home/u/thesis.md"],
	);
	// A quoted here-doc body is literal text, not commands: it is neither parsed
	// nor scanned, so the prefix plan stands. (A quoted body fed to a shell is
	// the rest's business, and the scope line says the rest was not analysed.)
	const quoted = planActionPrefix("rm -rf /w/a && cat <<'EOF'\n$(rm -rf /home/u/thesis.md)\nEOF\npwsh x.ps1");
	assert.deepEqual(quoted?.plan.removals, ["/w/a"]);
	assert.equal(quoted?.noClaims, undefined);
});

test("the rest-scan names a deny-list of deleting, moving, and overwriting commands", async () => {
	const env = await prefixEnv();
	const a = `${WORK}/a`;
	const denied = [
		"grm -rf /home/u/x", "gmv /home/u/x /tmp/y", "grmdir /home/u/x", "gunlink /home/u/x", "gshred /home/u/x",
		"srm /home/u/x", "trash /home/u/x",
		"echo x | tee /home/u/thesis.md", "truncate -s 0 /home/u/thesis.md", "dd if=/dev/zero of=/home/u/thesis.md",
		"cp /tmp/x /home/u/thesis.md", "install /tmp/x /home/u/thesis.md", "rsync -a --delete /tmp/x/ /home/u/",
		"ln -sf /tmp/x /home/u/thesis.md",
		"sed -i '' s/a/b/ /home/u/thesis.md", "sed -i.bak s/a/b/ /home/u/thesis.md", "sed -ni 5p /home/u/thesis.md",
		"sed --in-place s/a/b/ /home/u/thesis.md", "perl -pi -e s/a/b/ /home/u/thesis.md",
		"git reset --hard", "git checkout -- .", "git restore .", "git stash", "git clean -fd", "git rm x",
		"git worktree remove --force x", "/usr/bin/git -C /home/u checkout main",
		"xargs rm", "sudo rm -rf /x", "timeout 5 mv /x /y", "find /x -delete", "find /x -execdir touch {} +",
	];
	for (const rest of denied) {
		assert.deepEqual(await prefixClaims(env, `rm -rf ${a} && pwsh s.ps1 && ${rest}`), [], rest);
	}
	// Controls: ordinary commands in the rest keep the claim.
	for (const rest of ["pwsh s.ps1 | tail -5", "sed -n 5p /home/u/thesis.md", "git status", "git log -1", "git reset --soft HEAD~1", "python3 -c 'print(1)'", "cat x | wc -l"]) {
		assert.equal((await prefixClaims(env, `rm -rf ${a} && pwsh x && ${rest}`)).length, 2, rest);
	}
});

test("on the real filesystem, a rename-replaced user file is not recorded, and a new output is", async (t) => {
	const { mkdtempSync, renameSync, rmSync, writeFileSync } = await import("node:fs");
	const { tmpdir } = await import("node:os");
	const { join } = await import("node:path");
	const { NODE_CREATED_PATHS_FS } = await import("../extensions/auto-mode/created-paths.ts");
	if (!await birthTimesUsable()) {
		t.skip("this platform does not report real birth times");
		return;
	}
	const base = mkdtempSync(join(tmpdir(), "pi-automode-snapshot-"));
	try {
		const notes = join(base, "notes.md");
		writeFileSync(notes, "a");
		await new Promise((resolve) => setTimeout(resolve, 20));
		const paths = new CreatedPaths({ fs: NODE_CREATED_PATHS_FS });
		paths.setUsable(true);
		await paths.baseline(base);
		const input = { command: "sed -i '' s/a/b/ notes.md && pwsh run.ps1" };
		await paths.prepare("sed", undefined, input, { claims: [], lines: [] }, [base]);
		// What `sed -i` does: a temporary file renamed over the original.
		writeFileSync(join(base, "sedXYZ"), "b");
		renameSync(join(base, "sedXYZ"), notes);
		writeFileSync(join(base, "out.log"), "x");
		await paths.complete("sed", input);
		assert.deepEqual(paths.recordedPaths().map((path) => path.slice(path.lastIndexOf("/") + 1)), ["out.log"]);
	} finally {
		rmSync(base, { recursive: true, force: true });
	}
});

// Review round 2.

/** Run a script that creates `name` in the folder; true when it was recorded. */
const recordedAfter = async (env: ReturnType<typeof setup>, name: string, command = "pwsh x") => {
	await runSnapshot(env, command, [WORK], () => env.fs.write(`${WORK}/${name}`, 3));
	return env.paths.recordedPaths().includes(`${WORK}/${name}`);
};

test("a user's entry that vanished and came back is never recorded: stash round trip (taint)", async () => {
	const env = await workEnv();
	// Call 1: `git stash -u && npm test` makes the user's untracked entries vanish.
	await runSnapshot(env, "git stash -u && npm test", [WORK], () => {
		env.fs.mv(`${WORK}/keep.txt`, "/home/u/stashed-keep");
		env.fs.rm(`${WORK}/old-dir`);
	});
	env.fs.tick();
	// Call 2: `git stash pop` recreates them as new objects inside its window.
	await runSnapshot(env, "git stash pop", [WORK], () => {
		env.fs.write(`${WORK}/keep.txt`, 5);
		env.fs.mkdir(`${WORK}/old-dir`);
		env.fs.write(`${WORK}/fresh-from-script.txt`, 1);
	});
	env.fs.tick();
	assert.deepEqual(env.paths.recordedPaths(), [`${WORK}/fresh-from-script.txt`]);
	assert.deepEqual(await claimLines(env, `rm -rf ${WORK}/old-dir ${WORK}/keep.txt`), []);
	assert.deepEqual(await claimLines(env, `echo x > ${WORK}/keep.txt`), []);
});

test("move away in one call and copy back in the next records nothing (T42 across calls)", async () => {
	const env = await workEnv();
	await runSnapshot(env, "mv keep.txt ~/", [WORK], () => env.fs.mv(`${WORK}/keep.txt`, "/home/u/keep.txt"));
	env.fs.tick();
	await runSnapshot(env, "cp ~/keep.txt .", [WORK], () => env.fs.write(`${WORK}/keep.txt`, 5));
	assert.deepEqual(env.paths.recordedPaths(), []);
});

test("an entry that arrived unrecorded (moved in) and later vanished stays tainted", async () => {
	const env = await workEnv();
	await runSnapshot(env, "mv ~/thesis.md . && pwsh x", [WORK], () => env.fs.mv("/home/u/thesis.md", `${WORK}/thesis.md`));
	assert.deepEqual(env.paths.recordedPaths(), []);
	env.fs.tick();
	// Removed outside any snapshot, then recreated by a script.
	env.fs.rm(`${WORK}/thesis.md`);
	assert.equal(await recordedAfter(env, "thesis.md"), false);
	assert.equal(await recordedAfter(env, "other.md"), true);
});

test("a name the agent made (write tool) and a script later recreated is not tainted", async () => {
	const env = await workEnv();
	await runTool(env, "write", `${WORK}/x.ps1`, () => env.fs.write(`${WORK}/x.ps1`, 4));
	env.fs.tick();
	// Call A removes it: its first listing shows an agent-owned entry, so no taint.
	await runSnapshot(env, "pwsh cleanup.ps1", [WORK], () => env.fs.rm(`${WORK}/x.ps1`));
	env.fs.tick();
	assert.equal(await recordedAfter(env, "x.ps1"), true);
	env.fs.tick();
	assert.equal((await claimLines(env, `rm ${WORK}/x.ps1`)).length, 1);
});

test("the baseline taints names present before the first call, and fails closed", async () => {
	const env = await workEnv();
	await env.paths.baseline(WORK);
	// The user stashes outside any call; a script then recreates the names.
	env.fs.rm(`${WORK}/keep.txt`);
	env.fs.tick();
	assert.equal(await recordedAfter(env, "keep.txt"), false);
	assert.equal(await recordedAfter(env, "made.txt"), true);
	// session_start clears the taint with the record.
	env.paths.clear();
	env.fs.rm(`${WORK}/keep.txt`);
	// session_start clears and then takes a new baseline.
	assert.equal(await recordedAfter(env, "keep.txt"), false, "no baseline yet: C records nothing");
	env.fs.rm(`${WORK}/keep.txt`).rm(`${WORK}/made.txt`);
	await env.paths.baseline(WORK);
	assert.equal(await recordedAfter(env, "keep.txt"), true);
	assert.equal(await recordedAfter(env, "old-dir"), false);

	// A folder that cannot be listed is fully tainted: nothing is recorded in it.
	const fs = (await workEnv()).fs;
	let denied = true;
	const denying = Object.assign(Object.create(fs), {
		readdir: async (path: string) => {
			if (denied && path === WORK) throw Object.assign(new Error("EACCES"), { code: "EACCES" });
			return fs.readdir(path);
		},
	}) as FakeFs;
	const paths = new CreatedPaths({ fs: denying, now: () => new Date(fs.clock) });
	paths.setUsable(true);
	await paths.baseline(WORK);
	denied = false; // later listings work; the baseline failure must still hold
	const guarded = { fs, paths } as ReturnType<typeof setup>;
	await runSnapshot(guarded, "pwsh x", [WORK], () => fs.write(`${WORK}/made.txt`));
	assert.deepEqual(paths.recordedPaths(), []);
	// A folder that does not exist has nothing to taint.
	await paths.baseline("/missing/folder");
});

test("a folder over the taint cap is fully tainted: nothing is recorded in it", async () => {
	const env = await workEnv();
	env.fs.write(`${WORK}/b.txt`).write(`${WORK}/c.txt`);
	const paths = new CreatedPaths({ fs: env.fs, now: () => new Date(env.fs.clock), maxTaintNames: 2 });
	paths.setUsable(true);
	await paths.baseline(WORK); // 4 entries
	await runSnapshot({ fs: env.fs, paths } as ReturnType<typeof setup>, "pwsh x", [WORK], () => env.fs.write(`${WORK}/new.txt`));
	assert.deepEqual(paths.recordedPaths(), []);
});

test("a name spelled differently is still the same name (APFS README.md vs readme.md)", async () => {
	const env = await workEnv();
	env.fs.write(`${WORK}/README.md`, 9);
	env.fs.tick();
	await runSnapshot(env, "python3 fmt.py readme.md", [WORK], () => {
		env.fs.rm(`${WORK}/README.md`).write(`${WORK}/readme.md`, 9);
	});
	assert.deepEqual(env.paths.recordedPaths(), []);
	// Colliding spellings in one listing belong to nobody.
	await runSnapshot(env, "pwsh x", [WORK], () => env.fs.write(`${WORK}/B.txt`).write(`${WORK}/b.txt`));
	assert.deepEqual(env.paths.recordedPaths(), []);
	assert.equal(await recordedAfter(env, "b.txt"), false);
});

test("a user edit during the call is not absorbed by an atomic rewrite (stale agent-owned snapshot)", async () => {
	const env = await workEnv();
	await runTool(env, "write", `${WORK}/a.txt`, () => env.fs.write(`${WORK}/a.txt`, 4));
	env.fs.tick();
	const input = { command: "python3 tidy.py" };
	await env.paths.prepare("x", undefined, input, { claims: [], lines: [] }, [WORK]);
	env.fs.tick(30_000);
	env.fs.write(`${WORK}/a.txt`, 400); // the user, in place, before X executes
	env.fs.tick(5);
	env.fs.write(`${WORK}/.a.txt.tmp`, 401);
	env.fs.mv(`${WORK}/.a.txt.tmp`, `${WORK}/a.txt`); // the script's atomic rewrite
	env.fs.tick(5);
	await env.paths.complete("x", input);
	assert.deepEqual(env.paths.recordedPaths(), []);
	assert.deepEqual(await claimLines(env, `rm ${WORK}/a.txt`), []);
});

test("a cross-device mv gives a fresh birth time but keeps the old modification time (mtime)", async () => {
	const env = await workEnv();
	// C: `mv ~/thesis.md .` across devices copies the file and keeps its mtime.
	await runSnapshot(env, "mv ~/thesis.md . && pwsh x", [WORK], () => {
		env.fs.write(`${WORK}/thesis.md`, 50, { mtimeMs: 5 });
		env.fs.mkdir(`${WORK}/moved-dir`, { mtimeMs: 5 });
		env.fs.write(`${WORK}/script-made.txt`, 1);
	});
	assert.deepEqual(env.paths.recordedPaths(), [`${WORK}/script-made.txt`]);
	// A plan-recorded creation and a write-tool creation need a fresh mtime too.
	await run(env, `echo x > ${WORK}/r.out`, () => env.fs.write(`${WORK}/r.out`, 1, { mtimeMs: 5 }));
	await runTool(env, "write", `${WORK}/w.out`, () => env.fs.write(`${WORK}/w.out`, 1, { mtimeMs: 5 }));
	assert.deepEqual(env.paths.recordedPaths(), [`${WORK}/script-made.txt`]);
});

test("the contents walk refuses an entry with a fresh birth time and an old modification time", async () => {
	for (const stale of [true, false]) {
		const env = await workEnv();
		await runSnapshot(env, "mkdir o && pwsh x", [WORK], () => env.fs.mkdir(`${WORK}/o`));
		env.fs.tick();
		env.fs.write(`${WORK}/o/inner.txt`, 1, stale ? { mtimeMs: 5 } : {});
		assert.equal((await claimLines(env, `rm -rf ${WORK}/o`)).length, stale ? 0 : 1, String(stale));
		if (stale) {
			// Folders keep their old mtime across devices too.
			const other = await workEnv();
			await runSnapshot(other, "mkdir o && pwsh x", [WORK], () => other.fs.mkdir(`${WORK}/o`));
			other.fs.tick();
			other.fs.mkdir(`${WORK}/o/sub`, { mtimeMs: 5 });
			assert.deepEqual(await claimLines(other, `rm -rf ${WORK}/o`), []);
		}
	}
});

test("on the real filesystem, a stash round trip does not make the user's files claimable", async (t) => {
	const { execFileSync } = await import("node:child_process");
	const { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } = await import("node:fs");
	const { tmpdir } = await import("node:os");
	const { join } = await import("node:path");
	const { NODE_CREATED_PATHS_FS } = await import("../extensions/auto-mode/created-paths.ts");
	if (!await birthTimesUsable()) {
		t.skip("this platform does not report real birth times");
		return;
	}
	try {
		execFileSync("git", ["--version"], { stdio: "pipe" });
	} catch {
		t.skip("git is not installed");
		return;
	}
	const base = realpathSync(mkdtempSync(join(tmpdir(), "pi-automode-stash-")));
	const sh = (command: string) => execFileSync("sh", ["-c", command], { cwd: base, stdio: "pipe" }).toString();
	try {
		sh("git init -q && git config user.email a@b && git config user.name a && echo t > tracked.txt && git add . && git commit -qm init");
		writeFileSync(join(base, "notes.md"), "user's only copy\n");
		mkdirSync(join(base, "scratch"));
		writeFileSync(join(base, "scratch/a.txt"), "user's draft\n");
		writeFileSync(join(base, ".env"), "SECRET=1\n");
		const paths = new CreatedPaths({ fs: NODE_CREATED_PATHS_FS });
		paths.setUsable(true);
		await paths.baseline(base);
		const none = { claims: [], lines: [] };
		for (const [id, command, shell] of [
			["c1", "git stash -u && npm test", "git stash -u -q"],
			["c2", "git stash pop", "git stash pop -q"],
		] as const) {
			await paths.prepare(id, undefined, { command }, none, [base]);
			sh(shell);
			await paths.complete(id, { command });
			paths.release(id);
		}
		assert.deepEqual(paths.recordedPaths(), []);
		for (const command of [`rm -rf ${base}/scratch ${base}/notes.md`, `echo SECRET=2 > ${base}/.env`]) {
			assert.deepEqual((await paths.claimsFor(planAction(command)!)).lines, [], command);
		}
	} finally {
		rmSync(base, { recursive: true, force: true });
	}
});

test("on a case-insensitive real filesystem, unlink README.md and create readme.md is not a creation", async (t) => {
	const { existsSync, mkdtempSync, readdirSync, realpathSync, rmSync, unlinkSync, writeFileSync } = await import("node:fs");
	const { tmpdir } = await import("node:os");
	const { join } = await import("node:path");
	const { NODE_CREATED_PATHS_FS } = await import("../extensions/auto-mode/created-paths.ts");
	if (!await birthTimesUsable()) {
		t.skip("this platform does not report real birth times");
		return;
	}
	const base = realpathSync(mkdtempSync(join(tmpdir(), "pi-automode-case-")));
	try {
		writeFileSync(join(base, "README.md"), "the user's readme\n");
		if (!existsSync(join(base, "readme.md"))) {
			t.skip("this filesystem is case-sensitive");
			return;
		}
		const paths = new CreatedPaths({ fs: NODE_CREATED_PATHS_FS });
		paths.setUsable(true);
		await paths.baseline(base);
		const input = { command: "python3 fmt.py readme.md" };
		await paths.prepare("c", undefined, input, { claims: [], lines: [] }, [base]);
		unlinkSync(join(base, "readme.md"));
		writeFileSync(join(base, "readme.md"), "THE USER'S README\n");
		await paths.complete("c", input);
		assert.equal(readdirSync(base).length, 1);
		assert.deepEqual(paths.recordedPaths(), []);
	} finally {
		rmSync(base, { recursive: true, force: true });
	}
});

test("C records only in folders with a session-start baseline", async () => {
	const env = await workEnv();
	env.fs.mkdir("/work/other").write("/work/other/notes.md", 3);
	env.fs.tick();
	// No baseline for /work/other: the restore sequence looks like a creation unless it is skipped.
	await runSnapshot(env, "mv /work/other/notes.md ~/x", [WORK, "/work/other"], () => env.fs.mv("/work/other/notes.md", "/home/u/x"));
	await runSnapshot(env, "cp ~/x /work/other/notes.md && pwsh x", [WORK, "/work/other"], () => {
		env.fs.write("/work/other/notes.md", 3).write("/work/other/made.txt").write(`${WORK}/made.txt`);
	});
	assert.deepEqual(env.paths.recordedPaths(), [`${WORK}/made.txt`]);
	// A failed baseline leaves the folder unrecorded even if it is later readable.
	const fs = env.fs;
	let denied = true;
	const denying = Object.assign(Object.create(fs), {
		readdir: async (path: string) => {
			if (denied && path === "/work/other") throw Object.assign(new Error("EACCES"), { code: "EACCES" });
			return fs.readdir(path);
		},
	}) as FakeFs;
	const paths = new CreatedPaths({ fs: denying, now: () => new Date(fs.clock) });
	paths.setUsable(true);
	await paths.baseline("/work/other");
	denied = false;
	await runSnapshot({ fs, paths } as ReturnType<typeof setup>, "pwsh x", ["/work/other"], () => fs.write("/work/other/new.txt"));
	assert.deepEqual(paths.recordedPaths(), []);
});

test("restoresData names the commands that bring content back from outside the session", () => {
	for (const command of [
		"git stash pop", "git stash apply", "git -C /w stash pop", "sudo git stash pop", "timeout 5 git checkout main",
		"git switch x", "git restore .", "git reset --hard HEAD", "git pull", "git merge x", "git rebase main",
		"git cherry-pick abc", "git apply p.diff", "git am p.mbox", "git clone u d", "/usr/bin/git stash pop",
		"tar xf a.tar --touch", "timeout 5 tar x", "unzip a.zip", "bsdtar -xf a", "ditto a b", "rsync -a a/ b/",
		"7z x a.7z", "7za x a.7z", "gunzip a.gz", "gzip -d a.gz", "gzip -dk a.gz", "xz -d a.xz", "xz --decompress a.xz",
		"zstd -d a.zst", "echo hi && git stash pop && pwsh x", "pwsh x | tar x", "echo $(git stash pop)",
		"pwsh x <<EOF\n$(tar x)\nEOF", "echo 'unterminated", 'bash -c "$X"', "env FOO=1 git stash pop",
	]) {
		assert.equal(restoresData(command), true, command);
	}
	for (const command of [
		"git status", "git diff", "git log --merge", "git add . && git commit -m x",
		"pwsh -File run.ps1", "gzip a.txt", "xz a.txt", "zstd a.txt", "python3 -c 'print(1)'", "cd /w && rm -rf out && pwsh x",
		"ls | wc -l",
	]) {
		assert.equal(restoresData(command), false, command);
	}
	// Matched by word, so a mere mention counts: conservative.
	assert.equal(restoresData("echo tar"), true);
	assert.equal(restoresData("git stash list"), true);
});

test("on the real filesystem, a stash made before the session is not recorded when the agent pops it", async (t) => {
	const { execFileSync } = await import("node:child_process");
	const { mkdtempSync, realpathSync, rmSync, writeFileSync } = await import("node:fs");
	const { tmpdir } = await import("node:os");
	const { join } = await import("node:path");
	const { NODE_CREATED_PATHS_FS } = await import("../extensions/auto-mode/created-paths.ts");
	if (!await birthTimesUsable()) {
		t.skip("this platform does not report real birth times");
		return;
	}
	try {
		execFileSync("git", ["--version"], { stdio: "pipe" });
	} catch {
		t.skip("git is not installed");
		return;
	}
	const base = realpathSync(mkdtempSync(join(tmpdir(), "pi-automode-prestash-")));
	const sh = (command: string) => execFileSync("sh", ["-c", command], { cwd: base, stdio: "pipe" }).toString();
	try {
		sh("git init -q && git config user.email a@b && git config user.name a && echo t > tracked.txt && git add . && git commit -qm init");
		writeFileSync(join(base, "notes.md"), "user's only copy\n");
		sh("git stash -u -q"); // before the session: notes.md is absent from the baseline
		const run = async (command: string, snapshot: boolean) => {
			const paths = new CreatedPaths({ fs: NODE_CREATED_PATHS_FS });
			paths.setUsable(true);
			await paths.baseline(base);
			// The extension takes no snapshot when the action may restore data.
			await paths.prepare("c", undefined, { command }, { claims: [], lines: [] }, snapshot ? [base] : []);
			sh("git stash pop -q");
			await paths.complete("c", { command });
			return paths.recordedPaths();
		};
		const command = "git stash pop";
		assert.equal(restoresData(command), true);
		assert.deepEqual(await run(command, !restoresData(command)), []);
		// Control: with a snapshot, the restored file would be recorded as created.
		sh("git stash -u -q");
		assert.deepEqual((await run(command, true)).map((path) => path.slice(path.lastIndexOf("/") + 1)), ["notes.md"]);
	} finally {
		rmSync(base, { recursive: true, force: true });
	}
});
