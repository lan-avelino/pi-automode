import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
	CreatedPaths,
	birthTimesUsable,
	planAction,
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
	assert.deepEqual(planAction("ln --symbolic --force ../x /tmp/w/link")?.links, ["/tmp/w/link"]);
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
		// T8 and T6: relative and dot-dot paths.
		"cd /tmp/paa-r1 && rm -rf build",
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

test("a link through another spelling of /tmp cannot reroute a claimed write (T21)", async () => {
	const env = setup();
	await run(env, "echo a > /tmp/claimed.diff", () => env.fs.write("/tmp/claimed.diff"));
	const command = "ln -sf /home/u/thesis.md /private/tmp/claimed.diff && echo x > /tmp/claimed.diff";
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
	const removal = { readOnly: false, paths: ["/private/tmp/s"], removesFolders: ["/private/tmp/s"] };
	// The `mv` was checked first and has not finished.
	assert.equal(paths.admit("mv", { readOnly: false }), undefined);
	assert.match(paths.admit("rm", removal) ?? "", /Another action is still running/);
	paths.release("mv");
	assert.equal(paths.admit("rm", removal), undefined);
	// Now the removal runs: later calls that may change files wait for it.
	assert.match(paths.admit("mv2", { readOnly: false }) ?? "", /removing a session-created folder/);
	assert.match(
		paths.admit("inside", { readOnly: false, paths: ["/private/tmp/s/x"] }) ?? "",
		/removing a session-created folder/,
	);
	assert.equal(paths.admit("read", { readOnly: true }), undefined);
	assert.equal(paths.admit("other-worktree", { readOnly: false, paths: ["/private/tmp/paa-r2"] }), undefined);
	paths.release("rm");
	assert.equal(paths.admit("mv2", { readOnly: false }), undefined);
});

test("two guarded refreshes of different worktrees run together", () => {
	const { paths } = setup();
	const refresh = (name: string) => ({
		readOnly: false,
		paths: [`/private/tmp/${name}`, `/private/tmp/${name}.diff`],
		removesFolders: [`/private/tmp/${name}`],
	});
	assert.equal(paths.admit("p/1", refresh("paa-r2")), undefined);
	assert.equal(paths.admit("p/2", refresh("paa-r1")), undefined);
	assert.match(paths.admit("p/3", refresh("paa-r1")) ?? "", /still running|removing/);
});

test("a codemode parent does not block its own nested removal, and agent_end clears running calls", () => {
	const { paths } = setup();
	assert.equal(paths.admit("parent", { readOnly: false }), undefined);
	const removal = { readOnly: false, paths: ["/private/tmp/s"], removesFolders: ["/private/tmp/s"] };
	assert.equal(paths.admit("parent/1", removal), undefined);
	assert.match(paths.admit("sibling", { readOnly: false }) ?? "", /removing/);
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
