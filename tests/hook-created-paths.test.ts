import assert from "node:assert/strict";
import test from "node:test";
import { createPiAutomode, parseToolPattern, type ClassifyExtras } from "../extensions/auto-mode.ts";
import { FakeFs } from "./fake-fs.ts";
import { baseConfig, createFakeCtx, createFakePi } from "./test-helpers.ts";

type ToolCallResult = { block?: boolean; reason?: string } | undefined;

/**
 * pi-automode on the Jev backend over an in-memory filesystem. `onClassify`
 * runs while the classifier is "thinking", to change files mid-review.
 */
async function setup(options: {
	backend?: "jev" | "clef" | "llm";
	permissionAllow?: string[];
	cwd?: string;
	/** Runs on the filesystem before `session_start`. */
	prepare?: (fs: FakeFs) => void;
} = {}) {
	const fs = new FakeFs();
	fs.mkdir("/tmp").mkdir("/home").write("/home/thesis.md");
	options.prepare?.(fs);
	fs.tick();
	const fake = createFakePi();
	const seen: Array<{ action: string; extras?: ClassifyExtras }> = [];
	let onClassify: () => void = () => {};
	const classify = async (_ctx: unknown, _cfg: unknown, action: string, _loaded: string, extras?: ClassifyExtras) => {
		seen.push({ action, extras });
		onClassify();
		return { decision: "allow" as const, tier: "none" as const, reason: "test allow" };
	};
	createPiAutomode({
		loadConfig: () =>
			baseConfig({
				classifierBackend: options.backend ?? "jev",
				permissionAllow: (options.permissionAllow ?? []).map((rule) => parseToolPattern(rule)!),
			}),
		classifyAction: classify,
		jevClassifyAction: classify,
		createdPathsFs: fs,
		createdPathsNow: () => new Date(fs.clock),
		birthTimesUsable: async () => true,
	})(fake.pi);
	const ctx = createFakeCtx(fake.entries, options.cwd ? { cwd: options.cwd } : {});
	await fake.emit("session_start", { type: "session_start" }, ctx);
	await new Promise((resolve) => setImmediate(resolve));
	let ids = 0;

	/** `tool_call` only. Returns the id so the test can finish the call. */
	const start = async (toolName: string, input: Record<string, unknown>, id = `call-${++ids}`) => ({
		id,
		result: await fake.emit("tool_call", { type: "tool_call", toolName, toolCallId: id, input }, ctx) as ToolCallResult,
	});
	/** `tool_result` and `tool_execution_end`. */
	const finish = async (id: string, toolName: string, input: Record<string, unknown>) => {
		await fake.emit("tool_result", { type: "tool_result", toolName, toolCallId: id, input, content: [], isError: false }, ctx);
		await fake.emit("tool_execution_end", { type: "tool_execution_end", toolName, toolCallId: id, isError: false }, ctx);
	};
	/** A whole bash call: hooks, then the effect, then the result. */
	const bash = async (command: string, effect: () => void = () => {}) => {
		const input = { command };
		const { id, result } = await start("bash", input);
		if (!result?.block) {
			fs.tick(5);
			effect();
			fs.tick(5);
			await finish(id, "bash", input);
		}
		return result;
	};
	return {
		fs,
		fake,
		ctx,
		seen,
		start,
		finish,
		bash,
		/** A whole `write` or `edit` call. */
		tool: async (toolName: "write" | "edit", input: Record<string, unknown>, effect: () => void = () => {}) => {
			const { id, result } = await start(toolName, input);
			if (!result?.block) {
				fs.tick(5);
				effect();
				fs.tick(5);
				await finish(id, toolName, input);
			}
			return result;
		},
		setOnClassify(fn: () => void) {
			onClassify = fn;
		},
	};
}

const lastFacts = (seen: Array<{ extras?: ClassifyExtras }>) => seen.at(-1)?.extras?.extraFacts ?? [];

test("Jev sees a claim for a worktree the agent added earlier in the session", async () => {
	const env = await setup();
	await env.bash("git worktree add -q --detach /tmp/w HEAD", () => env.fs.mkdir("/tmp/w").write("/tmp/w/a"));
	env.fs.tick();
	assert.deepEqual(lastFacts(env.seen), []);
	await env.bash("git worktree remove --force /tmp/w", () => env.fs.rm("/tmp/w"));
	assert.equal(lastFacts(env.seen).length, 1);
	assert.match(lastFacts(env.seen)[0]!, /^created_this_session: \/tmp\/w \(folder;/);
});

test("on the Clef backend, a claim reaches the classifier", async () => {
	const env = await setup({ backend: "clef" });
	await env.bash("git worktree add -q --detach /tmp/w HEAD", () => env.fs.mkdir("/tmp/w").write("/tmp/w/a"));
	env.fs.tick();
	await env.bash("git worktree remove --force /tmp/w", () => env.fs.rm("/tmp/w"));
	assert.equal(lastFacts(env.seen).length, 1);
	assert.match(lastFacts(env.seen)[0]!, /^created_this_session: \/tmp\/w \(folder;/);
});

test("a claim that breaks while Jev reviews blocks the action, with a retry hint (T20)", async () => {
	const env = await setup();
	await env.bash("echo a > /tmp/r.diff", () => env.fs.write("/tmp/r.diff"));
	env.fs.tick();
	env.setOnClassify(() => env.fs.touchCtime("/tmp/r.diff"));
	const result = await env.bash("echo b > /tmp/r.diff");
	assert.equal(result?.block, true);
	assert.match(result?.reason ?? "", /changed while this action was reviewed; run it again/);
});

test("a claim that breaks during a deterministic allow does not block", async () => {
	const env = await setup({ permissionAllow: ["bash(echo b > /tmp/r.diff)"] });
	await env.bash("echo a > /tmp/r.diff", () => env.fs.write("/tmp/r.diff"));
	env.fs.tick();
	env.fs.touchCtime("/tmp/r.diff");
	const { result } = await env.start("bash", { command: "echo b > /tmp/r.diff" });
	assert.equal(result?.block, undefined);
});

test("while a claimed folder removal runs, calls that may change files wait (T11, T24)", async () => {
	const env = await setup();
	await env.bash("mkdir /tmp/s", () => env.fs.mkdir("/tmp/s"));
	env.fs.tick();
	const removal = await env.start("bash", { command: "rm -rf /tmp/s" });
	assert.equal(removal.result?.block, undefined);
	const write = await env.start("write", { path: "/tmp/s/x", content: "x" });
	assert.equal(write.result?.block, true);
	assert.match(write.result?.reason ?? "", /changing a session-created path/);
	const read = await env.start("read", { path: "/home/thesis.md" });
	assert.equal(read.result?.block, undefined);
	// A later extension blocked the removal: it still reaches tool_execution_end.
	await env.fake.emit("tool_execution_end", { type: "tool_execution_end", toolCallId: removal.id }, env.ctx);
	const retry = await env.start("write", { path: "/tmp/s/x", content: "x" });
	assert.equal(retry.result?.block, undefined);
});

test("a claimed folder removal waits for a running call that may change files", async () => {
	const env = await setup();
	await env.bash("mkdir /tmp/s", () => env.fs.mkdir("/tmp/s"));
	env.fs.tick();
	const move = await env.start("bash", { command: "mv /home/thesis.md /tmp/s/" });
	assert.equal(move.result?.block, undefined);
	const removal = await env.start("bash", { command: "rm -rf /tmp/s" });
	assert.equal(removal.result?.block, true);
	assert.match(removal.result?.reason ?? "", /Another action is still running/);
});

test("a claimed file refresh waits for a running call that may change files (T26)", async () => {
	const env = await setup();
	await env.bash("echo a > /tmp/r.diff", () => env.fs.write("/tmp/r.diff"));
	env.fs.tick();
	// Parallel mode: both preflights run before either call executes.
	const swap = await env.start("bash", { command: "mv /home/thesis.md /tmp/r.diff" });
	assert.equal(swap.result?.block, undefined);
	const removal = await env.start("bash", { command: "rm -f /tmp/r.diff" });
	assert.equal(lastFacts(env.seen).length, 1);
	assert.equal(removal.result?.block, true);
	assert.match(removal.result?.reason ?? "", /Another action is still running/);
});

test("agent_end and session_start clear running calls and the record", async () => {
	const env = await setup();
	await env.bash("mkdir /tmp/s", () => env.fs.mkdir("/tmp/s"));
	env.fs.tick();
	await env.start("bash", { command: "rm -rf /tmp/s" });
	await env.fake.emit("agent_end", { type: "agent_end" }, env.ctx);
	assert.equal((await env.start("write", { path: "/tmp/x", content: "x" })).result?.block, undefined);
	await env.fake.emit("session_start", { type: "session_start" }, env.ctx);
	await env.bash("rm -rf /tmp/s");
	assert.deepEqual(lastFacts(env.seen), []);
});

test("the LLM backend records nothing and passes no extras", async () => {
	const env = await setup({ backend: "llm" });
	await env.bash("mkdir /tmp/s", () => env.fs.mkdir("/tmp/s"));
	env.fs.tick();
	await env.bash("rm -rf /tmp/s");
	assert.equal(env.seen.at(-1)?.extras, undefined);
});

const SESSION_DIR = "/Users/dev/projects/data-migration";

function sessionEnv() {
	return setup({ cwd: SESSION_DIR }).then((env) => {
		let path = "";
		for (const part of ["Users", "dev", "projects", "data-migration"]) {
			path += `/${part}`;
			env.fs.mkdir(path);
		}
		env.fs.write(`${SESSION_DIR}/probes.ps1`, 100);
		env.fs.tick();
		return env;
	});
}

test("the write tool's file is claimed by the verbatim `cd && rm && wc` session command", async () => {
	const env = await sessionEnv();
	// A relative path, resolved against the session cwd as Pi does.
	await env.tool("write", { path: ".selftest.ps1", content: "x" }, () => env.fs.write(`${SESSION_DIR}/.selftest.ps1`, 20));
	env.fs.tick();
	await env.bash(`cd "${SESSION_DIR}" && rm .selftest.ps1 && wc -l probes.ps1`, () => env.fs.rm(`${SESSION_DIR}/.selftest.ps1`));
	assert.equal(lastFacts(env.seen).length, 1);
	assert.match(lastFacts(env.seen)[0]!, /\.selftest\.ps1 \(file; absent before and present after the agent's write tool call at /);
});

test("an edit keeps the write-recorded file claimed; a user change in between does not", async () => {
	const env = await sessionEnv();
	await env.tool("write", { path: ".a.ps1", content: "x" }, () => env.fs.write(`${SESSION_DIR}/.a.ps1`, 2));
	env.fs.tick();
	await env.tool("edit", { path: `${SESSION_DIR}/.a.ps1`, edits: [] }, () => env.fs.write(`${SESSION_DIR}/.a.ps1`, 5));
	env.fs.tick();
	await env.bash(`cd "${SESSION_DIR}" && rm .a.ps1`, () => {});
	assert.equal(lastFacts(env.seen).length, 1);
	env.fs.tick();
	env.fs.write(`${SESSION_DIR}/.a.ps1`, 5); // the user
	env.fs.tick();
	await env.tool("edit", { path: ".a.ps1", edits: [] }, () => env.fs.write(`${SESSION_DIR}/.a.ps1`, 6));
	env.fs.tick();
	await env.bash(`cd "${SESSION_DIR}" && rm .a.ps1`, () => {});
	assert.deepEqual(lastFacts(env.seen), []);
});

test("the write tool does not add facts for its own call", async () => {
	const env = await sessionEnv();
	await env.tool("write", { path: ".a.ps1", content: "x" }, () => env.fs.write(`${SESSION_DIR}/.a.ps1`, 2));
	env.fs.tick();
	await env.tool("write", { path: ".a.ps1", content: "y" }, () => env.fs.write(`${SESSION_DIR}/.a.ps1`, 3));
	assert.equal(env.seen.every((entry) => (entry.extras?.extraFacts ?? []).length === 0), true);
});

test("outputs of an unguarded script are recorded by the snapshot and claimed by a later guarded rm", async () => {
	const env = await sessionEnv();
	const script = `cd "${SESSION_DIR}" && pwsh -NoProfile -File ./.r3-test.ps1 2>&1 | tail -45`;
	await env.bash(script, () => {
		env.fs.mkdir(`${SESSION_DIR}/.r3-out`).mkdir(`${SESSION_DIR}/.r3-compat-out`);
		env.fs.write(`${SESSION_DIR}/_native.log`, 3).write(`${SESSION_DIR}/_compat.log`, 3);
	});
	env.fs.tick();
	await env.bash(`cd "${SESSION_DIR}" && rm -rf .r3-out .r3-compat-out _native.log _compat.log`, () => {
		for (const name of [".r3-out", ".r3-compat-out", "_native.log", "_compat.log"]) env.fs.rm(`${SESSION_DIR}/${name}`);
	});
	assert.equal(lastFacts(env.seen).length, 4);
	assert.match(lastFacts(env.seen)[0]!, /agent's bash command at /);
});

test("a read-only bash call is not snapshotted, and nothing is recorded after the call ended", async () => {
	const env = await sessionEnv();
	await env.bash("ls", () => env.fs.write(`${SESSION_DIR}/stray.txt`));
	env.fs.tick();
	await env.bash(`cd "${SESSION_DIR}" && rm stray.txt`, () => {});
	assert.deepEqual(lastFacts(env.seen), []);
	// The result arrives after tool_execution_end (or agent_end): nothing to compare.
	const input = { command: "pwsh x" };
	const { id } = await env.start("bash", input);
	env.fs.tick(5);
	env.fs.write(`${SESSION_DIR}/late.txt`);
	await env.fake.emit("tool_execution_end", { type: "tool_execution_end", toolCallId: id }, env.ctx);
	await env.fake.emit("tool_result", { type: "tool_result", toolName: "bash", toolCallId: id, input, content: [], isError: false }, env.ctx);
	await env.bash(`cd "${SESSION_DIR}" && rm late.txt`, () => {});
	assert.deepEqual(lastFacts(env.seen), []);
});

test("the LLM backend records nothing for write calls or snapshots", async () => {
	const env = await setup({ backend: "llm", cwd: "/tmp" });
	await env.tool("write", { path: "/tmp/a.md", content: "x" }, () => env.fs.write("/tmp/a.md", 1));
	await env.bash("pwsh x", () => env.fs.write("/tmp/b.log"));
	env.fs.tick();
	await env.bash("rm /tmp/a.md /tmp/b.log");
	assert.equal(env.seen.at(-1)?.extras, undefined);
});

// Revision: the guarded prefix.

const OUTPUTS = [".r3-out", ".r3-compat-out", "_native.log", "_compat.log"];
const RUN_SCRIPT = `cd "${SESSION_DIR}" && rm -rf ${OUTPUTS.join(" ")} && timeout 400 pwsh -NoProfile -File ./.r3-test.ps1 2>&1 | tail -45`;

/** What the pwsh script leaves behind: it recreates the outputs. */
function pwshOutputs(env: Awaited<ReturnType<typeof sessionEnv>>) {
	return () => {
		for (const name of OUTPUTS) env.fs.rm(`${SESSION_DIR}/${name}`);
		env.fs.mkdir(`${SESSION_DIR}/.r3-out`).write(`${SESSION_DIR}/.r3-out/a.json`);
		env.fs.mkdir(`${SESSION_DIR}/.r3-compat-out`);
		env.fs.write(`${SESSION_DIR}/_native.log`, 3).write(`${SESSION_DIR}/_compat.log`, 3);
	};
}

test("the `rm -rf … && timeout 400 pwsh …` session command gets claims and a scope line, run after run", async () => {
	const env = await sessionEnv();
	// First run: nothing was recorded yet, and the script creates the outputs.
	await env.bash(RUN_SCRIPT, pwshOutputs(env));
	assert.deepEqual(lastFacts(env.seen), []);
	for (const run of [2, 3, 4]) {
		env.fs.tick();
		await env.bash(RUN_SCRIPT, pwshOutputs(env));
		const facts = lastFacts(env.seen);
		assert.equal(facts.length, 5, `run ${run}`);
		assert.match(facts[0]!, /^created_this_session: .*\.r3-out \(folder; absent before and present after the agent's bash command/);
		assert.equal(
			facts[4],
			"created_this_session_scope: claims cover only commands before `timeout`; pi-automode did not analyse that command or anything after it",
		);
	}
});

test("the `python3 -c … && pwsh -Command …` session command gets claims for what write and scripts made", async () => {
	const env = await sessionEnv();
	for (const name of [".r3-compat.ps1", ".mock3.ps1", ".r3-test.ps1"]) {
		await env.tool("write", { path: name, content: "x" }, () => env.fs.write(`${SESSION_DIR}/${name}`, 5));
		env.fs.tick();
	}
	await env.tool("edit", { path: `${SESSION_DIR}/.mock3.ps1`, edits: [] }, () => env.fs.write(`${SESSION_DIR}/.mock3.ps1`, 9));
	env.fs.tick();
	await env.bash(`cd "${SESSION_DIR}" && pwsh -NoProfile -File ./.r3-test.ps1`, () => {
		env.fs.mkdir(`${SESSION_DIR}/.r3-out`).mkdir(`${SESSION_DIR}/.r3-compat-out`).write(`${SESSION_DIR}/.r3-token.txt`, 2);
		env.fs.write(`${SESSION_DIR}/_native.log`).write(`${SESSION_DIR}/_compat.log`);
	});
	env.fs.tick();
	const command = `cd "${SESSION_DIR}" && rm -rf .r3-out .r3-compat-out .r3-token.txt .r3-compat.ps1 .mock3.ps1 .r3-test.ps1 _native.log _compat.log && python3 -c "print(1)" && pwsh -NoProfile -Command 'Write-Host hi'`;
	await env.bash(command, () => {});
	const facts = lastFacts(env.seen);
	assert.equal(facts.length, 9);
	assert.match(facts[8]!, /^created_this_session_scope: claims cover only commands before `python3`;/);
	assert.equal(facts.filter((line) => /write tool call/.test(line)).length, 3);
});

test("a user-edited scratch file cancels the claims of the whole prefix", async () => {
	const env = await sessionEnv();
	await env.bash(RUN_SCRIPT, pwshOutputs(env));
	env.fs.tick();
	env.fs.touchCtime(`${SESSION_DIR}/_native.log`);
	await env.bash(RUN_SCRIPT, pwshOutputs(env));
	assert.deepEqual(lastFacts(env.seen), []);
});

test("a prefix call and another file-changing call wait for each other", async () => {
	const env = await sessionEnv();
	await env.bash(RUN_SCRIPT, pwshOutputs(env));
	env.fs.tick();
	// The prefix call runs: it protects its paths, and the rest may change any file.
	const running = await env.start("bash", { command: RUN_SCRIPT });
	assert.equal(running.result?.block, undefined);
	assert.equal(lastFacts(env.seen).length, 5);
	const other = await env.start("bash", { command: "pwsh other.ps1" });
	assert.equal(other.result?.block, true);
	assert.match(other.result?.reason ?? "", /changing a session-created path/);
	const edit = await env.start("write", { path: "/tmp/x.md", content: "x" });
	assert.equal(edit.result?.block, true);
	const read = await env.start("bash", { command: "ls" });
	assert.equal(read.result?.block, undefined);
	// A call that could change a claimed path waits even when it is guarded.
	const guarded = await env.start("bash", { command: `rm -rf ${SESSION_DIR}/_native.log` });
	assert.equal(guarded.result?.block, true);
	await env.fake.emit("tool_execution_end", { type: "tool_execution_end", toolCallId: running.id }, env.ctx);
	assert.equal((await env.start("bash", { command: "pwsh other.ps1" })).result?.block, undefined);
});

test("a prefix call waits for a file-changing call that is already running", async () => {
	const env = await sessionEnv();
	await env.bash(RUN_SCRIPT, pwshOutputs(env));
	env.fs.tick();
	const mover = await env.start("bash", { command: `mv /home/thesis.md ${SESSION_DIR}/_native.log` });
	assert.equal(mover.result?.block, undefined);
	const run = await env.start("bash", { command: RUN_SCRIPT });
	assert.equal(lastFacts(env.seen).length, 5);
	assert.equal(run.result?.block, true);
	assert.match(run.result?.reason ?? "", /Another action is still running/);
});

test("a prefix with a visible deletion in the rest gets no claims and no scope line", async () => {
	const env = await sessionEnv();
	await env.bash(RUN_SCRIPT, pwshOutputs(env));
	env.fs.tick();
	await env.bash(`${RUN_SCRIPT} && rm -rf /home/thesis.md`, () => {});
	assert.deepEqual(lastFacts(env.seen), []);
});

test("session_start lists the session folder, so a user's entry moved away before the first call is never recorded", async () => {
	const env = await setup({
		cwd: "/work/proj",
		prepare: (fs) => {
			fs.mkdir("/work").mkdir("/work/proj").write("/work/proj/notes.md", 7).mkdir("/work/proj/scratch");
		},
	});
	env.fs.tick();
	// The user stashes outside any call; the first bash call restores them.
	env.fs.mv("/work/proj/notes.md", "/home/notes.md");
	env.fs.rm("/work/proj/scratch");
	await env.bash("cp /home/notes.md /work/proj/notes.md && pwsh x", () => {
		env.fs.write("/work/proj/notes.md", 7).mkdir("/work/proj/scratch").write("/work/proj/script-made.txt", 1);
	});
	env.fs.tick();
	await env.bash("rm -rf /work/proj/notes.md /work/proj/scratch", () => {});
	assert.deepEqual(lastFacts(env.seen), []);
	await env.bash("rm /work/proj/script-made.txt", () => {});
	assert.equal(lastFacts(env.seen).length, 1);
	// session_start again (new session): the taint is gone with the record.
	await env.fake.emit("session_start", { type: "session_start" }, env.ctx);
});

test("the LLM backend takes no baseline listing", async () => {
	let listed = 0;
	const env = await setup({
		backend: "llm",
		cwd: "/work/proj",
		prepare: (fs) => {
			fs.mkdir("/work").mkdir("/work/proj").write("/work/proj/a.txt");
			const original = fs.readdir.bind(fs);
			fs.readdir = async (path: string) => (listed++, original(path));
		},
	});
	await env.fake.emit("session_start", { type: "session_start" }, env.ctx);
	await new Promise((resolve) => setImmediate(resolve));
	assert.equal(listed, 0);
});

// Review round 3: C records only in folders with a session-start baseline.

async function otherFolderEnv() {
	return setup({
		cwd: "/work/proj",
		prepare: (fs) => {
			fs.mkdir("/work").mkdir("/work/proj").mkdir("/other").write("/other/notes.md", 7);
		},
	});
}

test("a user file moved out of a non-cwd cd folder and restored later is never recorded", async () => {
	const env = await otherFolderEnv();
	env.fs.tick();
	await env.bash("mv /other/notes.md /home/x", () => env.fs.mv("/other/notes.md", "/home/x"));
	env.fs.tick();
	await env.bash('cd "/other" && cp /home/x notes.md && pwsh run.ps1', () => {
		env.fs.write("/other/notes.md", 7).write("/other/script-made.txt", 1);
	});
	env.fs.tick();
	await env.bash('cd "/other" && rm notes.md script-made.txt', () => {});
	assert.deepEqual(lastFacts(env.seen), []);
	// Snapshot recording in the session cwd still works.
	await env.bash("pwsh run.ps1", () => env.fs.write("/work/proj/made.txt", 1));
	env.fs.tick();
	await env.bash("rm /work/proj/made.txt", () => {});
	assert.equal(lastFacts(env.seen).length, 1);
});

test("a non-cwd cd folder still gets prefix-plan claims for paths a plan recorded", async () => {
	const env = await otherFolderEnv();
	env.fs.tick();
	const run = 'cd "/other" && rm -rf out log.txt && mkdir out && echo x > log.txt && pwsh run.ps1';
	await env.bash(run, () => {
		env.fs.mkdir("/other/out").write("/other/log.txt", 2).write("/other/script-made.txt", 1);
	});
	env.fs.tick();
	await env.bash('cd "/other" && rm -rf out log.txt && pwsh run.ps1', () => {});
	const facts = lastFacts(env.seen);
	assert.equal(facts.length, 3);
	assert.match(facts[0]!, /^created_this_session: \/other\/out \(folder; absent before and present after the agent's mkdir/);
	assert.match(facts[1]!, /^created_this_session: \/other\/log\.txt \(file; absent before and present after the agent's redirect/);
	assert.match(facts[2]!, /^created_this_session_scope: .*`pwsh`/);
	// What the script made there was not snapshotted.
	await env.bash('cd "/other" && rm script-made.txt && pwsh y', () => {});
	assert.deepEqual(lastFacts(env.seen), []);
});

// Review round 4: no snapshot for an action that may restore data.

test("a pre-session stash popped by the agent is not recorded: no snapshot for restoring actions", async () => {
	const env = await otherFolderEnv();
	env.fs.tick();
	// notes.md was stashed before the session, so it is absent from the baseline.
	await env.bash("git stash pop", () => env.fs.write("/work/proj/notes.md", 7));
	await env.bash("tar xf a.tar --touch && pwsh x", () => env.fs.write("/work/proj/extracted.txt", 1));
	env.fs.tick();
	await env.bash("rm /work/proj/notes.md /work/proj/extracted.txt", () => {});
	assert.deepEqual(lastFacts(env.seen), []);
	// A read-only git call or a diff still snapshots what a script leaves behind.
	await env.bash("git status && pwsh run.ps1", () => env.fs.write("/work/proj/made.txt", 1));
	env.fs.tick();
	await env.bash("rm /work/proj/made.txt", () => {});
	assert.equal(lastFacts(env.seen).length, 1);
	// Plan-recorded creations are unaffected by a restoring action.
	await env.bash("mkdir /work/proj/out && echo x > /work/proj/log.txt && git stash pop", () => {
		env.fs.mkdir("/work/proj/out").write("/work/proj/log.txt", 2);
	});
	env.fs.tick();
	await env.bash("rm -rf /work/proj/out /work/proj/log.txt", () => {});
	assert.equal(lastFacts(env.seen).length, 2);
});

// Review round 5: a restoring call in the same batch as a snapshotting call.

async function overlapEnv() {
	const env = await otherFolderEnv();
	env.fs.tick();
	return env;
}

const restoreEffect = (env: Awaited<ReturnType<typeof overlapEnv>>) => () => {
	env.fs.write("/work/proj/notes.md", 7); // Y's `git stash pop`
	env.fs.write("/work/proj/script-made.txt", 1); // X's script
};

async function claimedAfterOverlap(env: Awaited<ReturnType<typeof overlapEnv>>) {
	env.fs.tick();
	await env.bash("rm /work/proj/notes.md /work/proj/script-made.txt", () => {});
	return lastFacts(env.seen);
}

test("Y (git stash pop) admitted before X (pwsh) is prepared: X records nothing", async () => {
	const env = await overlapEnv();
	const y = await env.start("bash", { command: "git stash pop" });
	const x = await env.start("bash", { command: "pwsh -File t.ps1" });
	assert.equal(y.result?.block, undefined);
	assert.equal(x.result?.block, undefined);
	env.fs.tick(5);
	restoreEffect(env)();
	env.fs.tick(5);
	await env.finish(x.id, "bash", { command: "pwsh -File t.ps1" });
	await env.finish(y.id, "bash", { command: "git stash pop" });
	assert.deepEqual(await claimedAfterOverlap(env), []);
});

test("Y admitted while X is pending: X records nothing", async () => {
	const env = await overlapEnv();
	const x = await env.start("bash", { command: "pwsh -File t.ps1" });
	const y = await env.start("bash", { command: "git stash pop" });
	env.fs.tick(5);
	restoreEffect(env)();
	env.fs.tick(5);
	await env.finish(y.id, "bash", { command: "git stash pop" });
	await env.finish(x.id, "bash", { command: "pwsh -File t.ps1" });
	assert.deepEqual(await claimedAfterOverlap(env), []);
});

test("a restore that finished before X started does not affect X", async () => {
	const env = await overlapEnv();
	const y = await env.start("bash", { command: "git stash pop" });
	env.fs.tick(5);
	env.fs.write("/work/proj/notes.md", 7);
	await env.finish(y.id, "bash", { command: "git stash pop" });
	env.fs.tick(5);
	await env.bash("pwsh -File t.ps1", () => env.fs.write("/work/proj/script-made.txt", 1));
	env.fs.tick();
	await env.bash("rm /work/proj/script-made.txt", () => {});
	assert.equal(lastFacts(env.seen).length, 1);
});

test("a blocked-later restoring call is released by tool_execution_end and agent_end", async () => {
	const env = await overlapEnv();
	const y = await env.start("bash", { command: "git stash pop" });
	await env.fake.emit("tool_execution_end", { type: "tool_execution_end", toolCallId: y.id }, env.ctx);
	await env.bash("pwsh -File t.ps1", () => env.fs.write("/work/proj/script-made.txt", 1));
	env.fs.tick();
	await env.bash("rm /work/proj/script-made.txt", () => {});
	assert.equal(lastFacts(env.seen).length, 1);
	await env.start("bash", { command: "git stash pop" });
	await env.fake.emit("agent_end", { type: "agent_end" }, env.ctx);
	await env.bash("pwsh -File u.ps1", () => env.fs.write("/work/proj/second.txt", 1));
	env.fs.tick();
	await env.bash("rm /work/proj/second.txt", () => {});
	assert.equal(lastFacts(env.seen).length, 1);
});
