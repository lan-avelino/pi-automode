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
	backend?: "jev" | "llm";
	permissionAllow?: string[];
} = {}) {
	const fs = new FakeFs();
	fs.mkdir("/tmp").mkdir("/home").write("/home/thesis.md");
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
	const ctx = createFakeCtx(fake.entries);
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
	assert.match(write.result?.reason ?? "", /removing a session-created folder/);
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
