import assert from "node:assert/strict";
import test from "node:test";
import { createPiAutomode } from "../extensions/auto-mode.ts";
import type { ClassifyResult, EffectiveConfig } from "../extensions/auto-mode.ts";
import { baseConfig, createFakeCtx, createFakePi } from "./test-helpers.ts";

const SOFT_BLOCK: ClassifyResult = {
	decision: "block",
	tier: "soft_deny",
	reason: "Jev: soft-deny rule 6 scored 0.71 (threshold 0.50): \"Writing through remote shells\". Scores: hard=0.11",
};

type Outcome = {
	result: { block?: boolean; reason?: string } | undefined;
	prompts: Array<{ title: string; message: string }>;
	ctx: ReturnType<typeof createFakeCtx>;
	fake: ReturnType<typeof createFakePi>;
};

async function runSoftBlock(options: {
	config?: Partial<EffectiveConfig>;
	decision?: ClassifyResult;
	hasUI?: boolean;
	confirm?: () => Promise<boolean>;
	llm?: boolean;
}): Promise<Outcome> {
	const decision = options.decision ?? SOFT_BLOCK;
	const fake = createFakePi();
	createPiAutomode({
		loadConfig: () =>
			baseConfig({
				classifierBackend: options.llm ? "llm" : "jev",
				...options.config,
			}),
		classifyAction: async () => decision,
		jevClassifyAction: async () => decision,
	})(fake.pi);
	const ctx = createFakeCtx(fake.entries, { hasUI: options.hasUI ?? true });
	const prompts: Outcome["prompts"] = [];
	ctx.ui.confirm = async (title: string, message: string) => {
		prompts.push({ title, message });
		return options.confirm ? options.confirm() : true;
	};
	await fake.emit("session_start", { type: "session_start" }, ctx);
	const result = await fake.emit("tool_call", {
		toolName: "bash",
		input: { command: "ssh prod-proxy 'curl -s localhost:4000/metrics/' > /tmp/m.txt" },
	}, ctx) as Outcome["result"];
	return { result, prompts, ctx, fake };
}

test("a Jev soft deny asks the user and runs the action once on approval", async () => {
	const { result, prompts } = await runSoftBlock({});
	assert.equal(result, undefined);
	assert.equal(prompts.length, 1);
	assert.equal(prompts[0]!.title, "Auto mode soft deny");
	// The prompt shows why Jev objected and the exact action.
	assert.match(prompts[0]!.message, /soft-deny rule 6 scored 0\.71/);
	assert.match(prompts[0]!.message, /ssh prod-proxy 'curl -s localhost:4000\/metrics\/' > \/tmp\/m\.txt/);
	assert.match(prompts[0]!.message, /Allow this action once\?/);
});

test("approval does not carry over to the next identical action", async () => {
	let answers = [true, false];
	const { fake, ctx, prompts } = await runSoftBlock({
		confirm: async () => answers.shift() ?? false,
	});
	const second = await fake.emit("tool_call", {
		toolName: "bash",
		input: { command: "ssh prod-proxy 'curl -s localhost:4000/metrics/' > /tmp/m.txt" },
	}, ctx) as { block?: boolean; reason?: string };
	assert.equal(prompts.length, 2);
	assert.equal(second.block, true);
	assert.match(second.reason ?? "", /The user declined it/);
	assert.match(second.reason ?? "", /soft-deny rule 6 scored 0\.71/);
});

test("a declined soft deny blocks with the Jev reason", async () => {
	const { result } = await runSoftBlock({ confirm: async () => false });
	assert.equal(result?.block, true);
	assert.match(result?.reason ?? "", /soft-deny rule 6 scored 0\.71/);
	assert.match(result?.reason ?? "", /The user declined it/);
});

test("a failing or cancelled prompt blocks", async () => {
	const { result } = await runSoftBlock({
		confirm: async () => {
			throw new Error("aborted");
		},
	});
	assert.equal(result?.block, true);
	assert.match(result?.reason ?? "", /soft-deny rule 6 scored 0\.71/);
	assert.match(result?.reason ?? "", /The approval prompt was cancelled or failed\./);
});

test("hard denies, classifier failures, headless runs, and the LLM backend never ask", async () => {
	const cases: Array<Parameters<typeof runSoftBlock>[0] & { name: string }> = [
		{
			name: "hard deny",
			decision: { decision: "block", tier: "hard_deny", reason: "Jev: hard_deny 0.90" },
		},
		{
			name: "classifier failure",
			decision: { decision: "block", tier: "none", reason: "Jev classifier failed; auto mode fails closed" },
		},
		{ name: "headless", hasUI: false },
		{ name: "disabled", config: { jevConfirmSoftDeny: false } },
		{ name: "llm backend", llm: true },
	];
	for (const { name, ...options } of cases) {
		const { result, prompts } = await runSoftBlock(options);
		assert.equal(prompts.length, 0, name);
		assert.equal(result?.block, true, name);
	}
});
