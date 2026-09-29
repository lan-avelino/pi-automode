import assert from "node:assert/strict";
import test from "node:test";
import { createPiAutomode } from "../extensions/auto-mode.ts";
import type { ClassifyResult, EffectiveConfig } from "../extensions/auto-mode.ts";
import { baseConfig, createFakeCtx, createFakePi } from "./test-helpers.ts";

const SOFT_BLOCK: ClassifyResult = {
	decision: "block",
	tier: "soft_deny",
	reason: "Jev: soft-deny rule 6 scored 0.71 (threshold 0.55): \"Writing through remote shells\". Scores: hard=0.11",
};
const HARD_BLOCK: ClassifyResult = { decision: "block", tier: "hard_deny", reason: "Jev: hard_deny scored 0.90" };

const RESTART = "ssh prod-proxy 'sudo systemctl restart nginx' > /tmp/restart.log";
const ONCE = "Allow once";
const DENY = "Deny";

type Prompt = { title: string; options: string[] };
type Answer = string | undefined | Error | ((prompt: Prompt) => string | undefined);

const similar = (prompt: Prompt) =>
	prompt.options.find((option) => option.startsWith("Allow similar for this session: "));

/**
 * A session whose Jev classifier returns `decisions` in order (the last one
 * repeats) and whose select prompt returns `answers` in order.
 */
async function harness(options: {
	config?: Partial<EffectiveConfig>;
	decisions?: ClassifyResult[];
	hasUI?: boolean;
	mode?: string;
	answers?: Answer[];
	llm?: boolean;
} = {}) {
	const decisions = [...(options.decisions ?? [SOFT_BLOCK])];
	const next = () => (decisions.length > 1 ? decisions.shift()! : decisions[0]!);
	const fake = createFakePi();
	createPiAutomode({
		loadConfig: () =>
			baseConfig({ classifierBackend: options.llm ? "llm" : "jev", ...options.config }),
		classifyAction: async () => next(),
		jevClassifyAction: async () => next(),
	})(fake.pi);
	const ctx = createFakeCtx(fake.entries, {
		hasUI: options.hasUI ?? true,
		mode: options.mode ?? "tui",
	});
	const prompts: Prompt[] = [];
	const answers = [...(options.answers ?? [])];
	(ctx.ui as Record<string, unknown>).select = async (title: string, choices: string[]) => {
		const prompt = { title, options: choices };
		prompts.push(prompt);
		const answer = answers.shift();
		if (answer instanceof Error) throw answer;
		return typeof answer === "function" ? answer(prompt) : answer;
	};
	await fake.emit("session_start", { type: "session_start" }, ctx);
	const run = async (command: string, toolName = "bash") =>
		await fake.emit("tool_call", {
			toolName,
			input: toolName === "bash"
				? { command }
				: toolName === "edit"
				? { path: command, edits: [{ oldText: "a", newText: "b" }] }
				: { url: command },
		}, ctx) as { block?: boolean; reason?: string } | undefined;
	return { fake, ctx, prompts, run };
}

test("a Jev soft deny offers once, similar-for-session, and deny, with the reason and action", async () => {
	const h = await harness({ answers: [ONCE] });
	assert.equal(await h.run(RESTART), undefined);
	assert.equal(h.prompts.length, 1);
	const prompt = h.prompts[0]!;
	assert.match(prompt.title, /^Auto mode soft deny/);
	assert.match(prompt.title, /soft-deny rule 6 scored 0\.71/);
	assert.match(prompt.title, /ssh prod-proxy 'sudo systemctl restart nginx' > \/tmp\/restart\.log/);
	assert.deepEqual(prompt.options, [
		ONCE,
		"Allow similar for this session: ssh prod-proxy 'sudo systemctl restart nginx' > /tmp/restart.log",
		DENY,
	]);
});

test("allow once does not carry over to the next identical action", async () => {
	const h = await harness({ answers: [ONCE, DENY] });
	assert.equal(await h.run(RESTART), undefined);
	const second = await h.run(RESTART);
	assert.equal(h.prompts.length, 2);
	assert.equal(second?.block, true);
	assert.match(second?.reason ?? "", /The user declined it\./);
});

test("allow similar skips the prompt for matching soft denies for the rest of the session", async () => {
	const h = await harness({ answers: [similar, DENY, DENY] });
	assert.equal(await h.run(RESTART), undefined);
	// A matching command runs without a prompt.
	assert.equal(await h.run(RESTART), undefined);
	assert.equal(h.prompts.length, 1);
	// A different command still asks.
	const other = await h.run("ssh prod-proxy 'sudo systemctl restart php-fpm'");
	assert.equal(other?.block, true);
	assert.equal(h.prompts.length, 2);

	// /automode approvals lists the pattern, and clear removes it.
	await h.fake.commands.get("automode")?.handler("approvals", h.ctx);
	const listing = h.ctx.notifications.at(-1)?.message ?? "";
	assert.match(listing, /1 session approval/);
	assert.match(listing, /ssh prod-proxy 'sudo systemctl restart nginx'/);
	await h.fake.commands.get("automode")?.handler("approvals clear", h.ctx);
	assert.match(h.ctx.notifications.at(-1)?.message ?? "", /Cleared 1 session approval/);
	assert.equal((await h.run(RESTART))?.block, true);
	assert.equal(h.prompts.length, 3);
});

test("a session approval never overrides a hard deny", async () => {
	const h = await harness({ decisions: [SOFT_BLOCK, HARD_BLOCK], answers: [similar] });
	assert.equal(await h.run(RESTART), undefined);
	const hard = await h.run(RESTART);
	assert.equal(hard?.block, true);
	assert.match(hard?.reason ?? "", /hard_deny/);
	assert.equal(h.prompts.length, 1);
});

test("session approvals are cleared when a session starts", async () => {
	const h = await harness({ answers: [similar, DENY] });
	assert.equal(await h.run(RESTART), undefined);
	await h.fake.emit("session_start", { type: "session_start" }, h.ctx);
	assert.equal((await h.run(RESTART))?.block, true);
	assert.equal(h.prompts.length, 2);
});

test("a soft deny with no parser pattern offers only once and deny", async () => {
	const dynamic = await harness({ answers: [DENY] });
	assert.equal((await dynamic.run("ls $(pwd) > /tmp/x"))?.block, true);
	assert.deepEqual(dynamic.prompts[0]!.options, [ONCE, DENY]);
	const web = await harness({ answers: [ONCE] });
	assert.equal(await web.run("https://example.com", "webfetch"), undefined);
	assert.deepEqual(web.prompts[0]!.options, [ONCE, DENY]);
});

test("a one-off command offers only once and deny", async () => {
	const h = await harness({ answers: [ONCE] });
	const probe =
		"ssh prod-proxy 'sudo -n true 2>&1 && echo SUDO_NOPASS_OK || echo SUDO_NEEDS_PASS; echo ---; grep -n -B2 -A12 \"^  db:\" ~/proxy/docker-compose.yml | head -40'";
	assert.equal(await h.run(probe), undefined);
	assert.deepEqual(h.prompts[0]!.options, [ONCE, DENY]);
});

test("a dismissed, failing, or cancelled prompt blocks", async () => {
	const dismissed = await harness({ answers: [undefined] });
	const result = await dismissed.run(RESTART);
	assert.equal(result?.block, true);
	assert.match(result?.reason ?? "", /The user declined it\./);

	const failing = await harness({ answers: [new Error("aborted")] });
	const failed = await failing.run(RESTART);
	assert.equal(failed?.block, true);
	assert.match(failed?.reason ?? "", /The approval prompt was cancelled or failed\./);
});

test("hard denies, classifier failures, headless runs, and the LLM backend never ask", async () => {
	const cases: Array<Parameters<typeof harness>[0] & { name: string }> = [
		{ name: "hard deny", decisions: [HARD_BLOCK] },
		{
			name: "classifier failure",
			decisions: [{ decision: "block", tier: "none", reason: "Jev classifier failed; auto mode fails closed" }],
		},
		{ name: "headless", hasUI: false },
		{ name: "disabled", config: { jevConfirmSoftDeny: false } },
		{ name: "llm backend", llm: true },
	];
	for (const { name, ...options } of cases) {
		const h = await harness({ ...options, answers: [ONCE] });
		const result = await h.run(RESTART);
		assert.equal(h.prompts.length, 0, name);
		assert.equal(result?.block, true, name);
	}
});

test("subagents and other non-terminal modes block a soft deny instead of waiting for an answer", async () => {
	// pi reports hasUI in RPC mode, but a subagent's RPC client never answers a
	// dialog, so prompting would hang the subagent.
	for (const mode of ["rpc", "json", "print"]) {
		const h = await harness({ mode, answers: [ONCE] });
		const result = await h.run(RESTART);
		assert.equal(h.prompts.length, 0, mode);
		assert.equal(result?.block, true, mode);
		assert.match(result?.reason ?? "", /Not asked: no interactive terminal\./, mode);
	}
});

test("permissions.ask blocks in non-terminal modes instead of waiting for an answer", async () => {
	const fake = createFakePi();
	const { parseToolPattern } = await import("../extensions/auto-mode.ts");
	createPiAutomode({
		loadConfig: () => baseConfig({ permissionAsk: [parseToolPattern("bash(ssh *)")!] }),
		classifyAction: async () => ({ decision: "allow", tier: "none", reason: "ok" }),
	})(fake.pi);
	const ctx = createFakeCtx(fake.entries, { hasUI: true, mode: "rpc" });
	let asked = 0;
	ctx.ui.confirm = async () => {
		asked += 1;
		return true;
	};
	await fake.emit("session_start", { type: "session_start" }, ctx);
	const result = await fake.emit("tool_call", { toolName: "bash", input: { command: "ssh web-1 uptime" } }, ctx) as {
		block?: boolean;
		reason?: string;
	};
	assert.equal(asked, 0);
	assert.equal(result.block, true);
	assert.match(result.reason ?? "", /no interactive terminal/);
});

// --- session folder approvals ------------------------------------------------

import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const folderOption = (prompt: Prompt) =>
	prompt.options.find((option) => option.startsWith("Allow edits under "));

test("an edit soft deny offers the repository folder for the rest of the session", async () => {
	const repo = mkdtempSync(join(tmpdir(), "pi-automode-folder-"));
	mkdirSync(join(repo, ".git"));
	mkdirSync(join(repo, "src"));
	try {
		const h = await harness({ answers: [folderOption, DENY, DENY] });
		assert.equal(await h.run(join(repo, "src/app.js"), "edit"), undefined);
		const prompt = h.prompts[0]!;
		assert.ok(folderOption(prompt)?.endsWith("for this session"), prompt.options.join(" | "));
		assert.match(folderOption(prompt)!, /pi-automode-folder-/);
		// Later edits anywhere in the repository no longer prompt.
		assert.equal(await h.run(join(repo, "README.md"), "edit"), undefined);
		assert.equal(await h.run(join(repo, "src/deep/x.js"), "edit"), undefined);
		assert.equal(h.prompts.length, 1);
		// Protected paths inside it, and folders outside it, still prompt.
		assert.equal((await h.run(join(repo, ".git/config"), "edit"))?.block, true);
		assert.equal((await h.run(join(tmpdir(), "elsewhere.js"), "edit"))?.block, true);
		assert.equal(h.prompts.length, 3);

		await h.fake.commands.get("automode")?.handler("approvals", h.ctx);
		assert.match(h.ctx.notifications.at(-1)?.message ?? "", /edits under .*pi-automode-folder-/);
		await h.fake.commands.get("automode")?.handler("approvals clear", h.ctx);
		assert.equal((await h.run(join(repo, "README.md"), "edit"))?.block, true);
	} finally {
		rmSync(repo, { recursive: true, force: true });
	}
});

test("the folder option is not offered for bash or for a folder containing home", async () => {
	const { homedir } = await import("node:os");
	const bash = await harness({ answers: [DENY] });
	await bash.run(RESTART);
	assert.equal(folderOption(bash.prompts[0]!), undefined);

	// A file directly in the home directory has no safe folder to offer.
	const home = await harness({ answers: [DENY] });
	await home.run(join(homedir(), "pi-automode-not-a-real-file.txt"), "edit");
	assert.equal(folderOption(home.prompts[0]!), undefined);
});

test("session folder approvals are cleared when a session starts", async () => {
	const repo = mkdtempSync(join(tmpdir(), "pi-automode-folder-"));
	try {
		const h = await harness({ answers: [folderOption, DENY] });
		assert.equal(await h.run(join(repo, "a.js"), "edit"), undefined);
		await h.fake.emit("session_start", { type: "session_start" }, h.ctx);
		assert.equal((await h.run(join(repo, "b.js"), "edit"))?.block, true);
		assert.equal(h.prompts.length, 2);
	} finally {
		rmSync(repo, { recursive: true, force: true });
	}
});

