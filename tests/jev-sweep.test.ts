import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
	buildJevQuestions,
	jevDecision,
	jevGateScores,
} from "../extensions/auto-mode.ts";
import {
	caseConfig,
	caseState,
	casesFromLogEntries,
	parseCorpus,
	summarizeSweep,
	type CorpusCase,
} from "../scripts/jev-sweep-lib.ts";
import { baseConfig } from "./test-helpers.ts";

const HERE = dirname(fileURLToPath(import.meta.url));

function bashCase(overrides: Partial<CorpusCase> = {}): CorpusCase {
	return {
		name: "case",
		want: "allow",
		user: ["Check the logs"],
		action: { toolName: "bash", input: { command: "ls" } },
		...overrides,
	};
}

// --- gate scores -------------------------------------------------------------

test("jevGateScores reports the gates jevDecision uses", () => {
	const config = baseConfig({ softDeny: ["RULE_ONE", "RULE_TWO"] });
	const questions = buildJevQuestions(config);
	const scores = {
		hard_deny: 0.1,
		soft_deny_1: 0.3,
		soft_deny_2: 0.6,
		intent_mismatch: 0.4,
		scope_escape: 0.2,
	};
	assert.deepEqual(jevGateScores(scores, questions), {
		hard: 0.1,
		softRule: 0.6,
		softRuleNumber: 2,
		intent: 0.4,
		scope: 0.2,
		soft: 0.6,
	});
	assert.match(jevDecision(scores, config, questions).reason, /rule 2 scored 0\.60/);
	assert.equal(
		jevGateScores({ hard_deny: 0, intent_mismatch: 0.2, scope_escape: 0 }, buildJevQuestions(baseConfig()))
			.softRuleNumber,
		undefined,
	);
});

// --- corpus parsing ----------------------------------------------------------

test("parseCorpus accepts valid cases and reports invalid ones by index", () => {
	const { cases, errors } = parseCorpus({
		cases: [
			bashCase({ name: "good" }),
			{ name: "no action", want: "allow", user: ["x"] },
			{ name: "bad want", want: "maybe", user: ["x"], action: { toolName: "bash", input: {} } },
			{ ...bashCase({ name: "bad hosts" }), trustedHosts: "proxy" },
		],
	});
	assert.deepEqual(cases.map((c) => c.name), ["good"]);
	assert.deepEqual(errors, [
		"cases[1] (no action): action must be { toolName, input }",
		"cases[2] (bad want): want must be allow, block, or unlabeled",
		"cases[3] (bad hosts): trustedHosts must be an array of strings",
	]);
	assert.deepEqual(parseCorpus([]).errors, ["corpus must be an object with a cases array"]);
});

test("the committed synthetic corpus parses and labels every case", () => {
	const raw = JSON.parse(readFileSync(join(HERE, "fixtures/jev-corpus.json"), "utf8"));
	const { cases, errors } = parseCorpus(raw);
	assert.deepEqual(errors, []);
	assert.ok(cases.length >= 40, `only ${cases.length} cases`);
	assert.equal(new Set(cases.map((c) => c.name)).size, cases.length, "case names are unique");
	assert.ok(cases.every((c) => c.want !== "unlabeled"));
	assert.ok(cases.filter((c) => c.want === "allow").length >= 15);
	assert.ok(cases.filter((c) => c.want === "block").length >= 15);
});

// --- state -------------------------------------------------------------------

test("caseState builds the same state fields the classifier sends", () => {
	const state = caseState(
		bashCase({
			user: ["First ask", "Only read"],
			recentActions: ['memory_read: {"target":"long_term"}'],
			action: { toolName: "bash", input: { command: "ssh prod-proxy uptime" } },
			trustedHosts: ["prod-proxy"],
		}),
		baseConfig(),
	);
	assert.equal(state.user_request, "User: First ask\nUser: Only read");
	assert.equal(state.recent_actions, 'ToolCall memory_read: {"target":"long_term"}');
	assert.equal(state.action, '{"toolName":"bash","input":{"command":"ssh prod-proxy uptime"}}');
	assert.match(state.facts!, /^remote_shell: ssh host=prod-proxy trusted=true /m);
	assert.equal(state.project_instructions, "(none)");
	// Without case hosts, the config's trustedHosts apply.
	const fromConfig = caseState(
		bashCase({ action: { toolName: "bash", input: { command: "ssh db-1 uptime" } } }),
		baseConfig({ trustedHosts: ["db-1"] }),
	);
	assert.match(fromConfig.facts!, /host=db-1 trusted=true/);
});

test("caseConfig applies a case's trusted hosts to the questions too", () => {
	const config = caseConfig(bashCase({ trustedHosts: ["prod-proxy"] }), baseConfig());
	assert.deepEqual(config.trustedHosts, ["prod-proxy"]);
	assert.match(buildJevQuestions(config).scope_escape!.instructions, /Trusted SSH hosts \(autoMode\.trustedHosts\): prod-proxy\./);
	assert.deepEqual(caseConfig(bashCase(), baseConfig({ trustedHosts: ["db-1"] })).trustedHosts, ["db-1"]);
	assert.deepEqual(caseConfig(bashCase({ scratchRoots: ["/tmp"] }), baseConfig()).scratchRoots, ["/tmp"]);
});

// --- log extraction ----------------------------------------------------------

function classifierEntry(decisionId: string, context: Record<string, string>, action: string) {
	return {
		type: "classifier",
		decisionId,
		prompt: { context: JSON.stringify(context), action },
	};
}

test("casesFromLogEntries rebuilds cases from old and new state formats", () => {
	const action = '{"toolName":"bash","input":{"command":"ssh prod-proxy hostname"}}';
	const entries = [
		// Old format: tool calls were mixed into user_request, and a user turn
		// can span several lines.
		classifierEntry("a1", {
			user_request:
				"User: Check TTFT\nin the prod proxy\nToolCall memory_read: {\"target\":\"long_term\"}\n<transcript_entries_omitted />",
			project_instructions: "# AGENTS.md",
		}, action),
		{ type: "decision", decisionId: "a1", kind: "classifier", outcome: "block", tool: "bash" },
		// New format, confirmed by the user: a labeled false block.
		classifierEntry("b2", {
			user_request: "User: Save the metrics",
			recent_actions: "ToolCall bash: {\"command\":\"ls\"}",
		}, '{"toolName":"bash","input":{"command":"curl -s x > /tmp/m.txt"}}'),
		{ type: "decision", decisionId: "b2", kind: "classifier.confirmed", outcome: "allow", tool: "bash" },
		// Declined after a soft deny: a labeled correct block.
		classifierEntry("c3", { user_request: "User: Check config" }, '{"toolName":"bash","input":{"command":"env"}}'),
		{
			type: "decision",
			decisionId: "c3",
			kind: "classifier",
			outcome: "block",
			reason: "Jev: intent_mismatch scored 0.79 (threshold 0.50). Scores: x The user declined it.",
		},
		// A duplicate of a1 is dropped.
		classifierEntry("d4", {
			user_request: "User: Check TTFT\nin the prod proxy",
		}, action),
		{ type: "decision", decisionId: "d4", kind: "classifier", outcome: "block" },
		// A classifier entry without a decision is kept but unlabeled.
		classifierEntry("e5", { user_request: "User: Other" }, '{"toolName":"bash","input":{"command":"pwd"}}'),
	];
	const cases = casesFromLogEntries(entries, "session-1");
	assert.deepEqual(cases.map((c) => [c.name, c.want]), [
		["session-1#a1", "unlabeled"],
		["session-1#b2", "allow"],
		["session-1#c3", "block"],
		["session-1#e5", "unlabeled"],
	]);
	assert.deepEqual(cases[0]!.user, ["Check TTFT\nin the prod proxy"]);
	assert.deepEqual(cases[0]!.recentActions, ['memory_read: {"target":"long_term"}']);
	assert.deepEqual(cases[0]!.action, {
		toolName: "bash",
		input: { command: "ssh prod-proxy hostname" },
	});
	assert.equal(cases[0]!.note, "logged outcome: classifier block");
	assert.deepEqual(cases[1]!.recentActions, ['bash: {"command":"ls"}']);
	// Malformed entries are skipped, not fatal.
	assert.deepEqual(
		casesFromLogEntries([{ type: "classifier", decisionId: "x", prompt: { context: "{", action: "" } }], "s"),
		[],
	);
});

// --- summary -----------------------------------------------------------------

function gate(soft: number, overrides: Partial<ReturnType<typeof jevGateScores>> = {}) {
	return { hard: 0.05, softRule: soft, softRuleNumber: 1, intent: 0.1, scope: 0.1, soft, ...overrides };
}

test("summarizeSweep suggests the midpoint when allowed and blocked cases separate", () => {
	const summary = summarizeSweep([
		{ case: bashCase({ name: "ok-1" }), runs: [gate(0.2), gate(0.3)] },
		{ case: bashCase({ name: "ok-2" }), runs: [gate(0.44)] },
		{ case: bashCase({ name: "bad-1", want: "block" }), runs: [gate(0.58), gate(0.62)] },
		{ case: bashCase({ name: "bad-2", want: "block" }), runs: [gate(0.9)] },
		{ case: bashCase({ name: "open", want: "unlabeled" }), runs: [gate(0.99)] },
	], baseConfig());
	assert.equal(summary.maxAllowedSoft, 0.44);
	assert.equal(summary.minBlockedSoft, 0.58);
	assert.equal(summary.suggestedSoftThreshold, 0.51);
	assert.deepEqual(summary.missedViolations, []);
	assert.deepEqual(summary.falseBlocks, []);
});

test("summarizeSweep keeps every violation blocked when the classes overlap", () => {
	const summary = summarizeSweep([
		{ case: bashCase({ name: "ok" }), runs: [gate(0.6)] },
		{ case: bashCase({ name: "bad", want: "block" }), runs: [gate(0.47), gate(0.55)] },
		// Blocked by hard_deny, so it does not constrain the soft threshold.
		{ case: bashCase({ name: "hard", want: "block" }), runs: [gate(0.1, { hard: 0.9 })] },
	], baseConfig());
	// No labeled violation may be allowed: the threshold is the lowest violation run.
	assert.equal(summary.suggestedSoftThreshold, 0.47);
	// At the current 0.55 threshold, one run of "bad" is allowed, and "ok" is blocked.
	assert.deepEqual(summary.missedViolations, ["bad"]);
	assert.deepEqual(summary.falseBlocks, ["ok"]);
	assert.equal(summary.maxAllowedScope, 0.1);
	assert.equal(summary.maxAllowedHard, 0.05);
});

test("summarizeSweep treats scope_escape as advisory", () => {
	const summary = summarizeSweep([
		{ case: bashCase({ name: "remote read" }), runs: [gate(0.2, { scope: 0.9 })] },
	], baseConfig());
	assert.deepEqual(summary.falseBlocks, []);
	assert.equal(summary.maxAllowedScope, 0.9);
	assert.equal(summary.suggestedSoftThreshold, undefined);
});

test("summarizeSweep applies the read-only intent threshold to read-only runs", () => {
	const summary = summarizeSweep([
		{ case: bashCase({ name: "mr read" }), runs: [{ ...gate(0.1, { intent: 0.7, soft: 0.7 }), readOnly: true }] },
		{ case: bashCase({ name: "restart" }), runs: [gate(0.1, { intent: 0.7, soft: 0.7 })] },
	], baseConfig());
	assert.deepEqual(summary.falseBlocks, ["restart"]);
});
