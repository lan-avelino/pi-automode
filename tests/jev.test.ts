import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
	buildJevQuestions,
	buildJevState,
	clearJevCache,
	CLASSIFIER_POLICY_CLAUSES,
	CLASSIFIER_SYSTEM_PROMPT,
	credentialKey,
	defaultJevClassifyAction,
	DEFAULT_JEV_API_KEY_ENV,
	isOpenRouterBaseUrl,
	jevCredentialDiagnostics,
	jevDecision,
	jevStatusText,
	missingJevAnswers,
	openRouterDecisionsUrl,
	parseJevResponse,
	probeJevClassifier,
	redactSecrets,
	resolveJevKey,
	statusText,
} from "../extensions/auto-mode.ts";
import { createPiAutomode } from "../extensions/auto-mode.ts";
import type { EffectiveConfig } from "../extensions/auto-mode.ts";
import {
	baseConfig,
	baseState,
	createFakeCtx,
	createFakePi,
} from "./test-helpers.ts";

const HERE = dirname(fileURLToPath(import.meta.url));

// --- endpoint mapping ------------------------------------------------------

test("openRouterDecisionsUrl maps a chat base URL to the decisions endpoint", () => {
	assert.equal(
		openRouterDecisionsUrl("https://openrouter.ai/api/v1"),
		"https://openrouter.ai/api/alpha/decisions",
	);
	assert.equal(
		openRouterDecisionsUrl("https://openrouter.ai/api/v1/"),
		"https://openrouter.ai/api/alpha/decisions",
	);
});

test("openRouterDecisionsUrl passes through an explicit decisions URL", () => {
	assert.equal(
		openRouterDecisionsUrl("https://openrouter.ai/api/alpha/decisions"),
		"https://openrouter.ai/api/alpha/decisions",
	);
	assert.equal(
		openRouterDecisionsUrl("https://openrouter.ai/api/alpha/decisions/"),
		"https://openrouter.ai/api/alpha/decisions",
	);
});

test("openRouterDecisionsUrl appends /decisions to an arbitrary base", () => {
	assert.equal(
		openRouterDecisionsUrl("https://classifier.test/v1"),
		"https://classifier.test/v1/decisions",
	);
});

// --- response parsing ------------------------------------------------------

test("parseJevResponse reads in-range answers and rejects out-of-range values", () => {
	const parsed = parseJevResponse(
		200,
		JSON.stringify({
			model: "typesafe/jev-1.13",
			answers: {
				hard_deny: { type: "noul", noul: 1.5 },
				soft_deny_uncovered: { type: "noul", noul: -0.2 },
				intent_mismatch: { type: "noul", noul: 0.4 },
			},
		}),
	);
	assert.equal(parsed.ok, true);
	if (!parsed.ok) return;
	assert.equal(parsed.model, "typesafe/jev-1.13");
	// Out-of-range probabilities are a contract violation, so they are dropped
	// rather than clamped into a usable score.
	assert.deepEqual(parsed.scores, { intent_mismatch: 0.4 });

	// A response whose every score is out of range has no usable answer.
	const allBad = parseJevResponse(
		200,
		JSON.stringify({
			answers: { hard_deny: { type: "noul", noul: 1.5 } },
		}),
	);
	assert.equal(allBad.ok, false);
});

test("parseJevResponse surfaces HTTP errors with the server message", () => {
	const parsed = parseJevResponse(
		401,
		JSON.stringify({ message: "invalid api key" }),
	);
	assert.equal(parsed.ok, false);
	if (parsed.ok) return;
	assert.match(parsed.error, /HTTP 401: invalid api key/);
});

test("parseJevResponse fails closed on unreadable, malformed, or empty bodies", () => {
	for (
		const [status, body] of [
			[200, "not json"],
			[200, JSON.stringify({ model: "jev" })],
			[200, JSON.stringify({ answers: {} })],
			[200, JSON.stringify({ answers: { hard_deny: { type: "noul" } } })],
			[200, JSON.stringify({ answers: [{ type: "noul", noul: 0.9 }] })],
			// A numeric score of the wrong question type is not a usable answer.
			[
				200,
				JSON.stringify({
					answers: { hard_deny: { type: "other", noul: 0.9 } },
				}),
			],
		] as Array<[number, string]>
	) {
		const parsed = parseJevResponse(status, body);
		assert.equal(parsed.ok, false, body);
	}
});

test("missingJevAnswers treats a non-number answer as missing", () => {
	const questions = baseQuestions();
	// A null or string answer must count as missing rather than defaulting to zero
	// danger through the `?? 0` fallback in jevDecision.
	const scores = {
		hard_deny: null,
		soft_deny_uncovered: "0.9",
		intent_mismatch: 0,
		scope_escape: 0,
	} as unknown as Record<string, number>;
	assert.deepEqual(missingJevAnswers(scores, questions).sort(), [
		"hard_deny",
		"soft_deny_uncovered",
	]);
});

test("missingJevAnswers reports every unanswered question", () => {
	const questions = buildJevQuestions(baseConfig());
	assert.deepEqual(missingJevAnswers({}, questions).sort(), [
		"hard_deny",
		"intent_mismatch",
		"scope_escape",
		"soft_deny_uncovered",
	]);
	assert.deepEqual(
		missingJevAnswers(
			{
				hard_deny: 0,
				soft_deny_uncovered: 0,
				intent_mismatch: 0,
				scope_escape: 0,
			},
			questions,
		),
		[],
	);
	// An unrecognized answer id must not stand in for a real question.
	assert.deepEqual(
		missingJevAnswers({ bogus_question: 0.99 }, questions).sort(),
		[
			"hard_deny",
			"intent_mismatch",
			"scope_escape",
			"soft_deny_uncovered",
		],
	);
});

// --- decision mapping ------------------------------------------------------

/** The default question set; required scores are derived from it. */
const baseQuestions = () => buildJevQuestions(baseConfig());

test("jevDecision blocks at or above the hard threshold", () => {
	const config = baseConfig();
	assert.deepEqual(
		jevDecision(
			{
				hard_deny: 0.5,
				soft_deny_uncovered: 0,
				intent_mismatch: 0,
				scope_escape: 0,
			},
			config,
			baseQuestions(),
		),
		{
			decision: "block",
			tier: "hard_deny",
			reason:
				"Jev: hard=0.50 soft_uncov=0.00 intent=0.00 scope=0.00 soft_gate=0.00",
		},
	);
});

test("jevDecision blocks the soft band from the authorization-aware questions", () => {
	const config = baseConfig();
	// Use the configured threshold so this stays true if the default moves.
	const at = config.jevSoftDenyThreshold;
	for (
		const scores of [
			{
				hard_deny: 0.49,
				soft_deny_uncovered: at,
				intent_mismatch: 0,
				scope_escape: 0,
			},
			{
				hard_deny: 0.0,
				soft_deny_uncovered: 0,
				intent_mismatch: at,
				scope_escape: 0,
			},
		]
	) {
		const decision = jevDecision(scores, config, baseQuestions());
		assert.equal(decision.decision, "block", JSON.stringify(scores));
		assert.equal(decision.tier, "soft_deny");
	}
});

test("the default soft-deny threshold matches the measured benign ceiling", () => {
	// Measured against the live endpoint: a benign action with a real classifier
	// transcript peaks near 0.30 on the soft axes, while actions that are
	// soft-deny rules score 0.81-0.93. The design-record default of 0.35 left
	// only ~0.05 of margin, so the default moved to the middle of the gap.
	assert.equal(baseConfig().jevSoftDenyThreshold, 0.4);
	// The benign ceiling measured at 0.31 must stay below the threshold.
	const benign = jevDecision(
		{
			hard_deny: 0.13,
			soft_deny_uncovered: 0.3,
			intent_mismatch: 0.31,
			scope_escape: 0.21,
		},
		baseConfig(),
		baseQuestions(),
	);
	assert.equal(benign.decision, "allow", benign.reason);
	// The first genuine soft-deny case measured at 0.44 must stay above it.
	const underBounded = jevDecision(
		{
			hard_deny: 0.05,
			soft_deny_uncovered: 0.44,
			intent_mismatch: 0.27,
			scope_escape: 0.07,
		},
		baseConfig(),
		baseQuestions(),
	);
	assert.equal(underBounded.decision, "block", underBounded.reason);
	assert.equal(underBounded.tier, "soft_deny");
});

test("jevDecision gates scope_escape at its own higher threshold", () => {
	// scope_escape is a supporting, non-parity signal: it must not decide the
	// verdict on its own at the soft threshold.
	const config = baseConfig();
	const scores = {
		hard_deny: 0.0,
		soft_deny_uncovered: 0,
		intent_mismatch: 0,
		scope_escape: 0.36,
	};
	const decision = jevDecision(scores, config, baseQuestions());
	assert.equal(decision.decision, "allow", decision.reason);
	assert.equal(decision.tier, "none");
});

test("jevDecision blocks a scope_escape at or above its own threshold", () => {
	const config = baseConfig();
	const decision = jevDecision(
		{
			hard_deny: 0.0,
			soft_deny_uncovered: 0,
			intent_mismatch: 0,
			scope_escape: 0.5,
		},
		config,
		baseQuestions(),
	);
	assert.equal(decision.decision, "block", decision.reason);
	assert.equal(decision.tier, "soft_deny");
});

test("a raised scope_escape threshold cannot suppress the other soft questions", () => {
	const config = baseConfig({ jevScopeEscapeThreshold: 1 });
	const decision = jevDecision(
		{
			hard_deny: 0.0,
			soft_deny_uncovered: config.jevSoftDenyThreshold,
			intent_mismatch: 0,
			scope_escape: 0,
		},
		config,
		baseQuestions(),
	);
	assert.equal(decision.decision, "block", decision.reason);
	assert.equal(decision.tier, "soft_deny");
});

test("an at-or-above scope_escape cannot downgrade a hard deny", () => {
	const config = baseConfig();
	// scope_escape is at or above its own threshold and hard_deny is at its own,
	// so the tier must be hard_deny rather than soft_deny.
	const decision = jevDecision(
		{
			hard_deny: config.jevHardDenyThreshold,
			soft_deny_uncovered: 0,
			intent_mismatch: 0,
			scope_escape: config.jevScopeEscapeThreshold,
		},
		config,
		baseQuestions(),
	);
	assert.equal(decision.decision, "block");
	assert.equal(decision.tier, "hard_deny");
});

test("a raised scope_escape threshold cannot suppress a hard deny", () => {
	const config = baseConfig({
		jevScopeEscapeThreshold: 1,
		jevSoftDenyThreshold: 1,
	});
	const decision = jevDecision(
		{
			hard_deny: 0.9,
			soft_deny_uncovered: 0,
			intent_mismatch: 0,
			scope_escape: 0,
		},
		config,
		baseQuestions(),
	);
	assert.equal(decision.decision, "block", decision.reason);
	assert.equal(decision.tier, "hard_deny");
});

test("jevDecision allows below both thresholds", () => {
	const decision = jevDecision(
		{
			hard_deny: 0.49,
			soft_deny_uncovered: 0.34,
			intent_mismatch: 0.1,
			scope_escape: 0.1,
		},
		baseConfig(),
		baseQuestions(),
	);
	assert.equal(decision.decision, "allow");
	assert.equal(decision.tier, "none");
});

test("jevDecision fails closed when a required score is missing", () => {
	// Guards a future caller that skips the explicit missing-answer check.
	const decision = jevDecision(
		{ hard_deny: 0.0, intent_mismatch: 0.0 },
		baseConfig(),
		baseQuestions(),
	);
	assert.equal(decision.decision, "block");
	assert.equal(decision.tier, "none");
	assert.match(decision.reason, /incomplete scores/);
});

test("jevDecision honors configured thresholds", () => {
	const config = baseConfig({
		jevHardDenyThreshold: 0.9,
		jevSoftDenyThreshold: 0.8,
	});
	assert.equal(
		jevDecision(
			{
				hard_deny: 0.7,
				soft_deny_uncovered: 0.1,
				intent_mismatch: 0.5,
				scope_escape: 0.1,
			},
			config,
			baseQuestions(),
		).decision,
		"allow",
	);
	assert.equal(
		jevDecision(
			{
				hard_deny: 0.9,
				soft_deny_uncovered: 0,
				intent_mismatch: 0,
				scope_escape: 0,
			},
			config,
			baseQuestions(),
		).tier,
		"hard_deny",
	);
});

test("jevDecision prefers the hard tier when both bands are cleared", () => {
	const decision = jevDecision(
		{
			hard_deny: 0.9,
			soft_deny_uncovered: 0,
			intent_mismatch: 0.9,
			scope_escape: 0,
		},
		baseConfig(),
		baseQuestions(),
	);
	assert.equal(decision.decision, "block");
	assert.equal(decision.tier, "hard_deny");
});

test("buildJevQuestions phrases every question danger-side up with policy text", () => {
	const questions = buildJevQuestions(
		baseConfig({ environment: ["Trusted repo: acme"], hardDeny: ["no prod"] }),
	);
	for (const question of Object.values(questions)) {
		assert.equal(question.type, "noul");
	}
	assert.match(questions.hard_deny!.instructions, /no prod/);
	assert.match(questions.scope_escape!.instructions, /Trusted repo: acme/);
});

test("buildJevQuestions redacts secrets and sends the full rule text", () => {
	const longRule = "x".repeat(2000);
	const questions = buildJevQuestions(
		baseConfig({
			hardDeny: ["API key: sk-or-v1-abcdefghijklmnop", longRule],
		}),
	);
	const hard = questions.hard_deny!.instructions;
	assert.doesNotMatch(hard, /sk-or-v1-abcdefghijklmnop/);
	// Rule lists are user-owned policy and reach Jev in full, like the LLM path.
	assert.ok(hard.includes(longRule));
	assert.doesNotMatch(hard, /TRUNCATED/);
});

test("the Jev questions encode every shared classifier policy clause", () => {
	// Distinctive rule text so a clause cannot be satisfied by rule prose.
	const config = baseConfig({
		environment: ["ENV_MARKER"],
		allow: ["ALLOW_MARKER"],
		softDeny: ["SOFT_MARKER"],
		hardDeny: ["HARD_MARKER"],
	});
	const questions = buildJevQuestions(config);
	const expected: Record<string, Array<keyof typeof CLASSIFIER_POLICY_CLAUSES>> = {
		hard_deny: [
			"hardDenyNoOverride",
			"allowNeverOverridesHardDeny",
			"untrustedData",
			"securityNotQuality",
			"allowByDefault",
		],
		soft_deny_uncovered: [
			"softDenyAuthorization",
			"fileAuthorizationBounds",
			"otherSoftDenyAuthorization",
			"authorizationRevocation",
			"allowNeverOverridesHardDeny",
			"untrustedData",
			"securityNotQuality",
			"allowByDefault",
		],
		intent_mismatch: [
			"generalRequestsNotIntent",
			"untrustedData",
			"securityNotQuality",
			"allowByDefault",
		],
		scope_escape: ["untrustedData", "securityNotQuality", "allowByDefault"],
	};
	// Each clause must reach the question that carries its semantics, not just
	// any question, so a clause moved to the wrong question fails.
	for (const [id, clauseIds] of Object.entries(expected)) {
		const instructions = questions[id]!.instructions;
		for (const clauseId of clauseIds) {
			assert.ok(
				instructions.includes(CLASSIFIER_POLICY_CLAUSES[clauseId]),
				`${id} is missing policy clause ${clauseId}`,
			);
		}
	}
	// Every clause must reach at least one question.
	const uncovered = new Set(Object.keys(CLASSIFIER_POLICY_CLAUSES));
	for (const clauseIds of Object.values(expected)) {
		for (const clauseId of clauseIds) uncovered.delete(clauseId);
	}
	assert.deepEqual([...uncovered], []);

	// The system prompt is built from the same clauses.
	for (const [id, clause] of Object.entries(CLASSIFIER_POLICY_CLAUSES)) {
		assert.ok(
			CLASSIFIER_SYSTEM_PROMPT.includes(clause),
			`system prompt is missing policy clause ${id}`,
		);
	}
});

// --- state redaction -------------------------------------------------------

test("buildJevState redacts every field and does not re-bound the transcript", () => {
	clearJevCache();
	const longIntent = "deploy the release ".repeat(500);
	const state = buildJevState(
		"bash {\"command\":\"export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\"}",
		"deploy with sk-or-v1-abcdefghijklmnop",
		"",
	);
	assert.doesNotMatch(state.action!, /AKIAIOSFODNN7EXAMPLE/);
	assert.match(state.action!, /REDACTED/);
	assert.doesNotMatch(state.user_request!, /sk-or-v1-abcdefghijklmnop/);
	assert.equal(state.project_instructions, "(none)");
	// The transcript is token-bounded upstream, so it is not clipped again.
	assert.equal(buildJevState("bash", longIntent, "").user_request, longIntent);
	// The working directory is not part of the state payload.
	assert.deepEqual(Object.keys(state).sort(), [
		"action",
		"project_instructions",
		"user_request",
	]);
});

test("redactSecrets removes private key blocks and bearer tokens", () => {
	const input =
		"-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\nAuthorization: Bearer abcdefghijklmnop";
	const output = redactSecrets(input);
	assert.doesNotMatch(output, /MIIE/);
	assert.doesNotMatch(output, /abcdefghijklmnop/);
});

// --- credential helpers ----------------------------------------------------

test("credentialKey accepts api keys and oauth access tokens, declines commands", () => {
	assert.equal(credentialKey({ type: "api_key", key: "plain-key" }), "plain-key");
	assert.equal(credentialKey({ type: "oauth", access: "oauth-token" }), "oauth-token");
	assert.equal(credentialKey({ type: "api_key", key: "!op read foo" }), undefined);
	assert.equal(credentialKey({ type: "api_key" }), undefined);
	assert.equal(credentialKey(undefined), undefined);
});

test("resolveJevKey prefers the pi registry, then env, then stored auth", async () => {
	clearJevCache();
	const config = baseConfig({ jevApiKeyEnv: "PI_AUTOMODE_TEST_JEV_KEY" });

	const viaRegistry = await resolveJevKey(
		createFakeCtx([], {
			modelRegistry: { getApiKeyForProvider: async () => "registry-key" },
		}) as never,
		config,
		{ env: { PI_AUTOMODE_TEST_JEV_KEY: "env-key" } },
	);
	assert.deepEqual(viaRegistry, { key: "registry-key", source: "pi-auth" });

	const viaEnv = await resolveJevKey(
		createFakeCtx([], {
			modelRegistry: { getApiKeyForProvider: async () => undefined },
		}) as never,
		config,
		{ env: { PI_AUTOMODE_TEST_JEV_KEY: "env-key" } },
	);
	assert.deepEqual(viaEnv, { key: "env-key", source: "env" });

	const viaStored = await resolveJevKey(
		createFakeCtx([], {
			modelRegistry: { getApiKeyForProvider: async () => undefined },
		}) as never,
		config,
		{
			env: {},
			readStoredCredential: () => ({ type: "api_key", key: "stored-key" }),
		},
	);
	assert.deepEqual(viaStored, { key: "stored-key", source: "pi-auth" });

	const none = await resolveJevKey(
		createFakeCtx([], {
			modelRegistry: { getApiKeyForProvider: async () => undefined },
		}) as never,
		config,
		{ env: {}, readStoredCredential: () => undefined },
	);
	assert.deepEqual(none, { source: "none" });
});

test("isOpenRouterBaseUrl only matches OpenRouter endpoints", () => {
	assert.equal(isOpenRouterBaseUrl("https://openrouter.ai/api/v1"), true);
	assert.equal(
		isOpenRouterBaseUrl("https://openrouter.ai/api/alpha/decisions"),
		true,
	);
	assert.equal(isOpenRouterBaseUrl("https://classifier.test/v1"), false);
	assert.equal(isOpenRouterBaseUrl("https://openrouter.ai.evil.test/v1"), false);
	assert.equal(isOpenRouterBaseUrl("not a url"), false);
	// A non-default port is a different endpoint, even on the OpenRouter host.
	assert.equal(isOpenRouterBaseUrl("https://openrouter.ai:8443/api/v1"), false);
	assert.equal(isOpenRouterBaseUrl("https://openrouter.ai:443/api/v1"), true);
	// Cleartext http is not the OpenRouter service, so the key stays withheld.
	assert.equal(isOpenRouterBaseUrl("http://openrouter.ai/api/v1"), false);
});

test("resolveJevKey never sends OpenRouter credentials to a custom base URL", async () => {
	const customBase = baseConfig({
		jevApiKeyEnv: "PI_AUTOMODE_TEST_JEV_KEY",
		jevBaseUrl: "https://classifier.test/api/v1",
	});
	const registryKey = createFakeCtx([], {
		modelRegistry: { getApiKeyForProvider: async () => "registry-key" },
	}) as never;

	// Registry and stored OpenRouter credentials are withheld for a custom host.
	assert.deepEqual(
		await resolveJevKey(registryKey, customBase, {
			env: {},
			readStoredCredential: () => ({ type: "api_key", key: "stored-key" }),
		}),
		{ source: "none" },
	);
	// The explicit env var is still honored for the custom endpoint.
	assert.deepEqual(
		await resolveJevKey(registryKey, customBase, {
			env: { PI_AUTOMODE_TEST_JEV_KEY: "env-key" },
			readStoredCredential: () => ({ type: "api_key", key: "stored-key" }),
		}),
		{ key: "env-key", source: "env" },
	);
});

test("resolveJevKey withholds the default OpenRouter env var from a custom base URL", async () => {
	const customBase = baseConfig({
		jevBaseUrl: "https://classifier.test/api/v1",
		// jevApiKeyEnv stays at the OpenRouter default.
	});
	const ctx = createFakeCtx([], {
		modelRegistry: { getApiKeyForProvider: async () => undefined },
	}) as never;

	assert.deepEqual(
		await resolveJevKey(ctx, customBase, {
			env: { [DEFAULT_JEV_API_KEY_ENV]: "openrouter-key" },
			readStoredCredential: () => ({ type: "api_key", key: "stored-key" }),
		}),
		{ source: "none" },
	);
});

test("resolveJevKey uses the default OpenRouter env var on the OpenRouter endpoint", async () => {
	const ctx = createFakeCtx([], {
		modelRegistry: { getApiKeyForProvider: async () => undefined },
	}) as never;
	assert.deepEqual(
		await resolveJevKey(ctx, baseConfig(), {
			env: { [DEFAULT_JEV_API_KEY_ENV]: "openrouter-key" },
			readStoredCredential: () => undefined,
		}),
		{ key: "openrouter-key", source: "env" },
	);
});

test("resolveJevKey withholds a case-variant default env name from a custom host", async () => {
	const customBase = baseConfig({
		jevBaseUrl: "https://classifier.test/api/v1",
		// Windows env names are case-insensitive, so this is the OpenRouter var.
		jevApiKeyEnv: "openrouter_api_key",
	});
	const ctx = createFakeCtx([], {
		modelRegistry: { getApiKeyForProvider: async () => undefined },
	}) as never;

	assert.deepEqual(
		await resolveJevKey(ctx, customBase, {
			env: { OPENROUTER_API_KEY: "openrouter-key" },
			readStoredCredential: () => undefined,
		}),
		{ source: "none" },
	);
	assert.equal(jevCredentialDiagnostics(customBase).length, 1);
});

test("jevCredentialDiagnostics flags a custom base URL with the default key env", () => {
	const mismatch = baseConfig({
		jevBaseUrl: "https://classifier.test/api/v1",
	});
	const diagnostics = jevCredentialDiagnostics(mismatch);
	assert.equal(diagnostics.length, 1);
	assert.match(diagnostics[0]!, /jevApiKeyEnv/);
	assert.deepEqual(jevCredentialDiagnostics(baseConfig()), []);

	assert.deepEqual(
		jevCredentialDiagnostics(
			baseConfig({
				jevBaseUrl: "https://classifier.test/api/v1",
				jevApiKeyEnv: "CLASSIFIER_API_KEY",
			}),
		),
		[],
	);
});

// --- classify action -------------------------------------------------------

function jevTestConfig(overrides: Partial<EffectiveConfig> = {}): EffectiveConfig {
	return baseConfig({
		jevApiKeyEnv: "PI_AUTOMODE_TEST_JEV_KEY",
		...overrides,
	});
}

/** A complete answers map; every requested question must be answered. */
function jevAnswers(
	overrides: Partial<Record<string, number>> = {},
): Record<string, { type: "noul"; noul: number }> {
	const score = (key: string) => overrides[key] ?? 0.01;
	return {
		hard_deny: { type: "noul", noul: score("hard_deny") },
		soft_deny_uncovered: { type: "noul", noul: score("soft_deny_uncovered") },
		intent_mismatch: { type: "noul", noul: score("intent_mismatch") },
		scope_escape: { type: "noul", noul: score("scope_escape") },
	};
}

const JEV_KEY_DEPS = {
	env: { PI_AUTOMODE_TEST_JEV_KEY: "test-key" },
	readStoredCredential: () => undefined,
} as const;

test("defaultJevClassifyAction fails closed when no key is available", async () => {
	clearJevCache();
	const result = await defaultJevClassifyAction(
		createFakeCtx([], {
			modelRegistry: { getApiKeyForProvider: async () => undefined },
		}) as never,
		jevTestConfig(),
		'{"toolName":"bash"}',
		"",
		{ env: {}, readStoredCredential: () => undefined },
	);
	assert.equal(result.decision, "block");
	assert.equal(result.tier, "none");
	assert.match(result.reason, /key missing/);
	// A missing key has no attempt to log, matching the LLM path.
	assert.equal(result.io, undefined);
	assert.deepEqual(result.reasoning, {
		mode: "backend",
		backend: "jev",
		model: "~typesafe/jev-latest",
	});
});

test("defaultJevClassifyAction posts to the decisions endpoint and caches verdicts", async () => {
	clearJevCache();
	const originalFetch = globalThis.fetch;
	const calls: Array<{ url: string; init: RequestInit }> = [];
	globalThis.fetch = (async (url: string | URL, init?: RequestInit) => {
		calls.push({ url: String(url), init: init ?? {} });
		return new Response(
			JSON.stringify({
				model: "typesafe/jev-1.13",
				answers: jevAnswers({ hard_deny: 0.9 }),
			}),
			{ status: 200 },
		);
	}) as typeof fetch;

	try {
		const ctx = createFakeCtx([], {
			modelRegistry: { getApiKeyForProvider: async () => undefined },
		});
		const config = jevTestConfig({
			jevBaseUrl: "https://classifier.test/api/v1",
		});
		const action = '{"toolName":"bash","input":{"command":"deploy"}}';

		const first = await defaultJevClassifyAction(
			ctx as never,
			config,
			action,
			"",
			JEV_KEY_DEPS,
		);
		assert.equal(first.decision, "block");
		assert.equal(first.tier, "hard_deny");
		assert.equal(calls.length, 1);
		assert.equal(calls[0]!.url, "https://classifier.test/api/alpha/decisions");
		// Redirects are rejected so the key is never forwarded to another host.
		assert.equal(calls[0]!.init.redirect, "error");
		const headers = calls[0]!.init.headers as Record<string, string>;
		assert.equal(headers.Authorization, "Bearer test-key");
		const payload = JSON.parse(String(calls[0]!.init.body)) as {
			model: string;
			state: { action: string };
			questions: Record<string, { type: string }>;
		};
		assert.equal(payload.model, "~typesafe/jev-latest");
		assert.match(payload.state.action, /deploy/);
		assert.equal(payload.questions.hard_deny!.type, "noul");
		// A custom endpoint is not an OpenRouter provider.
		assert.equal(first.io?.model, "typesafe/jev-1.13");

		const second = await defaultJevClassifyAction(
			ctx as never,
			config,
			action,
			"",
			JEV_KEY_DEPS,
		);
		assert.equal(calls.length, 1);
		assert.match(second.reason, /\(cached\)$/);
		// A cache hit is still logged, but as a cached verdict with no request.
		assert.equal(second.io?.cached, true);
		assert.deepEqual(second.io?.attempts, []);
	} finally {
		globalThis.fetch = originalFetch;
		clearJevCache();
	}
});

test("a scope threshold change produces a new cache key", async () => {
	clearJevCache();
	const originalFetch = globalThis.fetch;
	let calls = 0;
	globalThis.fetch = (async () => {
		calls += 1;
		return new Response(
			JSON.stringify({
				model: "typesafe/jev-1.13",
				answers: jevAnswers({ hard_deny: 0.01 }),
			}),
			{ status: 200 },
		);
	}) as typeof fetch;

	try {
		const ctx = createFakeCtx([], {
			modelRegistry: { getApiKeyForProvider: async () => undefined },
		});
		const base = jevTestConfig({
			jevBaseUrl: "https://classifier.test/api/v1",
		});
		const action = '{"toolName":"bash","input":{"command":"ls"}}';

		await defaultJevClassifyAction(ctx as never, base, action, "", JEV_KEY_DEPS);
		assert.equal(calls, 1);
		// Same input and thresholds: served from cache.
		await defaultJevClassifyAction(ctx as never, base, action, "", JEV_KEY_DEPS);
		assert.equal(calls, 1);
		// A different scope threshold must not reuse the cached verdict, because
		// the verdict depends on it.
		await defaultJevClassifyAction(
			ctx as never,
			{ ...base, jevScopeEscapeThreshold: 0.9 },
			action,
			"",
			JEV_KEY_DEPS,
		);
		assert.equal(calls, 2);
	} finally {
		globalThis.fetch = originalFetch;
		clearJevCache();
	}
});

test("defaultJevClassifyAction sends the full action without truncation", async () => {
	clearJevCache();
	const originalFetch = globalThis.fetch;
	let sent: { state: { action: string } } | undefined;
	globalThis.fetch = (async (_url: string | URL, init?: RequestInit) => {
		sent = JSON.parse(String(init?.body));
		return new Response(
			JSON.stringify({ model: "typesafe/jev-1.13", answers: jevAnswers() }),
			{ status: 200 },
		);
	}) as typeof fetch;
	try {
		const action = JSON.stringify({
			toolName: "write",
			input: { path: "/tmp/x", content: "y".repeat(5000) },
		});
		const result = await defaultJevClassifyAction(
			createFakeCtx([], {
				modelRegistry: { getApiKeyForProvider: async () => undefined },
			}) as never,
			jevTestConfig(),
			action,
			"",
			JEV_KEY_DEPS,
		);
		assert.equal(result.decision, "allow");
		assert.equal(sent?.state.action, action);
		// The default base URL is OpenRouter, so the log labels it as such.
		assert.equal(result.io?.model, "openrouter/typesafe/jev-1.13");
		// Jev reports no token usage, so no provider response is fabricated:
		// one attempt with the parsed decision and no response.
		assert.equal(result.io?.attempts.length, 1);
		assert.equal(result.io?.attempts[0]?.stage, "detailed");
		assert.deepEqual(result.io?.attempts[0]?.parsed, {
			decision: "allow",
			tier: "none",
			reason:
				"Jev: permitted (hard=0.01 soft_uncov=0.01 intent=0.01 scope=0.01 soft_gate=0.01)",
		});
		assert.equal(result.io?.attempts[0]?.response, undefined);
	} finally {
		globalThis.fetch = originalFetch;
		clearJevCache();
	}
});

test("defaultJevClassifyAction fails closed on transport and parse errors", async () => {
	clearJevCache();
	const originalFetch = globalThis.fetch;
	try {
		const ctx = createFakeCtx([], {
			modelRegistry: { getApiKeyForProvider: async () => undefined },
		});

		globalThis.fetch = (async () => {
			throw new Error("connection refused");
		}) as typeof fetch;
		const transport = await defaultJevClassifyAction(
			ctx as never,
			jevTestConfig(),
			'{"toolName":"bash"}',
			"",
			JEV_KEY_DEPS,
		);
		assert.equal(transport.decision, "block");
		assert.match(transport.reason, /fails closed/);
		// Transport failures log one error attempt, like the LLM path.
		assert.equal(transport.io?.attempts.length, 1);
		assert.equal(transport.io?.attempts[0]?.stage, "detailed");
		assert.match(String(transport.io?.attempts[0]?.error), /connection refused/);
		assert.equal(transport.io?.attempts[0]?.parsed, undefined);
		assert.equal(transport.io?.attempts[0]?.response, undefined);

		globalThis.fetch = (async () =>
			new Response("not json", { status: 200 })) as typeof fetch;
		const malformed = await defaultJevClassifyAction(
			ctx as never,
			jevTestConfig(),
			'{"toolName":"edit"}',
			"",
			JEV_KEY_DEPS,
		);
		assert.equal(malformed.decision, "block");
		assert.match(malformed.reason, /unreadable response/);

		globalThis.fetch = (async () =>
			new Response(JSON.stringify({ message: "invalid api key" }), {
				status: 401,
			})) as typeof fetch;
		const rejected = await defaultJevClassifyAction(
			ctx as never,
			jevTestConfig(),
			'{"toolName":"write"}',
			"",
			JEV_KEY_DEPS,
		);
		assert.equal(rejected.decision, "block");
		assert.match(rejected.reason, /HTTP 401: invalid api key/);
	} finally {
		globalThis.fetch = originalFetch;
		clearJevCache();
	}
});

test("defaultJevClassifyAction allows a low-risk action", async () => {
	clearJevCache();
	const originalFetch = globalThis.fetch;
	globalThis.fetch = (async () =>
		new Response(
			JSON.stringify({
				model: "typesafe/jev-1.13",
				answers: jevAnswers({ hard_deny: 0.01, intent_mismatch: 0.02 }),
			}),
			{ status: 200 },
		)) as typeof fetch;
	try {
		const result = await defaultJevClassifyAction(
			createFakeCtx([], {
				modelRegistry: { getApiKeyForProvider: async () => undefined },
			}) as never,
			jevTestConfig(),
			'{"toolName":"bash","input":{"command":"npm test"}}',
			"",
			JEV_KEY_DEPS,
		);
		assert.equal(result.decision, "allow");
		assert.equal(result.tier, "none");
	} finally {
		globalThis.fetch = originalFetch;
		clearJevCache();
	}
});

test("defaultJevClassifyAction fails closed when answers omit a question", async () => {
	clearJevCache();
	const originalFetch = globalThis.fetch;
	try {
		const ctx = createFakeCtx([], {
			modelRegistry: { getApiKeyForProvider: async () => undefined },
		}) as never;
		for (
			const answers of [
				// Only an unrecognized id, carrying high danger: must not allow.
				{ bogus_question: { type: "noul", noul: 0.99 } },
				// Partial: three of the four requested questions.
				{
					hard_deny: { type: "noul", noul: 0.01 },
					soft_deny_uncovered: { type: "noul", noul: 0.01 },
					intent_mismatch: { type: "noul", noul: 0.01 },
				},
			]
		) {
			globalThis.fetch = (async () =>
				new Response(JSON.stringify({ answers }), {
					status: 200,
				})) as typeof fetch;
			const result = await defaultJevClassifyAction(
				ctx,
				jevTestConfig(),
				'{"toolName":"bash","input":{"command":"deploy"}}',
				"",
				JEV_KEY_DEPS,
			);
			assert.equal(result.decision, "block", JSON.stringify(answers));
			assert.match(result.reason, /missing answers/);
		}
	} finally {
		globalThis.fetch = originalFetch;
		clearJevCache();
	}
});

// --- backend selection and commands ---------------------------------------

async function hookResult(
	config: EffectiveConfig,
	options: {
		classifyAction?: () => Promise<unknown>;
		jevClassifyAction?: () => Promise<unknown>;
	},
): Promise<{
	llmCalls: number;
	jevCalls: number;
	result: unknown;
}> {
	const fake = createFakePi();
	let llmCalls = 0;
	let jevCalls = 0;
	createPiAutomode({
		loadConfig: () => config,
		classifyAction: async () => {
			llmCalls += 1;
			return (await options.classifyAction?.()) as never;
		},
		jevClassifyAction: async () => {
			jevCalls += 1;
			return (await options.jevClassifyAction?.()) as never;
		},
	})(fake.pi);
	const ctx = createFakeCtx(fake.entries);
	await fake.emit("session_start", { type: "session_start" }, ctx);
	const result = await fake.emit("tool_call", {
		toolName: "webfetch",
		input: { url: "https://example.com" },
	}, ctx);
	return { llmCalls, jevCalls, result };
}

test("tool_call routes to the Jev action when classifierBackend is jev", async () => {
	const { llmCalls, jevCalls, result } = await hookResult(
		baseConfig({ classifierBackend: "jev" }),
		{
			classifyAction: async () => ({
				decision: "allow",
				tier: "none",
				reason: "llm",
			}),
			jevClassifyAction: async () => ({
				decision: "allow",
				tier: "none",
				reason: "jev",
			}),
		},
	);
	assert.equal(result, undefined);
	assert.equal(jevCalls, 1);
	assert.equal(llmCalls, 0);
});

test("tool_call routes to the LLM action when classifierBackend is llm", async () => {
	const { llmCalls, jevCalls } = await hookResult(
		baseConfig({ classifierBackend: "llm" }),
		{
			classifyAction: async () => ({
				decision: "allow",
				tier: "none",
				reason: "llm",
			}),
			jevClassifyAction: async () => ({
				decision: "allow",
				tier: "none",
				reason: "jev",
			}),
		},
	);
	assert.equal(llmCalls, 1);
	assert.equal(jevCalls, 0);
});

test("deterministic hard-deny still blocks when the Jev backend would allow", async () => {
	const corpus = JSON.parse(
		readFileSync(join(HERE, "fixtures/jev-hard-deny-corpus.json"), "utf8"),
	) as { commands: string[] };
	assert.ok(corpus.commands.length > 0);

	for (const command of corpus.commands) {
		let jevCalls = 0;
		const fake = createFakePi();
		createPiAutomode({
			loadConfig: () => baseConfig({ classifierBackend: "jev" }),
			classifyAction: async () => ({
				decision: "allow",
				tier: "none",
				reason: "llm allow",
			}),
			jevClassifyAction: async () => {
				jevCalls += 1;
				return { decision: "allow", tier: "none", reason: "jev allow" };
			},
		})(fake.pi);
		const ctx = createFakeCtx(fake.entries);
		await fake.emit("session_start", { type: "session_start" }, ctx);
		const result = await fake.emit("tool_call", {
			toolName: "bash",
			input: { command },
		}, ctx) as { block?: boolean; reason?: string };

		assert.equal(result.block, true, command);
		assert.match(result.reason ?? "", /hard-denied/, command);
		assert.equal(jevCalls, 0, command);
	}
});

test("statusText reports the Jev backend instead of an LLM model", () => {
	const text = statusText(
		baseConfig({
			classifierBackend: "jev",
			jevModel: "~typesafe/jev-latest",
		}),
		baseState(),
	);
	assert.match(text, /^classifier: jev \(~typesafe\/jev-latest\)$/m);
	assert.match(text, /^classifier reasoning: not used by the Jev backend$/m);
});

test("/automode backend saves classifierBackend globally and reloads", async () => {
	const saved: Array<[string, string]> = [];
	const fake = createFakePi();
	createPiAutomode({
		loadConfig: () => baseConfig(),
		saveAutoModeSetting: (key, value) => saved.push([key, value]),
	})(fake.pi);
	const ctx = createFakeCtx(fake.entries);
	await fake.emit("session_start", { type: "session_start" }, ctx);

	await fake.commands.get("automode")?.handler("backend jev", ctx);
	assert.deepEqual(saved, [["classifierBackend", "jev"]]);
	assert.match(ctx.notifications.at(-1)?.message ?? "", /set to jev/);

	await fake.commands.get("automode")?.handler("backend nope", ctx);
	assert.equal(ctx.notifications.at(-1)?.type, "error");
	assert.match(ctx.notifications.at(-1)?.message ?? "", /Usage/);
});

test("/automode model writes jevModel when the Jev backend is active", async () => {
	const saved: Array<[string, string]> = [];
	const fake = createFakePi();
	createPiAutomode({
		loadConfig: () => baseConfig({ classifierBackend: "jev" }),
		saveAutoModeSetting: (key, value) => saved.push([key, value]),
	})(fake.pi);
	const ctx = createFakeCtx(fake.entries);
	await fake.emit("session_start", { type: "session_start" }, ctx);

	await fake.commands.get("automode")?.handler(
		"model ~typesafe/jev-1.13",
		ctx,
	);
	assert.deepEqual(saved, [["jevModel", "~typesafe/jev-1.13"]]);
	assert.match(
		ctx.notifications.at(-1)?.message ?? "",
		/Jev classifier saved globally/,
	);
});

// --- /automode jev --------------------------------------------------------

test("jevStatusText reports the endpoint, credential source, and warnings", () => {
	const text = jevStatusText(
		baseConfig({
			classifierBackend: "jev",
			jevBaseUrl: "https://classifier.test/api/v1",
		}),
		"none",
		["autoMode.jevBaseUrl targets a custom endpoint"],
	);
	assert.match(text, /^backend: jev$/m);
	assert.match(
		text,
		/^endpoint: https:\/\/classifier\.test\/api\/alpha\/decisions$/m,
	);
	assert.match(text, /^credential: none/m);
	assert.match(text, /^hard deny threshold: 0\.5$/m);
	assert.match(text, /^soft deny threshold: 0\.4$/m);
	assert.match(text, /^scope escape threshold: 0\.5$/m);
	assert.match(text, /warning: autoMode\.jevBaseUrl/);
	// A custom host with the default variable names the actual fix, not the
	// variable the gate withholds.
	assert.match(
		text,
		/^credential: none; the classifier fails closed \(set a custom key variable, not OPENROUTER_API_KEY\)$/m,
	);

	// The status reports the effective backend, not a hardcoded one.
	const llm = jevStatusText(baseConfig(), "none");
	assert.match(llm, /^backend: llm$/m);
});

test("/automode jev reports the backend status", async () => {
	const fake = createFakePi();
	createPiAutomode({
		loadConfig: () =>
			baseConfig({
				classifierBackend: "jev",
				jevApiKeyEnv: "PI_AUTOMODE_TEST_JEV_KEY",
			}),
	})(fake.pi);
	const ctx = createFakeCtx(fake.entries);
	await fake.emit("session_start", { type: "session_start" }, ctx);

	const previous = process.env.PI_AUTOMODE_TEST_JEV_KEY;
	process.env.PI_AUTOMODE_TEST_JEV_KEY = "test-key";
	try {
		await fake.commands.get("automode")?.handler("jev", ctx);
		const message = ctx.notifications.at(-1)?.message ?? "";
		assert.match(message, /backend: jev/);
		assert.match(message, /endpoint: https:\/\/openrouter\.ai\/api\/alpha\/decisions/);
		assert.match(message, /credential: environment variable PI_AUTOMODE_TEST_JEV_KEY/);
	} finally {
		if (previous === undefined) delete process.env.PI_AUTOMODE_TEST_JEV_KEY;
		else process.env.PI_AUTOMODE_TEST_JEV_KEY = previous;
	}
});

test("/automode jev test probes the endpoint in both directions", async () => {
	const originalFetch = globalThis.fetch;
	clearJevCache();
	const answers = (danger: number) => ({
		model: "typesafe/jev-1.13",
		answers: {
			hard_deny: { type: "noul", noul: danger },
			soft_deny_uncovered: { type: "noul", noul: danger },
			intent_mismatch: { type: "noul", noul: danger },
			scope_escape: { type: "noul", noul: danger },
		},
	});
	let calls = 0;
	const bodies: Array<{ state: { action: string } }> = [];
	globalThis.fetch = (async (_url: string | URL, init?: RequestInit) => {
		calls += 1;
		bodies.push(JSON.parse(String(init?.body)));
		return new Response(
			JSON.stringify(answers(calls === 1 ? 0.01 : 0.99)),
			{ status: 200 },
		);
	}) as typeof fetch;

	const previous = process.env.PI_AUTOMODE_TEST_JEV_KEY;
	process.env.PI_AUTOMODE_TEST_JEV_KEY = "test-key";
	try {
		const fake = createFakePi();
		createPiAutomode({
			loadConfig: () =>
				baseConfig({ jevApiKeyEnv: "PI_AUTOMODE_TEST_JEV_KEY" }),
		})(fake.pi);
		const ctx = createFakeCtx(fake.entries);
		await fake.emit("session_start", { type: "session_start" }, ctx);

		await fake.commands.get("automode")?.handler("jev test", ctx);
		const last = ctx.notifications.at(-1);
		assert.equal(last?.type, "info");
		assert.match(last?.message ?? "", /safe: allow/);
		assert.match(last?.message ?? "", /dangerous: block/);
		assert.equal(calls, 2);
		// The first probe must be the safe action and the second the dangerous
		// one, or the direction check is vacuous.
		assert.match(bodies[0]!.state.action, /README\.md/);
		assert.match(bodies[1]!.state.action, /rm/);
	} finally {
		globalThis.fetch = originalFetch;
		if (previous === undefined) delete process.env.PI_AUTOMODE_TEST_JEV_KEY;
		else process.env.PI_AUTOMODE_TEST_JEV_KEY = previous;
		clearJevCache();
	}
});

test("probeJevClassifier fails closed when the endpoint errors", async () => {
	const originalFetch = globalThis.fetch;
	clearJevCache();
	globalThis.fetch = (async () =>
		new Response(JSON.stringify({ message: "boom" }), {
			status: 500,
		})) as typeof fetch;
	const previous = process.env.PI_AUTOMODE_TEST_JEV_KEY;
	process.env.PI_AUTOMODE_TEST_JEV_KEY = "test-key";
	try {
		const ctx = createFakeCtx([], {
			modelRegistry: { getApiKeyForProvider: async () => undefined },
		}) as never;
		const result = await probeJevClassifier(
			ctx,
			baseConfig({ jevApiKeyEnv: "PI_AUTOMODE_TEST_JEV_KEY" }),
		);
		assert.equal(result.ok, false);
		if (result.ok) return;
		assert.match(result.reason, /HTTP 500: boom/);
	} finally {
		globalThis.fetch = originalFetch;
		if (previous === undefined) delete process.env.PI_AUTOMODE_TEST_JEV_KEY;
		else process.env.PI_AUTOMODE_TEST_JEV_KEY = previous;
		clearJevCache();
	}
});

test("/automode model without an argument does not open the LLM picker in Jev mode", async () => {
	const fake = createFakePi();
	createPiAutomode({
		loadConfig: () => baseConfig({ classifierBackend: "jev" }),
	})(fake.pi);
	const ctx = createFakeCtx(fake.entries);
	await fake.emit("session_start", { type: "session_start" }, ctx);

	await fake.commands.get("automode")?.handler("model", ctx);
	const last = ctx.notifications.at(-1);
	assert.equal(last?.type, "info");
	assert.match(last?.message ?? "", /Jev classifier model: ~typesafe\/jev-latest/);
	assert.match(last?.message ?? "", /does not apply to the Jev backend/);
});
