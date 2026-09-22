import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
	buildJevQuestions,
	buildJevState,
	clearJevCache,
	credentialKey,
	defaultJevClassifyAction,
	jevDecision,
	openRouterDecisionsUrl,
	parseJevResponse,
	redactSecrets,
	resolveJevKey,
	statusText,
} from "../extensions/auto-mode.ts";
import type { EffectiveConfig } from "../extensions/auto-mode.ts";
import {
	baseConfig,
	baseState,
	createFakeCtx,
	createFakePi,
} from "./test-helpers.ts";
import { createPiAutomode } from "../extensions/auto-mode.ts";

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

test("parseJevResponse reads the answers map and clamps out-of-range values", () => {
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
	assert.deepEqual(parsed.scores, {
		hard_deny: 1,
		soft_deny_uncovered: 0,
		intent_mismatch: 0.4,
	});
	assert.equal(parsed.danger, 1);
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
		] as Array<[number, string]>
	) {
		const parsed = parseJevResponse(status, body);
		assert.equal(parsed.ok, false, body);
	}
});

// --- decision mapping ------------------------------------------------------

test("jevDecision blocks at or above the hard threshold", () => {
	const config = baseConfig();
	assert.deepEqual(jevDecision({ hard_deny: 0.5 }, config), {
		decision: "block",
		tier: "hard_deny",
		reason: "Jev: hard=0.50 soft=0.00 intent=0.00 scope=0.00",
	});
});

test("jevDecision blocks the soft band from any danger-side question", () => {
	const config = baseConfig();
	for (
		const scores of [
			{ hard_deny: 0.49, soft_deny_uncovered: 0.35 },
			{ hard_deny: 0.0, intent_mismatch: 0.35 },
			{ hard_deny: 0.0, scope_escape: 0.36 },
		]
	) {
		const decision = jevDecision(scores, config);
		assert.equal(decision.decision, "block", JSON.stringify(scores));
		assert.equal(decision.tier, "soft_deny");
	}
});

test("jevDecision allows below both thresholds", () => {
	const decision = jevDecision(
		{ hard_deny: 0.49, soft_deny_uncovered: 0.34 },
		baseConfig(),
	);
	assert.equal(decision.decision, "allow");
	assert.equal(decision.tier, "none");
});

test("jevDecision honors configured thresholds", () => {
	const config = baseConfig({
		jevHardDenyThreshold: 0.9,
		jevSoftDenyThreshold: 0.8,
	});
	assert.equal(
		jevDecision({ hard_deny: 0.7, intent_mismatch: 0.5 }, config).decision,
		"allow",
	);
	assert.equal(
		jevDecision({ hard_deny: 0.9 }, config).tier,
		"hard_deny",
	);
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

// --- state redaction -------------------------------------------------------

test("buildJevState redacts secrets and bounds intent", () => {
	clearJevCache();
	const state = buildJevState(
		"bash {\"command\":\"export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\"}",
		"/tmp/project",
		"deploy with sk-or-v1-abcdefghijklmnop",
		"",
	);
	assert.doesNotMatch(state.tool_action!, /AKIAIOSFODNN7EXAMPLE/);
	assert.match(state.tool_action!, /REDACTED/);
	assert.doesNotMatch(state.user_request!, /sk-or-v1-abcdefghijklmnop/);
	assert.equal(state.project_instructions, "(none)");
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

// --- classify action -------------------------------------------------------

function jevTestConfig(overrides: Partial<EffectiveConfig> = {}): EffectiveConfig {
	return baseConfig({
		jevApiKeyEnv: "PI_AUTOMODE_TEST_JEV_KEY",
		...overrides,
	});
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
				answers: { hard_deny: { type: "noul", noul: 0.9 } },
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
		const headers = calls[0]!.init.headers as Record<string, string>;
		assert.equal(headers.Authorization, "Bearer test-key");
		const payload = JSON.parse(String(calls[0]!.init.body)) as {
			model: string;
			state: { tool_action: string };
			questions: Record<string, { type: string }>;
		};
		assert.equal(payload.model, "~typesafe/jev-latest");
		assert.match(payload.state.tool_action, /deploy/);
		assert.equal(payload.questions.hard_deny!.type, "noul");
		assert.equal(first.io?.model, "openrouter/typesafe/jev-1.13");

		const second = await defaultJevClassifyAction(
			ctx as never,
			config,
			action,
			"",
			JEV_KEY_DEPS,
		);
		assert.equal(calls.length, 1);
		assert.match(second.reason, /\(cached\)$/);
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
				answers: {
					hard_deny: { type: "noul", noul: 0.01 },
					intent_mismatch: { type: "noul", noul: 0.02 },
				},
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
