/**
 * jev.ts — Jev / SystemOne classifier backend for pi-automode.
 *
 * Jev is not an LLM: it takes a `state` object and `noul` probability
 * questions and returns a 0..1 score per question. The transcript and project
 * instructions are bounded upstream, before this module; policy text
 * lives in each question's `instructions`; context lives in `state`.
 *
 * Jev replaces only the classifier stage. The deterministic layers
 * (permissions, hard-deny, path policy) run before this action and stay
 * authoritative. Any setup, transport, or parse failure fails closed.
 */
import { createHash } from "node:crypto";
import {
  readStoredCredential as readStoredCredentialFromDisk,
  type ExtensionContext,
} from "@earendil-works/pi-coding-agent";
import {
  CLASSIFIER_POLICY_CLAUSES,
  DEFAULT_JEV_API_KEY_ENV,
} from "./constants.ts";
import { buildClassifierTranscript } from "./transcript.ts";
import { classifierCacheSessionId } from "./classifier.ts";
import type {
  ClassificationDecision,
  ClassifierIo,
  ClassifierReasoning,
  ClassifyResult,
  EffectiveConfig,
} from "./types.ts";

const CACHE_LIMIT = 200;

type CachedVerdict = {
  decision: ClassificationDecision;
  model: string;
};

const CACHE = new Map<string, CachedVerdict>();

export type JevQuestion = { type: "noul"; instructions: string };
export type JevQuestions = Record<string, JevQuestion>;

export type JevParse =
  | {
    ok: true;
    model: string;
    scores: Record<string, number>;
  }
  | { ok: false; error: string };

// --- redaction (from specpi-jev-guard risk-rules.ts) -----------------------

const SECRET_PATTERNS: RegExp[] = [
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
  /\bsk-(ant|or-v1|live|test)-[A-Za-z0-9_-]{8,}/g,
  /\bsk-ant-oat[A-Za-z0-9_-]{8,}/g,
  /\bgh[pousr]_[A-Za-z0-9]{20,}/g,
  /\bxox[baprs]-[A-Za-z0-9-]{8,}/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bAIza[0-9A-Za-z_-]{20,}/g,
  /(?<=['"]?(api[_-]?key|token|secret|password|passwd|auth)['"]?\s*[:=]\s*['"]?)[^'"\s;,}]{8,}/gi,
  /(?<=--(token|api-key|api_key|password)\s*=\s*)\S{8,}/gi,
  /\bBearer\s+[A-Za-z0-9._~+/-]{12,}/g,
];

export function redactSecrets(text: string): string {
  let out = text;
  for (const re of SECRET_PATTERNS) {
    re.lastIndex = 0;
    out = out.replace(re, "[REDACTED]");
  }
  return out;
}

function clip(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max)}…[truncated]`;
}

/**
 * Redact one policy rule list. Rule lists are user-owned config, so they are sent
 * in full, exactly as the LLM classifier interpolates them; only secret shapes
 * are removed.
 */
function redactRules(rules: string[]): string {
  return redactSecrets(rules.join("\n- "));
}

/**
 * True when the configured key env var is the OpenRouter default while the base
 * URL points somewhere else. The default variable holds an OpenRouter key, so it
 * is withheld from custom endpoints instead of being forwarded to a third party.
 */
export function jevOpenRouterKeyEnvMismatch(
  config: EffectiveConfig,
): boolean {
  // Windows env names are case-insensitive, so compare case-insensitively.
  const defaultEnv = config.jevApiKeyEnv.trim().toUpperCase() ===
    DEFAULT_JEV_API_KEY_ENV;
  return defaultEnv && !isOpenRouterBaseUrl(config.jevBaseUrl);
}

/** Diagnostics for a Jev key configuration that would withhold the default env var. */
export function jevCredentialDiagnostics(config: EffectiveConfig): string[] {
  if (!jevOpenRouterKeyEnvMismatch(config)) return [];
  return [
    `autoMode.jevBaseUrl targets a custom endpoint while autoMode.jevApiKeyEnv is still the OpenRouter default (${DEFAULT_JEV_API_KEY_ENV}); that variable is not sent to a custom base URL. Set autoMode.jevApiKeyEnv to a variable that holds the custom endpoint's key.`,
  ];
}

// --- credential (trimmed from specpi-jev-guard pi-auth.ts) -----------------

function nonEmpty(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() !== ""
    ? value.trim()
    : undefined;
}

/**
 * The usable key in a stored pi credential, or undefined when there is none.
 * A `!command` api_key is declined rather than sent as a literal bearer token.
 */
export function credentialKey(credential: unknown): string | undefined {
  if (typeof credential !== "object" || credential === null) return undefined;
  const rec = credential as Record<string, unknown>;
  if (rec.type === "oauth") return nonEmpty(rec.access);
  if (rec.type !== "api_key") return undefined;
  const raw = nonEmpty(rec.key);
  return raw === undefined || raw.startsWith("!") ? undefined : raw;
}

// --- endpoint + payload ----------------------------------------------------

/**
 * Derive the OpenRouter decisions endpoint from a chat-compatible base URL.
 * Default base https://openrouter.ai/api/v1 -> .../api/alpha/decisions.
 */
export function openRouterDecisionsUrl(baseUrl: string): string {
  const trimmed = baseUrl.replace(/\/+$/, "");
  if (trimmed.endsWith("/api/alpha/decisions")) return trimmed;
  if (trimmed.endsWith("/api/v1")) {
    return `${trimmed.slice(0, -"/api/v1".length)}/api/alpha/decisions`;
  }
  return `${trimmed}/decisions`;
}

/**
 * Intent questions, all phrased danger-side up (high probability = block),
 * so the model's danger direction is never mixed. Each question restates the
 * shared `CLASSIFIER_POLICY_CLAUSES` so Jev encodes the same policy as the LLM
 * classifier instead of a paraphrase of it.
 */
export function buildJevQuestions(config: EffectiveConfig): JevQuestions {
  const envText = redactRules(config.environment);
  const allowText = redactRules(config.allow);
  const softText = redactRules(config.softDeny);
  const hardText = redactRules(config.hardDeny);
  const shared = `${CLASSIFIER_POLICY_CLAUSES.untrustedData} ` +
    `${CLASSIFIER_POLICY_CLAUSES.securityNotQuality} ` +
    `${CLASSIFIER_POLICY_CLAUSES.allowByDefault}`;
  return {
    hard_deny: {
      type: "noul",
      instructions:
        "The described action violates at least one unconditional HARD_DENY rule. " +
        `${CLASSIFIER_POLICY_CLAUSES.hardDenyNoOverride} ` +
        `${CLASSIFIER_POLICY_CLAUSES.allowNeverOverridesHardDeny} ` +
        `Trusted environment:\n- ${envText}\nHARD_DENY:\n- ${hardText}\n` +
        shared,
    },
    soft_deny_uncovered: {
      type: "noul",
      instructions:
        "The described action matches a SOFT_DENY rule that is not covered. " +
        `${CLASSIFIER_POLICY_CLAUSES.softDenyAuthorization} ` +
        `${CLASSIFIER_POLICY_CLAUSES.fileAuthorizationBounds} ` +
        `${CLASSIFIER_POLICY_CLAUSES.otherSoftDenyAuthorization} ` +
        `${CLASSIFIER_POLICY_CLAUSES.authorizationRevocation} ` +
        `${CLASSIFIER_POLICY_CLAUSES.allowNeverOverridesHardDeny} ` +
        `SOFT_DENY:\n- ${softText}\nALLOW:\n- ${allowText}\n` +
        shared,
    },
    intent_mismatch: {
      type: "noul",
      instructions:
        "The action exceeds, contradicts, or is not authorized by what the user " +
        'actually asked in user_request. ' +
        `${CLASSIFIER_POLICY_CLAUSES.generalRequestsNotIntent} ` +
        shared,
    },
    scope_escape: {
      type: "noul",
      instructions:
        "The action reaches outside the trusted repository, working tree, or " +
        `trusted environment. Trusted environment:\n- ${envText}\n` +
        shared,
    },
  };
}

/**
 * Build the Jev `state`. Every field is redacted. The transcript is already
 * token-bounded by `maxUserTranscriptTokens`/`maxToolTranscriptTokens`, and
 * `loadedContext` is already per-file bounded upstream, so neither is re-bounded
 * here; an oversized action fails closed at the endpoint instead of being
 * truncated.
 */
export function buildJevState(
  action: string,
  intent: string,
  loadedContext: string,
): Record<string, string> {
  return {
    action: redactSecrets(action),
    user_request: redactSecrets(intent) || "(none)",
    project_instructions: redactSecrets(loadedContext) || "(none)",
  };
}

/** Parse the TypeSafe /v1/systemone (OpenRouter decisions) response. */
export function parseJevResponse(status: number, body: string): JevParse {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return { ok: false, error: `HTTP ${status}: unreadable response` };
  }
  if (status < 200 || status >= 300) {
    const rec = (parsed ?? {}) as Record<string, unknown>;
    const msg = rec.message ?? rec.error;
    return {
      ok: false,
      error: `HTTP ${status}${
        typeof msg === "string" ? `: ${clip(msg, 200)}` : ""
      }`,
    };
  }
  const rec = (parsed ?? {}) as Record<string, unknown>;
  const answers = rec.answers;
  if (
    typeof answers !== "object" || answers === null || Array.isArray(answers)
  ) {
    return { ok: false, error: "response has no answers map" };
  }
  const scores: Record<string, number> = {};
  for (const [id, answer] of Object.entries(answers as Record<string, unknown>)) {
    if (typeof answer !== "object" || answer === null) continue;
    const answerRecord = answer as Record<string, unknown>;
    // Accept an omitted `type`, but reject a different question type outright.
    if (answerRecord.type !== undefined && answerRecord.type !== "noul") {
      continue;
    }
    const probability = answerRecord.noul;
    if (
      typeof probability !== "number" || !Number.isFinite(probability) ||
      probability < 0 || probability > 1
    ) {
      // An out-of-range probability is a contract violation, not a score to
      // clamp. Dropping it makes the answer missing and the call fails closed.
      continue;
    }
    scores[id] = probability;
  }
  if (Object.keys(scores).length === 0) {
    return { ok: false, error: "no usable noul answers in response" };
  }
  return {
    ok: true,
    model: typeof rec.model === "string" ? rec.model : "jev",
    scores,
  };
}

/**
 * Question ids a Jev response must answer. A response that omits any of them
 * is invalid output and fails closed rather than defaulting to zero danger.
 */
export function missingJevAnswers(
  scores: Record<string, number>,
  questions: JevQuestions,
): string[] {
  return Object.keys(questions).filter((id) => scores[id] === undefined);
}

/**
 * Map per-question probabilities onto pi-automode's decision + tier. Missing
 * scores fail closed, so a caller that skips `missingJevAnswers` cannot turn
 * incomplete output into an allow.
 */
export function jevDecision(
  scores: Record<string, number>,
  config: EffectiveConfig,
  questions: JevQuestions,
): ClassificationDecision {
  const missing = missingJevAnswers(scores, questions);
  if (missing.length > 0) {
    return {
      decision: "block",
      tier: "none",
      reason:
        `Jev: incomplete scores for ${missing.join(", ")}; auto mode fails closed.`,
    };
  }
  const hard = scores.hard_deny ?? 0;
  const softUncovered = scores.soft_deny_uncovered ?? 0;
  const intent = scores.intent_mismatch ?? 0;
  const scope = scores.scope_escape ?? 0;
  // `scope_escape` is a supporting, non-parity signal: it gates at its own
  // higher threshold so it cannot decide the verdict alone.
  const soft = Math.max(softUncovered, intent);
  const scopeGate = scope >= config.jevScopeEscapeThreshold;
  const summary =
    `hard=${hard.toFixed(2)} soft=${softUncovered.toFixed(2)} ` +
    `intent=${intent.toFixed(2)} scope=${scope.toFixed(2)}`;
  if (hard >= config.jevHardDenyThreshold) {
    return { decision: "block", tier: "hard_deny", reason: `Jev: ${summary}` };
  }
  if (soft >= config.jevSoftDenyThreshold || scopeGate) {
    return { decision: "block", tier: "soft_deny", reason: `Jev: ${summary}` };
  }
  return {
    decision: "allow",
    tier: "none",
    reason: `Jev: permitted (${summary})`,
  };
}

// --- key resolution: pi registry -> env -> stored auth.json ----------------

export type JevKeySource = "pi-auth" | "env" | "none";

/** Test seams: keep key resolution deterministic without touching real auth.json. */
export type JevKeyDeps = {
  readStoredCredential?: (providerId: string) => unknown;
  env?: Record<string, string | undefined>;
};

/**
 * True when a base URL targets OpenRouter itself. Only then may OpenRouter-owned
 * Pi credentials be sent; a custom endpoint must supply its own key via
 * `jevApiKeyEnv` so the OpenRouter key never leaves for a third party.
 */
export function isOpenRouterBaseUrl(baseUrl: string): boolean {
  try {
    const url = new URL(openRouterDecisionsUrl(baseUrl));
    const host = url.hostname.toLowerCase();
    // Only the default-port HTTPS endpoint is the OpenRouter service. A
    // non-default port or cleartext http is not, so the OpenRouter key stays
    // withheld there.
    return (host === "openrouter.ai" || host.endsWith(".openrouter.ai")) &&
      url.port === "" &&
      url.protocol === "https:";
  } catch {
    return false;
  }
}

export async function resolveJevKey(
  ctx: ExtensionContext,
  config: EffectiveConfig,
  deps: JevKeyDeps = {},
): Promise<{ key?: string; source: JevKeySource }> {
  const env = deps.env ?? process.env;
  const readStored = deps.readStoredCredential ?? readStoredCredentialFromDisk;
  const openRouterOwned = isOpenRouterBaseUrl(config.jevBaseUrl);
  if (openRouterOwned) {
    try {
      const viaRegistry = await ctx.modelRegistry?.getApiKeyForProvider(
        "openrouter",
      );
      if (typeof viaRegistry === "string" && viaRegistry.trim() !== "") {
        return { key: viaRegistry.trim(), source: "pi-auth" };
      }
    } catch {
      // fall through to env / stored credential
    }
  }
  // The OpenRouter default variable is withheld from custom endpoints. A custom
  // base URL must name its own variable so the OpenRouter key is never sent.
  // Compare case-insensitively because Windows env names are case-insensitive.
  const defaultKeyEnv = config.jevApiKeyEnv.trim().toUpperCase() ===
    DEFAULT_JEV_API_KEY_ENV;
  if (openRouterOwned || !defaultKeyEnv) {
    const fromEnv = env[config.jevApiKeyEnv];
    if (typeof fromEnv === "string" && fromEnv.trim() !== "") {
      return { key: fromEnv.trim(), source: "env" };
    }
  }
  if (openRouterOwned) {
    try {
      const stored = credentialKey(readStored("openrouter"));
      if (stored) return { key: stored, source: "pi-auth" };
    } catch {
      // no stored credential
    }
  }
  return { source: "none" };
}

/** Explain why key resolution produced no key for the active configuration. */
function jevMissingKeyReason(config: EffectiveConfig): string {
  const hint = jevOpenRouterKeyEnvMismatch(config)
    ? `set autoMode.jevApiKeyEnv to a variable that holds the custom endpoint's key (${DEFAULT_JEV_API_KEY_ENV} is not sent to a custom base URL)`
    : isOpenRouterBaseUrl(config.jevBaseUrl)
    ? "run /login openrouter or set the env var"
    : "set the env var (custom base URLs do not use Pi's OpenRouter credential)";
  return `Jev classifier key missing (${config.jevApiKeyEnv}); ${hint}. ` +
    "Auto mode fails closed.";
}

/** Test hook: clear the session verdict cache. */
export function clearJevCache(): void {
  CACHE.clear();
}

/** Human-readable Jev backend status for `/automode jev`. */
export function jevStatusText(
  config: EffectiveConfig,
  keySource: JevKeySource,
  diagnostics: string[] = [],
): string {
  const credential = {
    "pi-auth": "Pi registry or stored credential",
    "env": `environment variable ${config.jevApiKeyEnv}`,
    "none": jevOpenRouterKeyEnvMismatch(config)
      ? `none; the classifier fails closed (set a custom key variable, not ${DEFAULT_JEV_API_KEY_ENV})`
      : `none; the classifier fails closed (set ${config.jevApiKeyEnv})`,
  }[keySource];
  const lines = [
    `backend: ${config.classifierBackend}`,
    `model: ${config.jevModel}`,
    `endpoint: ${openRouterDecisionsUrl(config.jevBaseUrl)}`,
    `credential: ${credential}`,
    `hard deny threshold: ${config.jevHardDenyThreshold}`,
    `soft deny threshold: ${config.jevSoftDenyThreshold}`,
    `scope escape threshold: ${config.jevScopeEscapeThreshold}`,
    `timeout: ${config.jevTimeoutMs}ms`,
    "ignored by this backend: classifierReasoningLevel, fastClassifierMaxTokens",
  ];
  for (const diagnostic of diagnostics.filter((d) => /jev/i.test(d))) {
    lines.push(`warning: ${diagnostic}`);
  }
  return lines.join("\n");
}

function jevIo(params: {
  model: string;
  baseUrl: string;
  reasoning: ClassifierReasoning;
  questions: JevQuestions;
  state: Record<string, string>;
  action: string;
  decision?: ClassificationDecision;
  error?: string;
  durationMs: number;
  cached: boolean;
}): ClassifierIo {
  const { model, reasoning, questions, state, action, decision } = params;
  return {
    // The provider is only OpenRouter when the base URL is OpenRouter itself.
    model: isOpenRouterBaseUrl(params.baseUrl)
      ? `openrouter/${model}`
      : model,
    reasoning,
    prompt: {
      system: JSON.stringify(questions, null, 2),
      context: JSON.stringify(state),
      action,
      fastInstruction: "(not used by the Jev backend)",
      detailedInstruction: "(not used by the Jev backend)",
    },
    // Jev reports no token usage, so no synthetic provider response is
    // fabricated and no ccusage `message` entry is written.
    attempts: params.cached ? [] : [{
      stage: "detailed",
      attempt: 1,
      ...(decision === undefined ? {} : { parsed: decision }),
      ...(params.error === undefined ? {} : { error: params.error }),
      durationMs: params.durationMs,
    }],
    durationMs: params.durationMs,
    ...(params.cached ? { cached: true } : {}),
  };
}

type JevScoresResult =
  | {
    ok: true;
    scores: Record<string, number>;
    model: string;
    durationMs: number;
  }
  | { ok: false; reason: string; error?: string; durationMs?: number };

/** One Jev decisions request. Any failure returns `ok: false` so callers block. */
async function requestJevScores(
  ctx: ExtensionContext,
  config: EffectiveConfig,
  state: Record<string, string>,
  questions: JevQuestions,
  deps: JevKeyDeps = {},
): Promise<JevScoresResult> {
  const { key } = await resolveJevKey(ctx, config, deps);
  if (!key) return { ok: false, reason: jevMissingKeyReason(config) };

  const signals: AbortSignal[] = [AbortSignal.timeout(config.jevTimeoutMs)];
  if (ctx.signal) signals.push(ctx.signal);
  const signal = signals.length === 1 ? signals[0] : AbortSignal.any(signals);
  const started = Date.now();

  try {
    const response = await fetch(openRouterDecisionsUrl(config.jevBaseUrl), {
      method: "POST",
      // A redirect could forward the Authorization header to another host; fail closed.
      redirect: "error",
      headers: {
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
        "HTTP-Referer": "https://pi.dev",
        "X-Title": "pi-automode",
      },
      body: JSON.stringify({ model: config.jevModel, state, questions }),
      signal,
    });
    const rawBody = await response.text();
    const parsed = parseJevResponse(response.status, rawBody);
    if (!parsed.ok) {
      return {
        ok: false,
        reason: `Jev classifier failed; auto mode fails closed: ${parsed.error}`,
        error: parsed.error,
        durationMs: Date.now() - started,
      };
    }
    const missing = missingJevAnswers(parsed.scores, questions);
    if (missing.length > 0) {
      return {
        ok: false,
        reason:
          `Jev classifier response is missing answers for: ${missing.join(", ")}; ` +
          "auto mode fails closed.",
        error: `missing answers for: ${missing.join(", ")}`,
        durationMs: Date.now() - started,
      };
    }
    return {
      ok: true,
      scores: parsed.scores,
      model: parsed.model,
      durationMs: Date.now() - started,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const timedOut = signal.aborted || /abort|timeout/i.test(message);
    return {
      ok: false,
      reason:
        `Jev classifier ${
          timedOut ? `timed out after ${config.jevTimeoutMs}ms` : "failed"
        }; auto mode fails closed: ${clip(message, 160)}`,
      error: clip(message, 160),
      durationMs: Date.now() - started,
    };
  }
}

/**
 * The ClassifyAction pi-automode calls when classifierBackend === "jev".
 * Any setup, transport, or parse failure returns a block.
 */
export async function defaultJevClassifyAction(
  ctx: ExtensionContext,
  config: EffectiveConfig,
  action: string,
  loadedContext: string,
  deps: JevKeyDeps = {},
): Promise<ClassifyResult> {
  const model = config.jevModel;
  const reasoning: ClassifierReasoning = {
    mode: "backend",
    backend: "jev",
    model,
  };
  const intent = buildClassifierTranscript(ctx, {
    maxUserTokens: config.maxUserTranscriptTokens,
    maxToolTokens: config.maxToolTranscriptTokens,
  });
  const state = buildJevState(
    action,
    intent,
    loadedContext,
  );
  const questions = buildJevQuestions(config);
  const cacheKey = createHash("sha256")
    .update(JSON.stringify({
      session: classifierCacheSessionId(ctx),
      model,
      baseUrl: config.jevBaseUrl,
      state,
      questions,
      hard: config.jevHardDenyThreshold,
      soft: config.jevSoftDenyThreshold,
      scope: config.jevScopeEscapeThreshold,
    }))
    .digest("hex");

  const cached = CACHE.get(cacheKey);
  if (cached) {
    // Refresh recency so the bounded cache evicts least-recently-used entries.
    CACHE.delete(cacheKey);
    CACHE.set(cacheKey, cached);
    return {
      ...cached.decision,
      reason: `${cached.decision.reason} (cached)`,
      reasoning,
      io: jevIo({
        model: cached.model,
        baseUrl: config.jevBaseUrl,
        reasoning,
        questions,
        state,
        action,
        decision: cached.decision,
        durationMs: 0,
        cached: true,
      }),
    };
  }

  const result = await requestJevScores(ctx, config, state, questions, deps);
  if (!result.ok) {
    return {
      decision: "block",
      tier: "none",
      reasoning,
      reason: result.reason,
      // A missing key has no attempt to log, matching the LLM path. Transport,
      // HTTP, parse, and incomplete-answer failures log one error attempt.
      ...(result.error === undefined ? {} : {
        io: jevIo({
          model,
          baseUrl: config.jevBaseUrl,
          reasoning,
          questions,
          state,
          action,
          error: result.error,
          durationMs: result.durationMs ?? 0,
          cached: false,
        }),
      }),
    };
  }

  const decision = jevDecision(result.scores, config, questions);
  CACHE.delete(cacheKey);
  CACHE.set(cacheKey, { decision, model: result.model });
  while (CACHE.size > CACHE_LIMIT) {
    const oldest = CACHE.keys().next();
    if (oldest.done) break;
    CACHE.delete(oldest.value);
  }

  return {
    ...decision,
    reasoning,
    io: jevIo({
      model: result.model,
      baseUrl: config.jevBaseUrl,
      reasoning,
      questions,
      state,
      action,
      decision,
      durationMs: result.durationMs,
      cached: false,
    }),
  };
}

export type JevProbe = {
  label: "safe" | "dangerous";
  action: string;
  scores: Record<string, number>;
  decision: ClassificationDecision;
};

export type JevProbeResult =
  | { ok: true; model: string; probes: JevProbe[] }
  | { ok: false; reason: string };

/**
 * Probes that exercise the live endpoint once. A "safe" action should be allowed
 * and a "dangerous" action blocked; if that is not the result, the endpoint's
 * `noul` direction or the thresholds are misconfigured.
 */
const PROBES: Array<{ label: "safe" | "dangerous"; action: string; request: string }> = [
  {
    label: "safe",
    action: '{"toolName":"read","input":{"path":"README.md"}}',
    request: "Summarize the repository README.",
  },
  {
    label: "dangerous",
    action: '{"toolName":"bash","input":{"command":"rm -rf ~/Documents"}}',
    request: "Summarize the repository README.",
  },
];

/** Run the read-only direction probe used by `/automode jev test`. */
export async function probeJevClassifier(
  ctx: ExtensionContext,
  config: EffectiveConfig,
  deps: JevKeyDeps = {},
): Promise<JevProbeResult> {
  const questions = buildJevQuestions(config);
  const probes: JevProbe[] = [];
  let model = config.jevModel;
  for (const probe of PROBES) {
    const state = buildJevState(
      probe.action,
      probe.request,
      "",
    );
    const result = await requestJevScores(ctx, config, state, questions, deps);
    if (!result.ok) return { ok: false, reason: result.reason };
    model = result.model;
    probes.push({
      label: probe.label,
      action: probe.action,
      scores: result.scores,
      decision: jevDecision(result.scores, config, questions),
    });
  }
  return { ok: true, model, probes };
}
