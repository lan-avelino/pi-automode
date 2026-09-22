/**
 * jev.ts — Jev / SystemOne classifier backend for pi-automode.
 *
 * Jev is not an LLM: it takes a bounded `state` object and `noul`
 * probability questions and returns a 0..1 score per question. Policy text
 * lives in each question's `instructions`; context lives in `state`.
 *
 * Jev replaces only the classifier stage. The deterministic layers
 * (permissions, hard-deny, path policy) run before this action and stay
 * authoritative. Any setup, transport, or parse failure fails closed.
 */
import { createHash } from "node:crypto";
import type { Usage } from "@earendil-works/pi-ai";
import {
  readStoredCredential as readStoredCredentialFromDisk,
  type ExtensionContext,
} from "@earendil-works/pi-coding-agent";
import { buildClassifierTranscript } from "./transcript.ts";
import { classifierCacheSessionId } from "./classifier.ts";
import type {
  ClassificationDecision,
  ClassifierIo,
  ClassifyResult,
  EffectiveConfig,
} from "./types.ts";

const ACTION_MAX = 2000;
const INTENT_MAX = 600;
const RULES_MAX = 1500;
const CACHE_LIMIT = 200;
const CACHE = new Map<string, ClassificationDecision>();

export type JevQuestion = { type: "noul"; instructions: string };
export type JevQuestions = Record<string, JevQuestion>;

export type JevParse =
  | {
    ok: true;
    model: string;
    scores: Record<string, number>;
    danger: number;
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
 * so the model's danger direction is never mixed.
 */
export function buildJevQuestions(config: EffectiveConfig): JevQuestions {
  const environment = clip(config.environment.join("\n- "), RULES_MAX);
  const allow = clip(config.allow.join("\n- "), RULES_MAX);
  const soft = clip(config.softDeny.join("\n- "), RULES_MAX);
  const hard = clip(config.hardDeny.join("\n- "), RULES_MAX);
  return {
    hard_deny: {
      type: "noul",
      instructions:
        "The described action violates at least one unconditional HARD_DENY rule. " +
        `Trusted environment:\n- ${environment}\nHARD_DENY:\n- ${hard}`,
    },
    soft_deny_uncovered: {
      type: "noul",
      instructions:
        "A SOFT_DENY rule applies and neither an ALLOW exception nor direct, " +
        "bounded user authorization in user_request covers it. " +
        `SOFT_DENY:\n- ${soft}\nALLOW:\n- ${allow}`,
    },
    intent_mismatch: {
      type: "noul",
      instructions:
        "The action exceeds, contradicts, or is not authorized by what the user " +
        'actually asked in user_request. General requests ("clean up the repo") ' +
        "do not authorize destructive, external, production, or irreversible actions.",
    },
    scope_escape: {
      type: "noul",
      instructions:
        "The action reaches outside the trusted repository, working tree, or " +
        `trusted environment. Trusted environment:\n- ${environment}`,
    },
  };
}

export function buildJevState(
  action: string,
  cwd: string,
  intent: string,
  loadedContext: string,
): Record<string, string> {
  return {
    tool_action: clip(redactSecrets(action), ACTION_MAX),
    working_directory: cwd,
    user_request: clip(redactSecrets(intent), INTENT_MAX) || "(none)",
    project_instructions: clip(
      redactSecrets(loadedContext || "(none)"),
      INTENT_MAX,
    ),
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
  if (typeof answers !== "object" || answers === null) {
    return { ok: false, error: "response has no answers map" };
  }
  const scores: Record<string, number> = {};
  for (const [id, answer] of Object.entries(answers as Record<string, unknown>)) {
    if (typeof answer !== "object" || answer === null) continue;
    const probability = (answer as Record<string, unknown>).noul;
    if (typeof probability === "number" && !Number.isNaN(probability)) {
      scores[id] = Math.min(1, Math.max(0, probability));
    }
  }
  if (Object.keys(scores).length === 0) {
    return { ok: false, error: "no usable noul answers in response" };
  }
  return {
    ok: true,
    model: typeof rec.model === "string" ? rec.model : "jev",
    scores,
    danger: Math.max(...Object.values(scores)),
  };
}

/** Map per-question probabilities onto pi-automode's decision + tier. */
export function jevDecision(
  scores: Record<string, number>,
  config: EffectiveConfig,
): ClassificationDecision {
  const hard = scores.hard_deny ?? 0;
  const softUncovered = scores.soft_deny_uncovered ?? 0;
  const intent = scores.intent_mismatch ?? 0;
  const scope = scores.scope_escape ?? 0;
  const soft = Math.max(softUncovered, intent, scope);
  const summary =
    `hard=${hard.toFixed(2)} soft=${softUncovered.toFixed(2)} ` +
    `intent=${intent.toFixed(2)} scope=${scope.toFixed(2)}`;
  if (hard >= config.jevHardDenyThreshold) {
    return { decision: "block", tier: "hard_deny", reason: `Jev: ${summary}` };
  }
  if (soft >= config.jevSoftDenyThreshold) {
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

export async function resolveJevKey(
  ctx: ExtensionContext,
  config: EffectiveConfig,
  deps: JevKeyDeps = {},
): Promise<{ key?: string; source: JevKeySource }> {
  const env = deps.env ?? process.env;
  const readStored = deps.readStoredCredential ?? readStoredCredentialFromDisk;
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
  const fromEnv = env[config.jevApiKeyEnv];
  if (typeof fromEnv === "string" && fromEnv.trim() !== "") {
    return { key: fromEnv.trim(), source: "env" };
  }
  try {
    const stored = credentialKey(readStored("openrouter"));
    if (stored) return { key: stored, source: "pi-auth" };
  } catch {
    // no stored credential
  }
  return { source: "none" };
}

const ZERO_USAGE: Usage = {
  input: 0,
  output: 0,
  cacheRead: 0,
  cacheWrite: 0,
  totalTokens: 0,
  cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
};

/** Test hook: clear the session verdict cache. */
export function clearJevCache(): void {
  CACHE.clear();
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
  const reasoning = { mode: "backend", backend: "jev", model } as const;
  const intent = buildClassifierTranscript(ctx, {
    maxUserTokens: config.maxUserTranscriptTokens,
    maxToolTokens: config.maxToolTranscriptTokens,
  });
  const state = buildJevState(action, ctx.cwd, intent, loadedContext);
  const questions = buildJevQuestions(config);
  const cacheKey = createHash("sha256")
    .update(JSON.stringify({
      session: classifierCacheSessionId(ctx),
      model,
      state,
      questions,
      hard: config.jevHardDenyThreshold,
      soft: config.jevSoftDenyThreshold,
    }))
    .digest("hex");

  const cached = CACHE.get(cacheKey);
  if (cached) {
    return { ...cached, reason: `${cached.reason} (cached)`, reasoning };
  }

  const { key } = await resolveJevKey(ctx, config, deps);
  if (!key) {
    return {
      decision: "block",
      tier: "none",
      reasoning,
      reason:
        `Jev classifier key missing (${config.jevApiKeyEnv}); run /login openrouter ` +
        "or set the env var. Auto mode fails closed.",
    };
  }

  const signals: AbortSignal[] = [AbortSignal.timeout(config.jevTimeoutMs)];
  if (ctx.signal) signals.push(ctx.signal);
  const signal = signals.length === 1 ? signals[0] : AbortSignal.any(signals);
  const started = Date.now();

  try {
    const response = await fetch(openRouterDecisionsUrl(config.jevBaseUrl), {
      method: "POST",
      headers: {
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
        "HTTP-Referer": "https://pi.dev",
        "X-Title": "pi-automode",
      },
      body: JSON.stringify({ model, state, questions }),
      signal,
    });
    const rawBody = await response.text();
    const parsed = parseJevResponse(response.status, rawBody);
    if (!parsed.ok) {
      return {
        decision: "block",
        tier: "none",
        reasoning,
        reason: `Jev classifier failed; auto mode fails closed: ${parsed.error}`,
      };
    }

    const decision = jevDecision(parsed.scores, config);
    const durationMs = Date.now() - started;

    CACHE.delete(cacheKey);
    CACHE.set(cacheKey, decision);
    while (CACHE.size > CACHE_LIMIT) {
      const oldest = CACHE.keys().next();
      if (oldest.done) break;
      CACHE.delete(oldest.value);
    }

    const io: ClassifierIo = {
      model: `openrouter/${parsed.model}`,
      reasoning,
      prompt: {
        system: JSON.stringify(questions, null, 2),
        context: JSON.stringify(state),
        action,
        fastInstruction: "(not used by the Jev backend)",
        detailedInstruction: "(not used by the Jev backend)",
      },
      attempts: [{
        stage: "detailed",
        attempt: 1,
        parsed: decision,
        durationMs,
        response: {
          stopReason: "stop",
          text: clip(rawBody, 4000),
          model: parsed.model,
          timestamp: Date.now(),
          usage: ZERO_USAGE,
        },
      }],
      durationMs,
    };
    return { ...decision, reasoning, io };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const timedOut = signal.aborted || /abort|timeout/i.test(message);
    return {
      decision: "block",
      tier: "none",
      reasoning,
      reason:
        `Jev classifier ${
          timedOut ? `timed out after ${config.jevTimeoutMs}ms` : "failed"
        }; auto mode fails closed: ${clip(message, 160)}`,
    };
  }
}
