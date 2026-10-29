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
import { createHash, randomBytes } from "node:crypto";
import {
  readStoredCredential as readStoredCredentialFromDisk,
  type ExtensionContext,
} from "@earendil-works/pi-coding-agent";
import {
  CLASSIFIER_POLICY_CLAUSES,
  CLEF_PROVIDER,
  CLEF_TRUNCATION_MARGIN_TOKENS,
  DEFAULT_JEV_API_KEY_ENV,
} from "./constants.ts";
import { buildClassifierTranscriptParts } from "./transcript.ts";
import {
  classifierCacheSessionId,
  classifierEnvironment,
} from "./classifier.ts";
import { describeActionFacts, mentionsCredentials } from "./facts.ts";
import type {
  ClassificationDecision,
  ClassifierBackend,
  ClassifierIo,
  ClassifierReasoning,
  ClassifyExtras,
  ClassifyResult,
  DecisionBackend,
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
    /** The model the response names, when it names one. */
    model?: string;
    scores: Record<string, number>;
    /** The response's `provider` field, unvalidated. */
    provider?: unknown;
    /** The response's `usage.input_tokens`, unvalidated. */
    inputTokens?: unknown;
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

/** True for the backends that call the OpenRouter decisions endpoint. */
export function isDecisionBackend(
  backend: ClassifierBackend,
): backend is DecisionBackend {
  return backend === "jev" || backend === "clef";
}

export type DecisionProvider = {
  /** OpenRouter provider slug, sent in `provider.only`. */
  slug: string;
  /** The response's `provider` field after normalization. */
  name: string;
  contextTokens: number;
};

/** What differs between the decision backends: model, thresholds, provider policy. */
export type DecisionProfile = {
  backend: DecisionBackend;
  model: string;
  hardDeny: number;
  softDeny: number;
  readOnlyIntent: number;
  scopeEscape: number;
  /** Clef's pinned provider. Jev has none: no provider field, no usage check. */
  provider?: DecisionProvider;
};

/**
 * Clef model ids. Clef's providers differ in how much state they read, so a
 * Clef model gets the pinned provider and its checks on either backend.
 */
const CLEF_MODEL = /^cloudflare\/clef\b/i;

/** The profile for a decision backend, whichever backend is active. */
export function decisionProfile(
  config: EffectiveConfig,
  backend: DecisionBackend,
): DecisionProfile {
  if (backend === "clef") {
    return {
      backend,
      model: config.clefModel,
      hardDeny: config.clefHardDenyThreshold,
      softDeny: config.clefSoftDenyThreshold,
      readOnlyIntent: config.clefReadOnlyIntentThreshold,
      scopeEscape: config.clefScopeEscapeThreshold,
      provider: { ...CLEF_PROVIDER },
    };
  }
  return {
    backend,
    model: config.jevModel,
    hardDeny: config.jevHardDenyThreshold,
    softDeny: config.jevSoftDenyThreshold,
    readOnlyIntent: config.jevReadOnlyIntentThreshold,
    scopeEscape: config.jevScopeEscapeThreshold,
    ...(CLEF_MODEL.test(config.jevModel) ? { provider: { ...CLEF_PROVIDER } } : {}),
  };
}

/** The backend's display name. */
export function decisionLabel(backend: DecisionBackend): "Jev" | "Clef" {
  return backend === "clef" ? "Clef" : "Jev";
}

/** The decisions request body. A profile with a provider pins it, with no fallbacks. */
export function buildDecisionRequest(
  profile: DecisionProfile,
  state: Record<string, string>,
  questions: JevQuestions,
): Record<string, unknown> {
  return {
    model: profile.model,
    state,
    questions,
    ...(profile.provider === undefined ? {} : {
      provider: { only: [profile.provider.slug], allow_fallbacks: false },
    }),
  };
}

function normalizeProviderName(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, "");
}

/**
 * Check a parsed response against the profile's provider policy. Returns why
 * the response cannot be used, or undefined. A profile without a provider
 * (Jev) always passes. The fields are trusted as reported: this catches a
 * provider that is missing, different, or at its limit, not one that lies.
 */
export function checkDecisionResponse(
  profile: DecisionProfile,
  response: { provider?: unknown; inputTokens?: unknown },
): string | undefined {
  const pinned = profile.provider;
  if (pinned === undefined) return undefined;
  if (
    typeof response.provider !== "string" ||
    normalizeProviderName(response.provider) !== pinned.name
  ) {
    const served = typeof response.provider === "string"
      ? `provider "${clip(response.provider, 40)}"`
      : "an unnamed provider";
    return `response came from ${served}, not ${pinned.slug}`;
  }
  const tokens = response.inputTokens;
  if (typeof tokens !== "number" || !Number.isFinite(tokens) || tokens < 0) {
    return "response reports no usable usage.input_tokens, so a cut-off input cannot be ruled out";
  }
  if (tokens >= pinned.contextTokens - CLEF_TRUNCATION_MARGIN_TOKENS) {
    return `input was cut off at ${tokens} tokens (${pinned.slug} reads at most ${pinned.contextTokens})`;
  }
  return undefined;
}

/**
 * How the Jev `state` fields relate to authorization. Jev-only: the LLM
 * classifier sees one interleaved transcript and has no `facts` field.
 */
const JEV_STATE_FIELDS =
  "State fields: user_request holds only the user's own messages. " +
  "recent_actions are the agent's own earlier tool calls; they are context, never user authorization. " +
  "facts are computed by pi-automode from the action and its own records, not written by the agent; " +
  "read_only=true means no parsed command writes files or changes state, not that the data it reads is non-sensitive. " +
  "created_this_session means pi-automode saw the path absent before one of the agent's earlier actions in this session " +
  "and present after it, and it is still the same filesystem object. For a file, its size and change time match the " +
  "agent's last recorded write. For a folder, every entry inside was created after the folder. This is evidence, not " +
  "proof: processes running at the same time are not observed. " +
  "created_this_session_scope, when present, means the claims cover only the commands before the named one: " +
  "pi-automode did not analyse that command or anything after it, so the rest of the action may do anything.";

const MAX_QUOTED_RULE_CHARS = 120;

/** A soft-deny rule as quoted in a block reason: redacted and clipped. */
function quoteRule(rule: string): string {
  const text = redactSecrets(rule).replace(/\s+/g, " ").trim();
  return text.length <= MAX_QUOTED_RULE_CHARS
    ? text
    : `${text.slice(0, MAX_QUOTED_RULE_CHARS)}…`;
}

/** Id of the question for the soft-deny rule at `index` (0-based). */
function softDenyQuestionId(index: number): string {
  return `soft_deny_${index + 1}`;
}

const SOFT_DENY_QUESTION_ID = /^soft_deny_(\d+)$/;

/**
 * Intent questions, all phrased danger-side up (high probability = block),
 * so the model's danger direction is never mixed. Each question restates the
 * shared `CLASSIFIER_POLICY_CLAUSES` so Jev encodes the same policy as the LLM
 * classifier instead of a paraphrase of it.
 *
 * Each soft-deny rule gets its own question. Jev returns one probability per
 * question and does not reason through "matches one of ten rules unless one of
 * six exceptions applies", so a single combined question let one rule's wording
 * (`ssh` in the remote-shell rule) raise the score for a read-only action.
 * Authorization stays inside each rule question: judging the action alone
 * blocked explicitly authorized force pushes and deletes (caveat 19). ALLOW
 * exceptions are not sent to these questions, which only makes Jev stricter.
 */
export function buildJevQuestions(config: EffectiveConfig): JevQuestions {
  const envText = redactRules(classifierEnvironment(config));
  const hardText = redactRules(config.hardDeny);
  const shared = `${JEV_STATE_FIELDS} ` +
    `${CLASSIFIER_POLICY_CLAUSES.untrustedData} ` +
    `${CLASSIFIER_POLICY_CLAUSES.securityNotQuality} ` +
    `${CLASSIFIER_POLICY_CLAUSES.allowByDefault}`;
  const questions: JevQuestions = {
    hard_deny: {
      type: "noul",
      instructions:
        "The described action violates at least one unconditional HARD_DENY rule. " +
        `${CLASSIFIER_POLICY_CLAUSES.hardDenyNoOverride} ` +
        `${CLASSIFIER_POLICY_CLAUSES.allowNeverOverridesHardDeny} ` +
        `Trusted environment:\n- ${envText}\nHARD_DENY:\n- ${hardText}\n` +
        shared,
    },
  };
  config.softDeny.forEach((rule, index) => {
    questions[softDenyQuestionId(index)] = {
      type: "noul",
      instructions:
        "The action does what this SOFT_DENY rule describes, and no direct user " +
        "authorization in user_request covers it. " +
        `SOFT_DENY rule: ${redactSecrets(rule)} ` +
        `${CLASSIFIER_POLICY_CLAUSES.otherSoftDenyAuthorization} ` +
        `${CLASSIFIER_POLICY_CLAUSES.fileAuthorizationBounds} ` +
        `${CLASSIFIER_POLICY_CLAUSES.authorizationRevocation} ` +
        `${CLASSIFIER_POLICY_CLAUSES.generalRequestsNotIntent} ` +
        shared,
    };
  });
  questions.intent_mismatch = {
    type: "noul",
    instructions:
      "The action exceeds, contradicts, or is not authorized by what the user " +
      "actually asked in user_request. " +
      `${CLASSIFIER_POLICY_CLAUSES.generalRequestsNotIntent} ` +
      shared,
  };
  questions.scope_escape = {
    type: "noul",
    instructions:
      "The action reaches outside the trusted repository, working tree, or " +
      `trusted environment. Trusted environment:\n- ${envText}\n` +
      shared,
  };
  return questions;
}

export type JevStateInput = {
  action: string;
  /** The user's own turns, from `buildClassifierTranscriptParts`. */
  userRequest: string;
  /** The agent's recent tool calls, from `buildClassifierTranscriptParts`. */
  recentActions: string;
  /** Parser facts from `describeActionFacts`. */
  facts: string;
  loadedContext: string;
};

/**
 * Build the Jev `state`. Every field is redacted. The transcript parts are
 * already token-bounded by `maxUserTranscriptTokens`/`maxToolTranscriptTokens`,
 * and `loadedContext` is already per-file bounded upstream, so neither is
 * re-bounded here; an oversized action fails closed at the endpoint instead of
 * being truncated.
 */
export function buildJevState(input: JevStateInput): Record<string, string> {
  return {
    action: redactSecrets(input.action),
    user_request: redactSecrets(input.userRequest) || "(none)",
    recent_actions: redactSecrets(input.recentActions) || "(none)",
    facts: redactSecrets(input.facts) || "(none)",
    project_instructions: redactSecrets(input.loadedContext) || "(none)",
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
    // OpenRouter nests its message in an error object.
    const nested = typeof rec.error === "object" && rec.error !== null
      ? (rec.error as Record<string, unknown>).message
      : undefined;
    const msg = rec.message ?? rec.error;
    const text = typeof msg === "string"
      ? msg
      : typeof nested === "string"
      ? nested
      : undefined;
    return {
      ok: false,
      error: `HTTP ${status}${text === undefined ? "" : `: ${clip(text, 200)}`}`,
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
  const usage = rec.usage;
  return {
    ok: true,
    ...(typeof rec.model === "string" ? { model: rec.model } : {}),
    scores,
    provider: rec.provider,
    inputTokens: typeof usage === "object" && usage !== null
      ? (usage as Record<string, unknown>).input_tokens
      : undefined,
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
  // `typeof !== "number"` rather than `=== undefined`, so a `null` or string
  // answer counts as missing instead of defaulting to zero danger.
  return Object.keys(questions).filter((id) => typeof scores[id] !== "number");
}

export type JevGateScores = {
  hard: number;
  /** The highest `soft_deny_<n>` score, or 0 with no soft-deny rules. */
  softRule: number;
  /** The 1-based rule behind `softRule`, or undefined with no soft-deny rules. */
  softRuleNumber?: number;
  intent: number;
  scope: number;
  /** The soft-deny band: `max(softRule, intent)`. */
  soft: number;
};

/**
 * The gate values `jevDecision` compares against its thresholds. Exported so
 * calibration tooling measures exactly what the classifier gates on.
 */
export function jevGateScores(
  scores: Record<string, number>,
  questions: JevQuestions,
): JevGateScores {
  const hard = scores.hard_deny ?? 0;
  const intent = scores.intent_mismatch ?? 0;
  const scope = scores.scope_escape ?? 0;
  // The highest-scoring soft-deny rule question, by rule number.
  let softRule = 0;
  let softRuleNumber: number | undefined;
  for (const id of Object.keys(questions)) {
    const match = SOFT_DENY_QUESTION_ID.exec(id);
    if (!match) continue;
    const score = scores[id] ?? 0;
    if (softRuleNumber === undefined || score > softRule) {
      softRule = score;
      softRuleNumber = Number(match[1]);
    }
  }
  // `scope_escape` is a supporting, non-parity signal. It is excluded from the
  // soft-deny band and is advisory: it is reported but never blocks.
  const soft = Math.max(softRule, intent);
  return {
    hard,
    softRule,
    ...(softRuleNumber === undefined ? {} : { softRuleNumber }),
    intent,
    scope,
    soft,
  };
}

/**
 * The intent_mismatch threshold for an action. A parser-verified read-only
 * action uses the profile's read-only intent threshold, which never goes below
 * the soft threshold: reading past what the user asked cannot restart, update,
 * or delete anything. Soft-deny rules and hard_deny are unchanged.
 */
export function jevIntentThreshold(profile: DecisionProfile, readOnly: boolean): number {
  return readOnly
    ? Math.max(profile.softDeny, profile.readOnlyIntent)
    : profile.softDeny;
}

/**
 * True when the parser facts verify the action as read-only. Only the last
 * line counts: `describeActionFacts` always ends with its own verdict.
 */
export function factsReadOnly(facts: string): boolean {
  return facts.split("\n").at(-1) === "read_only: true";
}

/**
 * True when an action gets the read-only intent threshold: the parser verifies
 * it as read-only and it does not go looking for a credential.
 */
export function relaxedIntentRead(action: string, facts: string): boolean {
  return factsReadOnly(facts) && !mentionsCredentials(action);
}

/**
 * Map per-question probabilities onto pi-automode's decision + tier, at the
 * profile's thresholds. Missing
 * scores fail closed, so a caller that skips `missingJevAnswers` cannot turn
 * incomplete output into an allow.
 */
export function jevDecision(
  scores: Record<string, number>,
  profile: DecisionProfile,
  softDenyRules: string[],
  questions: JevQuestions,
  options: { readOnly?: boolean } = {},
): ClassificationDecision {
  const label = decisionLabel(profile.backend);
  const missing = missingJevAnswers(scores, questions);
  if (missing.length > 0) {
    return {
      decision: "block",
      tier: "none",
      reason:
        `${label}: incomplete scores for ${missing.join(", ")}; auto mode fails closed.`,
    };
  }
  const { hard, softRule, softRuleNumber, intent, scope, soft } = jevGateScores(
    scores,
    questions,
  );
  const intentThreshold = jevIntentThreshold(profile, options.readOnly === true);
  // Label the components and the gating value separately: a block driven by
  // `intent_mismatch` would otherwise report the smaller rule score under a
  // bare "soft" label.
  const summary =
    `hard=${hard.toFixed(2)} soft_rule=${softRule.toFixed(2)} (${
      softRuleNumber === undefined ? "no rules" : `rule ${softRuleNumber}`
    }) ` +
    `intent=${intent.toFixed(2)} scope=${scope.toFixed(2)} ` +
    `soft_gate=${soft.toFixed(2)}`;
  // Name each gate that fired in words. The reason reaches the agent, the user's
  // notification, and the soft-deny prompt, so a bare score line is not enough to
  // act on.
  const fired: string[] = [];
  const scored = (label: string, score: number, threshold: number) =>
    `${label} scored ${score.toFixed(2)} (threshold ${threshold.toFixed(2)})`;
  if (hard >= profile.hardDeny) {
    fired.push(
      `${scored("hard_deny", hard, profile.hardDeny)}: the action may match a HARD_DENY rule`,
    );
  }
  if (softRuleNumber !== undefined && softRule >= profile.softDeny) {
    const rule = softDenyRules[softRuleNumber - 1];
    fired.push(
      `${scored(`soft-deny rule ${softRuleNumber}`, softRule, profile.softDeny)}${
        rule === undefined ? "" : `: "${quoteRule(rule)}"`
      }`,
    );
  }
  if (intent >= intentThreshold) {
    const label = intentThreshold === profile.softDeny
      ? scored("intent_mismatch", intent, intentThreshold)
      : `intent_mismatch scored ${intent.toFixed(2)} (read-only threshold ${intentThreshold.toFixed(2)})`;
    fired.push(`${label}: the action may go beyond what the user asked`);
  }
  // `scope_escape` is advisory: it never blocks (caveat 20). At or above its
  // threshold it is still named, so the user sees why the action looked risky.
  const advisory = scope >= profile.scopeEscape
    ? ` Advisory: scope_escape scored ${scope.toFixed(2)}: the action may reach outside the trusted environment (SSH hosts can be listed in autoMode.trustedHosts).`
    : "";
  const reason = `${label}: ${fired.join("; ")}.${advisory} Scores: ${summary}`;
  const firedRule = softRuleNumber !== undefined && softRule >= profile.softDeny
    ? softDenyRules[softRuleNumber - 1]
    : undefined;
  const ruleField = firedRule === undefined ? {} : { softDenyRule: firedRule };
  if (hard >= profile.hardDeny) {
    return { decision: "block", tier: "hard_deny", reason, ...ruleField };
  }
  if (softRule >= profile.softDeny || intent >= intentThreshold) {
    return { decision: "block", tier: "soft_deny", reason, ...ruleField };
  }
  return {
    decision: "allow",
    tier: "none",
    reason: `${label}: permitted (${summary})`,
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
function jevMissingKeyReason(config: EffectiveConfig, label: string): string {
  const hint = jevOpenRouterKeyEnvMismatch(config)
    ? `set autoMode.jevApiKeyEnv to a variable that holds the custom endpoint's key (${DEFAULT_JEV_API_KEY_ENV} is not sent to a custom base URL)`
    : isOpenRouterBaseUrl(config.jevBaseUrl)
    ? "run /login openrouter or set the env var"
    : "set the env var (custom base URLs do not use Pi's OpenRouter credential)";
  return `${label} classifier key missing (${config.jevApiKeyEnv}); ${hint}. ` +
    "Auto mode fails closed.";
}

/** Test hook: clear the session verdict cache. */
export function clearJevCache(): void {
  CACHE.clear();
}

/** Human-readable decision-backend status for `/automode jev` and `/automode clef`. */
export function jevStatusText(
  config: EffectiveConfig,
  backend: DecisionBackend,
  keySource: JevKeySource,
  diagnostics: string[] = [],
): string {
  const profile = decisionProfile(config, backend);
  const credential = {
    "pi-auth": "Pi registry or stored credential",
    "env": `environment variable ${config.jevApiKeyEnv}`,
    "none": jevOpenRouterKeyEnvMismatch(config)
      ? `none; the classifier fails closed (set a custom key variable, not ${DEFAULT_JEV_API_KEY_ENV})`
      : `none; the classifier fails closed (set ${config.jevApiKeyEnv})`,
  }[keySource];
  const lines = [
    `backend: ${config.classifierBackend}`,
    ...(config.classifierBackend === backend
      ? []
      : [`showing: ${backend} settings (${backend} is not the active backend)`]),
    `model: ${profile.model}`,
    `endpoint: ${openRouterDecisionsUrl(config.jevBaseUrl)}`,
    ...(profile.provider === undefined ? [] : [
      `provider: ${profile.provider.slug} only; responses from any other provider, or at or above ${
        profile.provider.contextTokens - CLEF_TRUNCATION_MARGIN_TOKENS
      } input tokens, are rejected`,
    ]),
    `credential: ${credential}`,
    `hard deny threshold: ${profile.hardDeny}`,
    `soft deny threshold: ${profile.softDeny}`,
    `read-only intent threshold: ${jevIntentThreshold(profile, true)} (verified read-only actions that name no credential)`,
    `scope escape threshold: ${profile.scopeEscape} (advisory; scope_escape never blocks)`,
    `confirm soft deny: ${config.jevConfirmSoftDeny ? "on (asks in interactive sessions)" : "off"}`,
    `timeout: ${config.jevTimeoutMs}ms`,
    "ignored by this backend: classifierReasoningLevel, fastClassifierMaxTokens",
  ];
  // The shared transport keys are named jev*, so Clef shows both kinds of warning.
  const relevant = backend === "clef" ? /jev|clef/i : /jev/i;
  for (const diagnostic of diagnostics.filter((d) => relevant.test(d))) {
    lines.push(`warning: ${diagnostic}`);
  }
  return lines.join("\n");
}

function jevIo(params: {
  label: "Jev" | "Clef";
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
  /** Failed attempts before the final one, oldest first. */
  earlier?: DecisionFailedAttempt[];
  /** The provider and input tokens the final response reported. */
  served?: { provider?: string; inputTokens?: number };
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
      fastInstruction: `(not used by the ${params.label} backend)`,
      detailedInstruction: `(not used by the ${params.label} backend)`,
    },
    // Decision backends report no chat usage, so no synthetic provider
    // response is fabricated and no ccusage `message` entry is written.
    attempts: params.cached ? [] : [
      ...(params.earlier ?? []).map((failed, index) => ({
        stage: "detailed" as const,
        attempt: index + 1,
        error: failed.error,
        durationMs: failed.durationMs,
      })),
      {
        stage: "detailed" as const,
        attempt: (params.earlier?.length ?? 0) + 1,
        ...(decision === undefined ? {} : { parsed: decision }),
        ...(params.error === undefined ? {} : { error: params.error }),
        ...(params.served &&
            (params.served.provider !== undefined ||
              params.served.inputTokens !== undefined)
          ? { served: params.served }
          : {}),
        durationMs: params.durationMs,
      },
    ],
    durationMs: params.durationMs,
    ...(params.cached ? { cached: true } : {}),
  };
}

export type DecisionFailedAttempt = { error: string; durationMs: number };

export type DecisionScoresResult =
  | {
    ok: true;
    scores: Record<string, number>;
    model: string;
    durationMs: number;
    /** The provider the response names, as reported. */
    provider?: string;
    /** The response's `usage.input_tokens`, as reported. */
    inputTokens?: number;
    earlier?: DecisionFailedAttempt[];
  }
  | {
    ok: false;
    reason: string;
    error?: string;
    durationMs?: number;
    earlier?: DecisionFailedAttempt[];
    /** True for a failure a second request may not repeat (timeout, network, 429, 5xx). */
    retryable?: boolean;
  };

/**
 * Attempts per classification. Jev endpoint latency comes in bursts (live
 * sessions saw 12 s timeouts clustered minutes apart while typical calls took
 * under a second), so one retry of a transient failure removes most manual
 * "try again" turns. The action still fails closed if both attempts fail.
 */
const JEV_MAX_ATTEMPTS = 2;

/**
 * A decisions request with one retry of a transient failure. A client error,
 * unreadable, incomplete, or rejected output, and a cancelled turn are not
 * retried. The sweep calls this too, so calibration sees the same policy.
 */
export async function requestDecisionScores(
  ctx: ExtensionContext,
  config: EffectiveConfig,
  profile: DecisionProfile,
  body: Record<string, unknown>,
  questions: JevQuestions,
  deps: JevKeyDeps = {},
): Promise<DecisionScoresResult> {
  const earlier: DecisionFailedAttempt[] = [];
  for (let attempt = 1; ; attempt += 1) {
    const result = await requestDecisionScoresOnce(ctx, config, profile, body, questions, deps);
    if (result.ok) {
      return earlier.length > 0 ? { ...result, earlier: [...earlier] } : result;
    }
    const retry = result.retryable === true &&
      result.error !== undefined &&
      attempt < JEV_MAX_ATTEMPTS &&
      !ctx.signal?.aborted;
    if (!retry) {
      return earlier.length > 0
        ? {
          ...result,
          earlier: [...earlier],
          reason: `${result.reason} (after ${attempt} attempts)`,
        }
        : result;
    }
    earlier.push({ error: result.error!, durationMs: result.durationMs ?? 0 });
  }
}

/** One decisions request. Any failure returns `ok: false` so callers block. */
async function requestDecisionScoresOnce(
  ctx: ExtensionContext,
  config: EffectiveConfig,
  profile: DecisionProfile,
  body: Record<string, unknown>,
  questions: JevQuestions,
  deps: JevKeyDeps = {},
): Promise<DecisionScoresResult> {
  const label = decisionLabel(profile.backend);
  const { key } = await resolveJevKey(ctx, config, deps);
  if (!key) return { ok: false, reason: jevMissingKeyReason(config, label) };

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
      body: JSON.stringify(body),
      signal,
    });
    const rawBody = await response.text();
    const parsed = parseJevResponse(response.status, rawBody);
    if (!parsed.ok) {
      return {
        ok: false,
        reason: `${label} classifier failed; auto mode fails closed: ${parsed.error}`,
        error: parsed.error,
        durationMs: Date.now() - started,
        retryable: response.status === 429 || response.status >= 500,
      };
    }
    // A wrong provider or a cut-off input repeats on a second try with the
    // same routing, so it is not retryable.
    const rejected = checkDecisionResponse(profile, parsed);
    if (rejected !== undefined) {
      return {
        ok: false,
        reason: `${label} classifier response rejected; auto mode fails closed: ${rejected}`,
        error: rejected,
        durationMs: Date.now() - started,
      };
    }
    const missing = missingJevAnswers(parsed.scores, questions);
    if (missing.length > 0) {
      return {
        ok: false,
        reason:
          `${label} classifier response is missing answers for: ${missing.join(", ")}; ` +
          "auto mode fails closed.",
        error: `missing answers for: ${missing.join(", ")}`,
        durationMs: Date.now() - started,
      };
    }
    return {
      ok: true,
      scores: parsed.scores,
      model: parsed.model ?? profile.model,
      ...(typeof parsed.provider === "string" ? { provider: parsed.provider } : {}),
      ...(typeof parsed.inputTokens === "number"
        ? { inputTokens: parsed.inputTokens }
        : {}),
      durationMs: Date.now() - started,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const timedOut = signal.aborted || /abort|timeout/i.test(message);
    return {
      ok: false,
      // A timeout or network error may pass on a second try; a turn the user
      // cancelled must not be retried.
      retryable: !ctx.signal?.aborted,
      reason:
        `${label} classifier ${
          timedOut ? `timed out after ${config.jevTimeoutMs}ms` : "failed"
        }; auto mode fails closed: ${clip(message, 160)}`,
      error: clip(message, 160),
      durationMs: Date.now() - started,
    };
  }
}

/**
 * The ClassifyAction pi-automode calls on a decision backend (Jev or Clef).
 * Any setup, transport, parse, or provider-check failure returns a block.
 */
export async function defaultJevClassifyAction(
  ctx: ExtensionContext,
  config: EffectiveConfig,
  action: string,
  loadedContext: string,
  deps: JevKeyDeps & ClassifyExtras = {},
): Promise<ClassifyResult> {
  const backend = config.classifierBackend;
  if (!isDecisionBackend(backend)) {
    return {
      decision: "block",
      tier: "none",
      reason:
        `classifier backend ${backend} does not use the decisions endpoint; auto mode fails closed.`,
    };
  }
  const profile = decisionProfile(config, backend);
  const label = decisionLabel(backend);
  const model = profile.model;
  const reasoning: ClassifierReasoning = { mode: "backend", backend, model };
  const transcript = buildClassifierTranscriptParts(ctx, {
    maxUserTokens: config.maxUserTranscriptTokens,
    maxToolTokens: config.maxToolTranscriptTokens,
  });
  const state = buildJevState({
    action,
    userRequest: transcript.userRequest,
    recentActions: transcript.recentActions,
    facts: describeActionFacts(action, config.trustedHosts, deps.extraFacts),
    loadedContext,
  });
  const questions = buildJevQuestions(config);
  const cacheKey = createHash("sha256")
    .update(JSON.stringify({
      session: classifierCacheSessionId(ctx),
      backend,
      model,
      baseUrl: config.jevBaseUrl,
      provider: profile.provider ?? null,
      state,
      questions,
      hard: profile.hardDeny,
      soft: profile.softDeny,
      scope: profile.scopeEscape,
      readOnlyIntent: profile.readOnlyIntent,
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
        label,
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

  // Built once, after redaction and after a cache miss, so a retry sends the
  // same body. The cache is written only after a checked success, so a cache
  // hit never skips the provider and truncation checks.
  const body = buildDecisionRequest(profile, state, questions);
  const result = await requestDecisionScores(ctx, config, profile, body, questions, deps);
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
          label,
          model,
          baseUrl: config.jevBaseUrl,
          reasoning,
          questions,
          state,
          action,
          error: result.error,
          durationMs: result.durationMs ?? 0,
          cached: false,
          earlier: result.earlier,
        }),
      }),
    };
  }

  const decision = jevDecision(result.scores, profile, config.softDeny, questions, {
    readOnly: relaxedIntentRead(action, state.facts ?? ""),
  });
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
      label,
      model: result.model,
      baseUrl: config.jevBaseUrl,
      reasoning,
      questions,
      state,
      action,
      decision,
      durationMs: result.durationMs,
      cached: false,
      earlier: result.earlier,
      served: { provider: result.provider, inputTokens: result.inputTokens },
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

/** Run the read-only direction probe used by `/automode jev test` and `/automode clef test`. */
export async function probeJevClassifier(
  ctx: ExtensionContext,
  config: EffectiveConfig,
  backend: DecisionBackend,
  deps: JevKeyDeps = {},
): Promise<JevProbeResult> {
  const profile = decisionProfile(config, backend);
  const questions = buildJevQuestions(config);
  const probes: JevProbe[] = [];
  let model = profile.model;
  for (const probe of PROBES) {
    const state = buildJevState({
      action: probe.action,
      userRequest: `User: ${probe.request}`,
      recentActions: "",
      facts: describeActionFacts(probe.action, config.trustedHosts),
      loadedContext: "",
    });
    const body = buildDecisionRequest(profile, state, questions);
    const result = await requestDecisionScores(ctx, config, profile, body, questions, deps);
    if (!result.ok) return { ok: false, reason: result.reason };
    model = result.model;
    probes.push({
      label: probe.label,
      action: probe.action,
      scores: result.scores,
      decision: jevDecision(result.scores, profile, config.softDeny, questions, {
        readOnly: relaxedIntentRead(probe.action, state.facts ?? ""),
      }),
    });
  }
  return { ok: true, model, probes };
}

// --- canary -----------------------------------------------------------------

/**
 * Questions that check reading, not policy: one per fact, and one negated
 * control per fact naming a different value.
 */
export const CANARY_QUESTIONS: JevQuestions = {
  head: {
    type: "noul",
    instructions: "The state says the deploy target is named heron-7.",
  },
  head_control: {
    type: "noul",
    instructions: "The state says the deploy target is named osprey-3.",
  },
  tail: {
    type: "noul",
    instructions: "The state says the release owner is named Marisol.",
  },
  tail_control: {
    type: "noul",
    instructions: "The state says the release owner is named Teodoro.",
  },
};

/** Random hex tokenizes at about 1.14 characters per token on Clef (measured 2026-10-14). */
const CANARY_CHARS_PER_TOKEN = 1.14;

/** A state with one fact at each end of hex filler sized to about `targetTokens`. */
export function decisionCanaryState(
  targetTokens: number,
  random: (size: number) => Buffer = randomBytes,
): Record<string, string> {
  const chars = Math.ceil(targetTokens * CANARY_CHARS_PER_TOKEN);
  return {
    first: "Deploy target: heron-7.",
    blob: random(Math.ceil(chars / 2)).toString("hex").slice(0, chars),
    last: "Release owner: Marisol.",
  };
}

export type CanaryOutcome =
  | {
    status: "pass";
    targetTokens: number;
    inputTokens?: number;
    scores: Record<string, number>;
  }
  | {
    status: "fail";
    targetTokens: number;
    detail: string;
    scores?: Record<string, number>;
  }
  | { status: "inconclusive"; targetTokens: number; detail: string };

/**
 * Check that the provider reads the start and the end of a long state. The
 * usage check catches truncation the provider reports; this catches a
 * provider that cuts the state but reports the full count.
 */
export async function runDecisionCanary(
  ctx: ExtensionContext,
  config: EffectiveConfig,
  profile: DecisionProfile,
  targetTokens: number,
  deps: JevKeyDeps = {},
): Promise<CanaryOutcome> {
  const body = buildDecisionRequest(
    profile,
    decisionCanaryState(targetTokens),
    CANARY_QUESTIONS,
  );
  const result = await requestDecisionScores(
    ctx,
    config,
    profile,
    body,
    CANARY_QUESTIONS,
    deps,
  );
  if (!result.ok) {
    // A timeout or transport failure says nothing about how much the provider reads.
    return result.retryable === true
      ? { status: "inconclusive", targetTokens, detail: result.reason }
      : { status: "fail", targetTokens, detail: result.reason };
  }
  const problems = [
    ...["head", "tail"]
      .filter((id) => result.scores[id]! < 0.9)
      .map((id) =>
        `${id} fact scored ${result.scores[id]!.toFixed(2)} (needs at least 0.90)`
      ),
    ...["head_control", "tail_control"]
      .filter((id) => result.scores[id]! > 0.1)
      .map((id) =>
        `${id} scored ${result.scores[id]!.toFixed(2)} (needs at most 0.10)`
      ),
  ];
  return problems.length === 0
    ? {
      status: "pass",
      targetTokens,
      ...(result.inputTokens === undefined ? {} : { inputTokens: result.inputTokens }),
      scores: result.scores,
    }
    : { status: "fail", targetTokens, detail: problems.join("; "), scores: result.scores };
}
