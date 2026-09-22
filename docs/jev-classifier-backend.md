# Enhancing pi-automode with the Jev classifier backend

Status: **implemented** — this is the design record for the shipped Jev backend.

The shipped implementation is authoritative: `extensions/auto-mode/jev.ts`,
`config.ts`, `types.ts`, `constants.ts`, and `extension.ts`. The code blocks
below are the original proposal sketch and intentionally close to, but not
guaranteed identical with, what shipped (for example, the final `jev.ts` adds
a session-scoped cache key, `JevKeyDeps` test seams, missing-answer
validation, and an OpenRouter-host guard on credential use). When they
diverge, trust the source files.
Scope: add an opt-in classifier backend that uses the Jev / SystemOne
classifier (via OpenRouter) for intent, in place of the LLM classifier stage.

## TL;DR

Jev replaces **only** the classifier stage (`ClassifyAction`). Everything above
it stays authoritative and untouched:

- `permissions.deny` / `permissions.ask` / `permissions.allow`
- `deterministicHardDeny` (AST, paths, root deletes, persistence, TLS, etc.)
- `deniedPaths`
- the read-only and inside-working-directory allow tiers

Jev's hard-deny answer is *advisory*; the deterministic layer is the
unconditional floor. Any Jev error, missing key, or unparseable response
**fails closed** (block), matching pi-automode's default posture.

Opt in with `"classifierBackend": "jev"`. Default stays `"llm"`, so nothing
changes until configured.

## Why this is a backend swap, not a prompt rewrite

Jev is not an LLM. Its mechanics differ enough that porting the existing
classifier prompt does not work.

| LLM classifier (today) | Jev |
| --- | --- |
| system prompt + chat messages + streaming | `POST {model, state, questions}` — no prompt, no chat |
| tool call `classifier_decision` with `{decision,tier,reason}` | `answers: {id: {noul: 0..1}}` probabilities |
| fast 1-token gate → detailed stage | one request, per-question scores |
| free-form reason text | no text; the reason/tier is synthesized |
| non-deterministic | deterministic per `(state, questions)` → cacheable |
| `reasoning`, `fastClassifierMaxTokens` apply | both are meaningless for Jev |

Consequences:

- Policy rules go into each question's `instructions`.
- Action + intent + project context go into `state`.
- Probabilities are mapped onto pi-automode's `tier` enum locally.
- The one-token pre-filter and reasoning-level plumbing are skipped.

## Reference implementation

The Jev mechanics are taken from `specpi-jev-guard`
(`extensions/risk-rules.ts`, `extensions/jev-guard.ts`, `extensions/pi-auth.ts`):

- `buildSystemOneBody` → `{model, state, questions}`
- `openRouterDecisionsUrl` maps a chat base URL to `/api/alpha/decisions`
- `TYPESAFE_QUESTIONS` shows the `noul` question shape
- `parseSystemOneResponse` shows the `answers[id].noul` response shape
- `credentialKey` / `readStoredCredential` show credential resolution

## Implementation checklist

1. [x] `types.ts`: add config fields, `EffectiveConfig` fields, and a
   `ClassifierReasoning` variant for the Jev backend.
2. [x] `constants.ts`: add Jev defaults.
3. [x] `config.ts`: validate, merge, and default the new keys; generalize
   global model persistence.
4. [x] `jev.ts` (new): client, questions, state, parser, decision mapping,
   key resolution, `defaultJevClassifyAction`.
5. [x] `extension.ts`: select the backend per call; report it in status/logs;
   add `/automode backend`.
6. [x] Tests: parser, thresholds, redaction, backend selection, and a
   hard-deny regression corpus.
7. [x] `npm test && npm run check`.

---

## 1. Config and types

### `extensions/auto-mode/types.ts`

Add to `AutoModeSettings`:

```ts
  classifierBackend?: "llm" | "jev";
  jevModel?: string;              // default "~typesafe/jev-latest"
  jevBaseUrl?: string;            // default "https://openrouter.ai/api/v1"
  jevApiKeyEnv?: string;          // default "OPENROUTER_API_KEY"
  jevTimeoutMs?: number;          // default 12000
  jevHardDenyThreshold?: number;  // default 0.5
  jevSoftDenyThreshold?: number;  // default 0.35
```

Add the same fields (resolved, non-optional) to `EffectiveConfig`:

```ts
  classifierBackend: "llm" | "jev";
  jevModel: string;
  jevBaseUrl: string;
  jevApiKeyEnv: string;
  jevTimeoutMs: number;
  jevHardDenyThreshold: number;
  jevSoftDenyThreshold: number;
```

Extend `ClassifierReasoning` so the log can report the backend without
pretending it has an LLM reasoning level:

```ts
export type ClassifierReasoning =
  | { mode: "server-default" }
  | {
    mode: "explicit";
    requestedLevel: ClassifierReasoningLevel;
    effectiveLevel: EffectiveClassifierReasoningLevel;
  }
  | { mode: "backend"; backend: "jev"; model: string };
```

`ClassifierReasoningLog` already unions over `ClassifierReasoning`, so no
further change is needed there.

### `extensions/auto-mode/constants.ts`

```ts
export const DEFAULT_CLASSIFIER_BACKEND = "llm" as const;
export const DEFAULT_JEV_MODEL = "~typesafe/jev-latest";
export const DEFAULT_JEV_BASE_URL = "https://openrouter.ai/api/v1";
export const DEFAULT_JEV_API_KEY_ENV = "OPENROUTER_API_KEY";
export const DEFAULT_JEV_TIMEOUT_MS = 12_000;
export const DEFAULT_JEV_HARD_DENY_THRESHOLD = 0.5;
export const DEFAULT_JEV_SOFT_DENY_THRESHOLD = 0.35;
```

### `extensions/auto-mode/config.ts`

- Add the new keys to the `knownAutoMode` set (so they are not reported as
  unknown).
- Add validation:

```ts
if (
  hasOwn(autoMode, "classifierBackend") &&
  autoMode.classifierBackend !== "llm" && autoMode.classifierBackend !== "jev"
) {
  diagnostics.push(`${source}: autoMode.classifierBackend must be "llm" or "jev"`);
}
if (hasOwn(autoMode, "jevModel") && !isValidClassifierModel(autoMode.jevModel)) {
  diagnostics.push(`${source}: autoMode.jevModel must be a provider/model string`);
}
if (
  hasOwn(autoMode, "jevTimeoutMs") &&
  (!Number.isInteger(autoMode.jevTimeoutMs) ||
    (autoMode.jevTimeoutMs as number) < 1000 ||
    (autoMode.jevTimeoutMs as number) > MAX_CLASSIFIER_TIMEOUT_MS)
) {
  diagnostics.push(
    `${source}: autoMode.jevTimeoutMs must be an integer from 1000 through ${MAX_CLASSIFIER_TIMEOUT_MS}`,
  );
}
for (const key of ["jevHardDenyThreshold", "jevSoftDenyThreshold"] as const) {
  const value = autoMode[key];
  if (hasOwn(autoMode, key) &&
      (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 1)) {
    diagnostics.push(`${source}: autoMode.${key} must be a number from 0 through 1`);
  }
}
```

- Merge in `applyAutoModeScalars`:

```ts
    classifierBackend: settings.classifierBackend === "llm" || settings.classifierBackend === "jev"
      ? settings.classifierBackend
      : base.classifierBackend,
    jevModel: isValidClassifierModel(settings.jevModel) ? settings.jevModel : base.jevModel,
    jevBaseUrl: typeof settings.jevBaseUrl === "string" && settings.jevBaseUrl.trim() !== ""
      ? settings.jevBaseUrl.replace(/\/+$/, "")
      : base.jevBaseUrl,
    jevApiKeyEnv: typeof settings.jevApiKeyEnv === "string" && settings.jevApiKeyEnv.trim() !== ""
      ? settings.jevApiKeyEnv
      : base.jevApiKeyEnv,
    jevTimeoutMs: validClassifierTimeout(settings.jevTimeoutMs)
      ? settings.jevTimeoutMs
      : base.jevTimeoutMs,
    jevHardDenyThreshold:
      typeof settings.jevHardDenyThreshold === "number" &&
      settings.jevHardDenyThreshold >= 0 && settings.jevHardDenyThreshold <= 1
        ? settings.jevHardDenyThreshold
        : base.jevHardDenyThreshold,
    jevSoftDenyThreshold:
      typeof settings.jevSoftDenyThreshold === "number" &&
      settings.jevSoftDenyThreshold >= 0 && settings.jevSoftDenyThreshold <= 1
        ? settings.jevSoftDenyThreshold
        : base.jevSoftDenyThreshold,
```

- Seed the base config in `buildEffectiveConfigFromSources`:

```ts
    classifierBackend: DEFAULT_CLASSIFIER_BACKEND,
    jevModel: DEFAULT_JEV_MODEL,
    jevBaseUrl: DEFAULT_JEV_BASE_URL,
    jevApiKeyEnv: DEFAULT_JEV_API_KEY_ENV,
    jevTimeoutMs: DEFAULT_JEV_TIMEOUT_MS,
    jevHardDenyThreshold: DEFAULT_JEV_HARD_DENY_THRESHOLD,
    jevSoftDenyThreshold: DEFAULT_JEV_SOFT_DENY_THRESHOLD,
```

- Generalize global model persistence so `/automode model` can write
  `jevModel` when the backend is Jev. Either add a sibling function:

```ts
export function writeGlobalJevModel(jevModel: string, path = PI_GLOBAL_SETTINGS[0]): void {
  const settings = readWritableSettingsFile(path);
  const next: SettingsFile = {
    ...settings,
    autoMode: { ...settings.autoMode, jevModel },
  };
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(next, null, 2)}\n`, "utf8");
}
```

  or refactor both into `writeGlobalAutoModeSetting(key, value)`.

---

## 2. New module: `extensions/auto-mode/jev.ts`

```ts
/**
 * jev.ts — Jev classifier backend for pi-automode.
 *
 * Jev is not an LLM: it takes a bounded `state` object and `noul`
 * probability questions and returns a 0..1 score per question. Policy text
 * lives in each question's `instructions`; context lives in `state`.
 * Deterministic layers run before this action and stay authoritative.
 */
import { createHash } from "node:crypto";
import { readStoredCredential } from "@earendil-works/pi-coding-agent";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { Usage } from "@earendil-works/pi-ai";
import { buildClassifierTranscript } from "./transcript.ts";
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
  | { ok: true; model: string; scores: Record<string, number>; danger: number }
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
  return typeof value === "string" && value.trim() !== "" ? value.trim() : undefined;
}

export function credentialKey(credential: unknown): string | undefined {
  if (typeof credential !== "object" || credential === null) return undefined;
  const rec = credential as Record<string, unknown>;
  if (rec.type === "oauth") return nonEmpty(rec.access);
  if (rec.type !== "api_key") return undefined;
  const raw = nonEmpty(rec.key);
  return raw === undefined || raw.startsWith("!") ? undefined : raw;
}

// --- endpoint + payload ----------------------------------------------------

/** Default base https://openrouter.ai/api/v1 -> .../api/alpha/decisions. */
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
        "actually asked in user_request. General requests (\"clean up the repo\") " +
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
    action: clip(redactSecrets(action), ACTION_MAX),
    working_directory: cwd,
    user_request: clip(redactSecrets(intent), INTENT_MAX) || "(none)",
    project_instructions: clip(redactSecrets(loadedContext || "(none)"), INTENT_MAX),
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
      error: `HTTP ${status}${typeof msg === "string" ? `: ${clip(msg, 200)}` : ""}`,
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
  return { decision: "allow", tier: "none", reason: `Jev: permitted (${summary})` };
}

// --- key resolution: pi registry -> env -> stored auth.json ----------------

export async function resolveJevKey(
  ctx: ExtensionContext,
  config: EffectiveConfig,
): Promise<{ key?: string; source: "pi-auth" | "env" | "none" }> {
  try {
    const viaRegistry = await ctx.modelRegistry?.getApiKeyForProvider("openrouter");
    if (typeof viaRegistry === "string" && viaRegistry.trim() !== "") {
      return { key: viaRegistry.trim(), source: "pi-auth" };
    }
  } catch {
    // fall through
  }
  const env = process.env[config.jevApiKeyEnv];
  if (typeof env === "string" && env.trim() !== "") {
    return { key: env.trim(), source: "env" };
  }
  try {
    const stored = credentialKey(readStoredCredential("openrouter"));
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

  const { key } = await resolveJevKey(ctx, config);
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
        `Jev classifier ${timedOut ? `timed out after ${config.jevTimeoutMs}ms` : "failed"}; ` +
        `auto mode fails closed: ${clip(message, 160)}`,
    };
  }
}
```

---

## 3. Wire backend selection

### `extensions/auto-mode/extension.ts`

Imports:

```ts
import { defaultJevClassifyAction } from "./jev.ts";
```

Options:

```ts
export type PiAutomodeOptions = {
  // ...
  /** Override the Jev classifier in tests. */
  jevClassifyAction?: ClassifyAction;
};
```

Replace the single classifier binding:

```ts
// was: const classify = options.classifyAction ?? defaultClassifyAction;
const classifyLlm = options.classifyAction ?? defaultClassifyAction;
const classifyJev = options.jevClassifyAction ?? defaultJevClassifyAction;
const selectClassify = (cfg: EffectiveConfig) =>
  cfg.classifierBackend === "jev" ? classifyJev : classifyLlm;
```

Call site (currently `const decision = await classify(ctx, cfg, ...)`):

```ts
const decision = await selectClassify(cfg)(
  ctx,
  cfg,
  serializeClassifierAction(event.toolName, input),
  loadedContext,
);
```

`LogCtx.classifierModel` (currently `classifierModel: cfg.classifierModel`) must
report the backend-appropriate model:

```ts
classifierModel: cfg.classifierBackend === "jev" ? cfg.jevModel : cfg.classifierModel,
```

Both backends return the same `ClassifyResult`, so `logClassifierIo`, the
`ca:`/`cd:` status counters, denial history, and the `kind: "classifier"`
block path work unchanged.

### `extensions/auto-mode/state.ts` and status output

`/automode status` currently prints `classifier: <classifierModel ?? current
session model>`. Make it backend-aware:

```ts
classifier: ${cfg.classifierBackend === "jev"
  ? `jev (${cfg.jevModel})`
  : `llm (${cfg.classifierModel ?? "current session model"})`}
```

### `/automode backend`

Add a command that writes `autoMode.classifierBackend` to the global config
(like `classifierModel`, it is a safety control and should not come from a
shared project file):

```ts
if (command === "backend") {
  const value = remainder;
  if (value !== "llm" && value !== "jev") {
    ctx.ui.notify("Usage: /automode backend <llm|jev>", "error");
    return;
  }
  saveAutoModeSetting("classifierBackend", value); // global only
  // reload config, persist, updateUi
  ctx.ui.notify(`pi-automode classifier backend set to ${value}`, "info");
  return;
}
```

Update `/automode model` to write `jevModel` when
`effectiveConfig().classifierBackend === "jev"`.

---

## 4. Intent: what actually goes to Jev

- `user_request` = `buildClassifierTranscript(ctx, {maxUserTokens,
  maxToolTokens})`. This already selects the bounded user turns, which is what
  soft-deny's "bounded direct authorization" reasoning needs. Do not use only
  the last message.
- `project_instructions` = `loadedContext` (AGENTS.md and loaded project
  instructions).
- `action` = the full `{toolName, input}` JSON, **redacted**. Jev is a
  different third party from the model provider, and `bash`/`write` payloads
  routinely contain `.env` / token text.
- policy = `environment` / `allow` / `softDeny` / `hardDeny`, substituted into
  each question's `instructions` exactly as `buildClassifierPrompt` substitutes
  them for the LLM.

---

## 5. Thresholds and tier mapping

Defaults: `jevHardDenyThreshold = 0.5`, `jevSoftDenyThreshold = 0.35`.

The deterministic layer already covers the obvious hard-deny cases, so Jev's
hard question catches residual categories (fabricated public content, IAM/RBAC
grants, credential scanning) where a false negative is expensive — hence the
lower hard bar. Mapping:

- `hard_deny >= 0.5` → `{ block, tier: "hard_deny" }`
- `max(soft_deny_uncovered, intent_mismatch, scope_escape) >= 0.35` →
  `{ block, tier: "soft_deny" }`
- otherwise → `{ allow, tier: "none" }`

Calibrate the way `specpi-jev-guard` does: replay commands that must stop and
commands that must not, then put the thresholds in the gap. If
`explicit_intent` / `allow` tiers are wanted in the log, add a fifth
reverse-phrased question (`authorized_by_user`) and use it to pick the allow
tier — but keep all questions danger-directional or the mapping gets
error-prone.

---

## 6. Tests

`tests/jev.test.ts` covers:

- `openRouterDecisionsUrl` for `/api/v1`, an explicit decisions URL, and an
  arbitrary base.
- `parseJevResponse`: happy path, HTTP error with `message`, unreadable JSON,
  missing `answers`, empty `answers`, an array `answers`, missing `noul`, and
  clamping of out-of-range values.
- `missingJevAnswers` / end-to-end fail-closed: a response that omits any
  requested question id (including one that only returns an unrecognized id)
  blocks instead of defaulting to zero danger.
- `jevDecision`: boundaries for both thresholds, the resulting `tier`, and hard
  precedence when both bands are cleared.
- `buildJevState`: `AKIA…` / `sk-…` / private-key blocks are redacted.
- no key → block; transport error → block; malformed response → block.
- `resolveJevKey` / `isOpenRouterBaseUrl`: a custom base URL never receives
  OpenRouter registry or stored credentials.

Add a backend-selection test using `options.jevClassifyAction` with a stub
`fetch` (or a stub key resolver), asserting `classifierBackend: "jev"` routes to
the Jev action and `"llm"` routes to the LLM action.

Add a regression corpus test: run a subset of
`specpi-jev-guard/tests/jev-devious.json` through the extension with the Jev
action stubbed to realistic scores, and assert that deterministic hard-deny
still blocks even when Jev would allow. This protects the "unconditional"
guarantee.

Run:

```bash
npm test
npm run check
```

---

## 7. Caveats

1. **Never route deterministic hard-deny through Jev.** It is a probability.
   Keep the AST / permission / root-delete layer as the unconditional floor.
   This is the single most important rule.
2. Jev's hard-deny question only catches categories the deterministic layer
   does not encode — verify with the corpus test.
3. Jev returns no reason prose or tier, so audit reasons are synthesized score
   summaries; denials read slightly more mechanically.
4. Jev is priced per question; the default four is deliberate. If cost matters,
   drop `scope_escape` (it overlaps the deterministic path checks) or collapse
   to two questions and branch on `danger = max`.
5. `noul` is assumed 0..1 danger-side-up, matching `specpi-jev-guard`'s parsed
   behavior. Validate with one live call before enabling enforcement. Confirm
   the `state` field names (`action`, `user_request`) still read as intended.
6. The cache is keyed on
   `(session, model, baseUrl, state, questions, thresholds)` and is
   session-scoped, with least-recently-used eviction. Identical retried tool
   calls become free.
7. `classifierReasoningLevel` and `fastClassifierMaxTokens` do not apply to the
   Jev backend; they are reported as ignored when `classifierBackend === "jev"`.
8. Rule lists are clipped to a bounded size before they reach Jev; a truncated
   list emits a config diagnostic and a `[TRUNCATED]` marker in the question.

## 8. Configuration example

`~/.pi/agent/extensions/pi-automode/config.json`:

```json
{
  "autoMode": {
    "classifierBackend": "jev",
    "jevModel": "~typesafe/jev-latest",
    "jevBaseUrl": "https://openrouter.ai/api/v1",
    "jevApiKeyEnv": "OPENROUTER_API_KEY",
    "jevTimeoutMs": 12000,
    "jevHardDenyThreshold": 0.5,
    "jevSoftDenyThreshold": 0.35
  }
}
```

Key resolution order: pi's registry (`/login openrouter`) → env
(`OPENROUTER_API_KEY` by default) → stored `auth.json`. Missing key fails
closed.
