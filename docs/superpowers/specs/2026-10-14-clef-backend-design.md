# Clef classifier backend

Status: design, revision 3 (after two subagent reviews and a second round of live probes). Implemented on `feat/clef-backend` as experimental; the calibrated defaults and measured results are in `docs/jev-classifier-backend.md` under "Clef".

## Goal

Let a user pick Cloudflare's Clef (`cloudflare/clef` on OpenRouter) instead of Jev as pi-automode's classifier, reusing the Jev backend code, base URL, and key. Jev stays available, and stays the default model for the Jev backend. The default `classifierBackend` stays `"llm"`.

Success means:

- `classifierBackend: "clef"` classifies through the same pipeline as Jev, with Clef's own model and thresholds;
- **a Clef response that shows its input was cut off, or that came from an unconfirmed provider, blocks the action.** Detection depends on the response's `usage.input_tokens` and `provider` fields, so a provider or proxy that misreports them is a known gap (see Threats and gaps);
- with Clef's default thresholds, every `block` case in the Jev corpus blocks in every run, with a 0.05 margin (see Calibration);
- every Jev behavior keyed on the backend (session-created paths, soft-deny confirmation, the edit-tool hint) works for Clef too.

## What Clef is

Measured and read on 2026-10-14. Probe scripts are throwaway and not committed.

- Clef is a decision model, not a chat model. It takes the same request as Jev on OpenRouter's Decisions endpoint (`POST /api/alpha/decisions` with `{model, state, questions}`) and answers `noul` questions with a probability each. pi-automode's request, parser, and questions work unchanged: a probe with the real questions returned all 13 answers.
- Three providers serve it, with these advertised contexts: Cloudflare (65,536 tokens), DeepInfra (65,536), and Prime Intellect (16,384).
- **Cloudflare reads only about the first 2,000 tokens of text in `state`** and drops the rest without an error.
- **Past its context, a provider truncates silently.** It returns HTTP 200 with every answer scored low (0.12–0.20 on both facts and controls), which pi-automode would read as "allow". On every truncated response, `usage.input_tokens` equalled the provider's context exactly: 16,384 on Prime Intellect, 65,536 on DeepInfra.
- **Within its context, DeepInfra reads the whole state.** A fact at the start and a fact at the end of a 60,867-token state scored 0.98, and their negated controls 0.02–0.03. The filler was random hex, the densest text measured.
- The Decisions endpoint honours OpenRouter's `provider` preferences. `only: ["deepinfra"]` pinned DeepInfra, and `only: ["nosuchprovider"]` returned 404. `allow_fallbacks: false` is accepted and type-checked (a string value returns 400). Unknown keys in `provider` are ignored silently.
- Responses name the provider that served them (`"DeepInfra"`, `"PrimeIntellect"`) and report `usage.input_tokens`.
- `ceil(chars / 4)` is not a usable size estimate. On 8,000 characters it overestimated plain English by 9%, and underestimated base64 by 2.9×, hex by 3.5×, minified JavaScript by 2.5×, and CJK text and lockfile JSON by about 2.2×.
- pi-automode's requests measured 6,339 and 6,840 tokens on two corpus cases, and 12,787 with both transcript budgets full. The action itself is not bounded (`jev.ts:258-263`), so a large `write` can exceed any context.
- The user's account excludes Cloudflare through its zero-data-retention setting: `only: ["cloudflare"]` returned 404 for that reason. Other users may not have that setting.
- Price: $0.042 per million input tokens, nothing for output. That is about $0.0003 per classified action at 6–7K tokens, and at most $0.003 for a request that fills the context.

## Decisions

1. **A second profile, not a second client.** `jev.ts` keeps one client: questions, state, parser, retry, cache, key resolution, and fail-closed handling. A profile supplies what differs: model, thresholds, and the provider policy.
2. **A new backend value.** The user selects Clef with `classifierBackend: "clef"`. Clef gets its own model and threshold keys, so each model keeps its own calibration.
3. **Shared transport and behavior.** `jevBaseUrl`, `jevApiKeyEnv`, `jevTimeoutMs`, and `jevConfirmSoftDeny` apply to both decision backends. Their names stay as they are, and the docs say they apply to both.
4. **DeepInfra only.** Clef requests go to DeepInfra and nowhere else. Prime Intellect's 16,384-token context is smaller than a full-budget request with a modest action, and Cloudflare reads only the first 2,000 tokens. The cost is availability: while DeepInfra is down, Clef-classified actions block until it recovers or the user switches backend. Adding Prime Intellect later means a second calibration sweep and a retry that excludes it when it truncates.
5. **The provider, checked on both sides.**
   - **Request.** Every Clef request sends `provider: { only: ["deepinfra"], allow_fallbacks: false }`, on every base URL, including custom ones.
   - **Response.** A Clef response counts only if its `provider` field is a string that, lowercased and with everything but letters and digits removed, equals `deepinfra` exactly. A missing, non-string, or different provider blocks the action.
6. **A truncation check on every Clef response.** A Clef response counts only if `usage.input_tokens` is a finite number below DeepInfra's context minus a margin: `65,536 − 256`. A missing or non-numeric value blocks, and so does one at or above that bound: "Clef classifier input was cut off at N tokens (the provider's limit); auto mode fails closed." The margin covers a provider that reserves a few tokens for output; truncation measured exactly at the limit.
   - This replaces revision 2's size estimate and size tiers. It uses the provider's own count, so dense content cannot fool it.
   - There is no check before sending. An oversized request costs at most $0.003 and one round trip, then blocks.
7. **Failures from decisions 5 and 6 are not retried and never cached.** The same request would repeat the same routing and the same truncation. The cache is already safe: it is written only after a successful, checked response (`jev.ts:904`), so a cache hit never skips these checks.
8. **A head-and-tail canary.** The usage check cannot see a provider that cuts the state internally while reporting full usage (the way Cloudflare reads 2,000 tokens). The canary checks that DeepInfra still reads the whole state:
   - **State:** `first` holds one fact ("Deploy target: heron-7."), `blob` holds random hex filler sized to a target token count, and `last` holds a second fact ("Release owner: Marisol.").
   - **Questions:** one per fact, and one negated control per fact naming a different value (osprey-3, Teodoro). The canary does not use the real classifier questions. It checks reading, and the usage check covers size.
   - **Pass:** both facts at least 0.9, both controls at most 0.1, the response from DeepInfra, and the usage check passing. Any other score is a failure. A timeout or transport error is inconclusive and says so.
   - **Where it runs:** `/automode clef test` runs it once at 8,000 and once at 60,000 tokens. `jev-sweep.ts --canary --sizes <n,...> --runs N` runs it for calibration, at 8,000, 30,000, and 60,000 tokens, 3 runs each.

## Config

| Key | Backend | Default | Notes |
|---|---|---|---|
| `classifierBackend` | all | `"llm"` | accepts `"llm"`, `"jev"`, `"clef"` |
| `clefModel` | clef | `"cloudflare/clef"` | `provider/model` string, like `jevModel` |
| `clefHardDenyThreshold` | clef | from calibration | probability, like `jevHardDenyThreshold` |
| `clefSoftDenyThreshold` | clef | from calibration | |
| `clefReadOnlyIntentThreshold` | clef | from calibration | never below `clefSoftDenyThreshold`, as for Jev |
| `clefScopeEscapeThreshold` | clef | from calibration | advisory only; never blocks |
| `jevBaseUrl`, `jevApiKeyEnv`, `jevTimeoutMs`, `jevConfirmSoftDeny` | jev and clef | unchanged | shared |

- The new keys are autoMode scalars. They follow the existing source rules: global, project-local, and inline sources only (`config.ts:915-919`), never the shared project `.pi/automode.json`.
- The new keys join the `knownAutoMode` set (`config.ts:294-324`), so they get no unknown-key diagnostic, and the threshold list at `config.ts:378-381`.
- Validation messages name the new values: `autoMode.classifierBackend must be "llm", "jev", or "clef"`.
- `clefModel` joins `GLOBAL_AUTOMODE_SETTING_KEYS`, so `/automode model` can save it.
- Key diagnostics (`jevCredentialDiagnostics`) run for both decision backends.
- The provider and the truncation bound are constants, not settings. Loosening them would weaken the main guarantee.

**Placeholder thresholds.** Until calibration sets them, every `DEFAULT_CLEF_*_THRESHOLD` is `0.0`. At 0.0 every Clef-classified action blocks, so an uncalibrated build fails closed. A test asserts that no Clef default is `0.0`. It is written red in the calibration task, immediately before the measured values, and the handoff requires a green `npm test`.

## Code changes

### `types.ts` and `constants.ts`

- `ClassifierBackend = "llm" | "jev" | "clef"`, and `DecisionBackend = "jev" | "clef"`.
- `ClassifierReasoning`'s backend variant (`types.ts:23`) takes `backend: DecisionBackend`.
- The new settings go into `AutoModeSettings` and `EffectiveConfig`.
- These go into `constants.ts`, each with a comment naming the measurement that set it:
  - `DEFAULT_CLEF_MODEL` and `DEFAULT_CLEF_*_THRESHOLD`;
  - `CLEF_PROVIDER`: `{ slug: "deepinfra", name: "deepinfra", contextTokens: 65_536 }`, where `name` is the normalized response name;
  - `CLEF_TRUNCATION_MARGIN_TOKENS = 256`.

### `jev.ts`: the profile

```ts
export type DecisionProvider = {
  /** OpenRouter provider slug, sent in `provider.only`. */
  slug: string;
  /** The response's `provider` field after normalization. */
  name: string;
  contextTokens: number;
};

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

/** The profile for a decision backend, whichever backend is active. */
export function decisionProfile(config: EffectiveConfig, backend: DecisionBackend): DecisionProfile;

/** The backend's display name: "Jev" or "Clef". */
export function decisionLabel(backend: DecisionBackend): string;

/** The request body: model, state, questions, and the provider field when the profile has one. */
export function buildDecisionRequest(
  profile: DecisionProfile,
  state: Record<string, string>,
  questions: JevQuestions,
): Record<string, unknown>;

/**
 * Decisions 5 and 6. Returns an error message, or nothing when the response
 * passes. Always passes for a profile without a provider.
 */
export function checkDecisionResponse(
  profile: DecisionProfile,
  response: { provider?: unknown; inputTokens?: unknown },
): string | undefined;
```

- The backend is always passed explicitly. Callers on the classify path pass the active backend. `/automode jev` and `/automode clef` pass their own backend, whatever is active. The sweep passes its `--backend`. No code maps `"llm"` to a profile.
- These take a `DecisionProfile` instead of reading `config.jev*`:
  - `jevIntentThreshold` (`jev.ts:396-399`) and `jevDecision` (`jev.ts:423-490`);
  - `defaultJevClassifyAction`, which builds the profile once and uses it for the request, the cache key (which also gets the backend), and `jevIo`;
  - `probeJevClassifier` and `jevStatusText`.
- **The body is built once.** `defaultJevClassifyAction` calls `buildDecisionRequest` after redaction and after a cache miss, and passes the body to `requestJevScores`. Today the body is built inside each attempt (`jev.ts:759`).
- **The check runs on every successful parse.** `requestJevScoresOnce` calls `checkDecisionResponse` after `parseJevResponse` and before the missing-answers check. A failure returns `ok: false` without `retryable` (decision 7).
- `parseJevResponse` also returns the response's `provider` and `usage.input_tokens`, unvalidated. Its model fallback (`jev.ts:324`) becomes the requested model.
- `jevIo` logs the served provider and input tokens when present. Its "(not used by the Jev backend)" strings (`jev.ts:645-646`) and the comment that the backend reports no usage use `decisionLabel(backend)` and become accurate for Clef.
- `jevStatusText` shows warnings for the profile's backend. Its diagnostics filter (`jev.ts:614`) matches `/jev|clef/i` for Clef, so `clef*` warnings appear in `/automode clef`. It also shows the pinned provider and the truncation bound.
- Messages that say "Jev" use `decisionLabel(backend)`. That covers the classifier failure, the missing key, timeouts, and missing answers.
- The wording sent to the model (`JEV_STATE_FIELDS` and the questions) stays as it is. It does not name Jev.

### `extension.ts`, `state.ts`, `config.ts`

A helper `isDecisionBackend(cfg)` (true for `"jev"` and `"clef"`) replaces `cfg.classifierBackend === "jev"` at these sites:

- classifier selection (`selectClassify`, `extension.ts:241-242`). The `jevClassifyAction` test override covers both decision backends.
- the log context (`extension.ts:577-581`): model and reasoning come from the profile.
- status: the status line (`state.ts:33-39`) and the inspect-tool status (`extension.ts:356-362`). They show `clef (cloudflare/clef)`, with fast-stage settings "not used by the Clef backend".
- the soft-deny confirmation gate (`extension.ts:1042`). The edit-tool hint (`extension.ts:939-952`) is reached only through this gate, so it needs no change of its own. The prompt and approval wording (`extension.ts:1019`, `1287`) names the active backend.
- the session-created-paths `tool_call` wrapper (`extension.ts:1089`).
- the `/automode model` branch (`extension.ts:1378`).
- `loadConfigWithDiagnostics` (`config.ts:1094`), for key diagnostics.

Names that are internal and test-facing keep `jev` (for example `shownToJev`, `defaultJevClassifyAction`, and the `jev.ts` file). Renaming them is churn with no behavior change.

**One way to apply a reload.** A helper `applyLoadResult(next)` replaces the five copies of "set `loadResult`, `config`, and `configDiagnostics`" (`extension.ts:533`, `1204`, `1319`, `1413`, `1455`):

- It compares the classifier identity before and after: the backend, and for a decision backend, that backend's model. When the identity changes, it clears `sessionApprovals` and returns that it did. `session_start` already clears them (`extension.ts:540`).
- `sessionEditRoots` are kept. They skip the classifier entirely, like `scratchRoots` (`extension.ts:836-850`), so they do not depend on which model proposed them. `/automode approvals clear` still clears both (`extension.ts:1272-1274`).
- Every command that reloads reports the effective result. `/automode backend clef` says "saved globally: clef" and, when a project-local or inline setting overrides it, "current config uses jev". This matches what `/automode model` already does (`extension.ts:1421-1426`). When approvals were cleared, the message says so.

### Commands

- `/automode backend <llm|jev|clef>`, through `applyLoadResult`.
- `/automode clef` shows the Clef status and diagnostics. `/automode clef test` runs the direction probes and the canary (decision 8) with the Clef profile. Both work whichever backend is active, and so do `/automode jev` and `/automode jev test` (`extension.ts:1333-1375`).
- `/automode model <provider/model>` saves `clefModel` when Clef is active, and `jevModel` when Jev is active, through `applyLoadResult`. Messages name the active backend.
- `/automode reload` goes through `applyLoadResult`, so a reload that changes the backend or model clears approvals too.
- The usage and description strings (`extension.ts:1304`, `1475`, `1482`) list `clef`.

### `scripts/jev-sweep.ts` and `scripts/jev-sweep-lib.ts`

- `--backend <jev|clef>` (default `jev`) picks the profile. The request body comes from `buildDecisionRequest`, replacing the hard-coded values (`jev-sweep.ts:101`, `133-139`). Every response goes through `checkDecisionResponse`.
- **The same retry policy as the classifier.** One retry of a transient failure (429, 5xx, timeout, network error), as in `requestJevScores` (`jev.ts:696-735`). A run that still fails is a failed run.
- **Failed runs count as misses.** A case with fewer successful runs than `--runs` is reported as incomplete, and an incomplete `block` case counts against calibration rule 1. Today, errors are recorded and dropped (`jev-sweep.ts:142-144`), and `summarizeSweep` judges only the successful runs.
- `summarizeSweep` and the printed thresholds take a `DecisionProfile` instead of reading `config.jev*` (`jev-sweep-lib.ts:287-297`, `jev-sweep.ts:165-167`).
- **The saved format.** `--json <out>` writes everything `--rescore` needs:

  ```ts
  type SavedSweep = {
    backend: DecisionBackend;
    model: string;
    date: string; // ISO 8601
    thresholds: { hard: number; soft: number; readOnlyIntent: number; scope: number };
    cases: Array<{
      name: string;
      want: "allow" | "block" | "unlabeled";
      questionIds: string[];
      runs: Array<
        | { ok: true; provider?: string; inputTokens?: number; latencyMs: number;
            readOnly: boolean; scores: Record<string, number> }
        | { ok: false; error: string; latencyMs: number }
      >;
    }>;
  };
  ```

  Scores are kept per question, so `--rescore` rebuilds the gates (`hard`, the highest soft-deny rule, intent) itself.
- `--rescore <saved.json>` re-scores a saved sweep at the profile's thresholds, or at `--hard/--soft/--intent/--scope` overrides, without new requests. Thresholds are searched this way, offline.
- `--canary --sizes <n,...> --runs N` runs the canary (decision 8) and prints pass, fail, or inconclusive per run.
- The output prints each response's provider, input tokens, and latency.
- `--extract-logs` records each case's classifier as `loggedBackend` (`"llm"`, `"jev"`, or `"clef"`), read from the logged reasoning. `parseCorpus` accepts the field, and the logged-corpus check reports counts per backend, so Clef-session cases are not mixed into a Jev-only count.

## Calibration

Clef's probabilities are not Jev's, so Clef's defaults come from measurement, not from copying Jev's values.

1. **Canary first.** Run `--canary --sizes 8000,30000,60000 --runs 3` against DeepInfra. Every run must pass. If one fails, stop and report.
2. **Jev baseline, same day.** Sweep the 65-case corpus (`tests/fixtures/jev-corpus.json`: 38 block, 27 allow) 3 times with `--backend jev` at Jev's current defaults. Record Jev's misses and its false blocks: allow cases blocked in any run. Save with `--json`.
3. **Clef sweep.** Sweep the same corpus 3 times with `--backend clef` and save with `--json`.
4. **Pick the thresholds** with `--rescore` over the saved Clef sweep, by these rules in order:
   1. **Must block.** Every `block` case has 3 successful runs, and blocks in all of them. That includes the counterparts that must keep blocking: refreshes with no record, the project overwrite, the `..` path, and the joined claim.
   2. **Block-side margin, mandatory.** In every run of every `block` case, at least one blocking gate's score is at least its threshold plus 0.05. The gates are `hard_deny`, the highest soft-deny rule, and `user_intent` against the intent threshold that applies to that run (read-only or not).
   3. **Few false blocks.** Within rules 1 and 2, as few allow cases as possible block in any run.
   4. **Allow-side margin, best effort.** Leave 0.05 above the highest allow-case score where the scores allow it.
   5. `clefReadOnlyIntentThreshold` is at least `clefSoftDenyThreshold`, and `clefScopeEscapeThreshold` stays advisory.
5. **Stop rule.** Implementation stops, and the numbers go to the user before any defaults are set, if either:
   - no thresholds satisfy rules 1 and 2; or
   - Clef's false blocks are more than Jev's from step 2. Both counts are over 3 runs on the same corpus.

   Whether to ship Clef anyway, as experimental with its misses documented, is the user's decision.
6. **Logged-corpus check.** The thresholds are tuned on the same 65 cases they are judged on, which overfits. So Clef (at the chosen thresholds) and Jev (at its defaults) are also scored on the local logged corpus (`.jev-corpus/real.json`: 33 cases, 30 allow, 3 block).
   - **It is not a held-out set.** It is unseen by Clef, but Jev's defaults were tuned with it in view (`docs/jev-classifier-backend.md:1034-1037`). Its labels start from the user's answers to Jev's soft-deny prompts (`jev-sweep-lib.ts:193-210`) and were reviewed by hand, so it leans toward actions Jev chose to ask about. With 3 block cases it is a sanity check, not evidence of generalization.
   - The corpus is not committed, and only counts are reported. A labelled `block` case that Clef misses triggers the stop rule.
7. **Also recorded:**
   - run-to-run spread;
   - median and p95 latency against the 12-second timeout;
   - cost per action, from `usage.cost`.
8. **Docs.** The results and chosen thresholds go into a Clef section of `docs/jev-classifier-backend.md`, with a caveat for each corpus case Clef gets wrong.

## Threats and gaps

| # | Threat | Handling |
|---|---|---|
| C1 | A request lands on Cloudflare or Prime Intellect | request `only: ["deepinfra"]` with no fallbacks; any other provider in the response blocks |
| C2 | A provider not yet known, or a renamed provider field | exact match on the normalized name; a missing or unknown provider blocks |
| C3 | A request larger than DeepInfra's context (a large `write`, many loaded files) | the truncation check on `usage.input_tokens`; missing usage blocks too |
| C4 | A custom base URL (a proxy) routes elsewhere or strips fields | the provider field is sent on every base URL; a proxy that drops `provider` or `usage` blocks visibly. A proxy that rewrites them is not caught (gaps below) |
| C5 | Jev thresholds used for Clef, or the reverse | explicit profiles; tests assert each backend's decisions read its own thresholds |
| C6 | A shared project file switches the backend or loosens Clef thresholds | the new keys are autoMode scalars, which shared project files cannot set; a test covers it |
| C7 | A session approval given under one model auto-allows another model's soft deny | `applyLoadResult` clears approvals whenever the backend or decision model changes, on every reload path |
| C8 | Calibration passes because failed runs were dropped | failed runs count as misses for `block` cases |
| C9 | Clef is worse than Jev | the stop rule, with a same-day Jev baseline, and the logged-corpus check |
| C10 | Uncalibrated defaults ship | the placeholders are 0.0, which blocks every action, and a test fails while they remain |

Known gaps:

- **Fields are trusted as reported.** The provider and usage checks read what the response says. A proxy, or OpenRouter itself, could report `"DeepInfra"` and a full count for a request served elsewhere or cut short. The checks catch a provider that is missing, different, or at its limit, not one that misreports.
- **Internal truncation.** A provider that cuts the state but reports the full count would pass the usage check. DeepInfra does not do this today (decision 8's canary at 60K). `/automode clef test` lets a user check again, but nothing checks every request.
- **Availability.** With one provider, a DeepInfra outage blocks every Clef-classified action.

## Testing

Red/green, in the existing suites:

- **Config** (`tests/config.test.ts`):
  - `classifierBackend: "clef"` is accepted, and an invalid value gets the new message;
  - the `clef*` keys validate and merge, with defaults, and get no unknown-key diagnostic;
  - shared project config can set neither the backend nor the `clef*` keys;
  - `clefModel` can be saved globally;
  - key diagnostics run for Clef;
  - no `DEFAULT_CLEF_*_THRESHOLD` is `0.0` (added in the calibration task).
- **Profile** (`tests/jev.test.ts`):
  - `decisionProfile(config, "clef")` returns Clef's model, thresholds, and provider even while Jev is active, and the reverse;
  - `jevDecision` blocks or allows at Clef's thresholds for the Clef profile, and at Jev's for the Jev profile;
  - the cache key differs between backends.
- **Request and response** (`tests/jev.test.ts`, with the fetch stub):
  - a Clef request body has `provider: { only: ["deepinfra"], allow_fallbacks: false }`, on the default and on a custom base URL;
  - a Jev request body is unchanged, with no `provider` field, and a Jev response without `provider` or `usage` still passes;
  - a retried Clef request sends the same body both times;
  - each of these Clef responses blocks with a clear reason, is not retried, and is not cached:
    - the provider is missing, not a string, `"Cloudflare"`, `"PrimeIntellect"`, or `"DeepInfra2"`;
    - `usage` or `usage.input_tokens` is missing or not a finite number;
    - `usage.input_tokens` is 65,536, and is 65,280 (the bound);
  - `"DeepInfra"`, `"deepinfra"`, and `"Deep Infra"` pass, with `input_tokens` 65,279;
  - messages say "Clef", and `jevIo` logs the provider and input tokens.
- **Status** (`tests/status.test.ts`):
  - `jevStatusText` for Clef shows a `clefSoftDenyThreshold` diagnostic;
  - the status line and the inspect-tool status show `clef (cloudflare/clef)`;
  - the reasoning in a Clef log entry has `backend: "clef"`.
- **Hooks** (`tests/hook-created-paths.test.ts`, `tests/jev-confirm.test.ts`):
  - on the Clef backend, session-created claims reach the classifier;
  - soft-deny confirmation and the edit-tool hint behave as on Jev;
  - session approvals are cleared by `/automode backend`, by `/automode model` when the model changes, and by `/automode reload` when the backend changes, and not by a reload that changes neither;
  - session edit roots survive a backend change.
- **Commands** (the command tests):
  - `/automode backend clef`, including the "current config uses jev" message when a project-local setting overrides it;
  - `/automode model` saves `clefModel` while Clef is active;
  - `/automode clef` and `/automode clef test`, with the canary passing, failing on a low fact score, failing on a high control score, and inconclusive on a timeout;
  - `/automode jev` while Clef is active shows Jev's profile.
- **Sweep** (`tests/jev-sweep.test.ts`):
  - `--backend clef`, `--rescore`, and `--canary` parsing;
  - the request body comes from `buildDecisionRequest`;
  - a transient failure is retried once, and a run that still fails counts as a miss for a `block` case;
  - a response from a disallowed provider or at the token bound is rejected;
  - `summarizeSweep` reads the profile's thresholds;
  - a saved sweep round-trips through `--rescore`, and the margin rule rejects a block run within 0.05 of every gate;
  - extracted log cases carry `loggedBackend`.
- `npm run check`, `npm test`, and `npm pack --dry-run` (if the sandbox allows it) before handing off.

## Docs

- `docs/configuration.md`:
  - the `"clef"` backend and the new keys;
  - which `jev*` keys are shared;
  - that Clef requests go to DeepInfra only, and responses are checked for the provider and for truncation;
  - that a proxy base URL must pass the `provider` field through in both directions, and `usage` back, and that a proxy can misreport them.
- `docs/jev-classifier-backend.md`: a Clef section with the measurements and caveats from the calibration.
- `README.md`: the `/automode backend llm|jev|clef` and `/automode clef` command lines, and a sentence on Clef in the backend section.
- `examples/automode.local.json`: unchanged. Clef is opt-in.
- `CHANGELOG.md`: a "Clef classifier backend" entry.
