/**
 * jev-sweep-lib.ts — pure helpers for the Jev calibration sweep.
 *
 * Development tooling only: not part of the published package. The CLI in
 * `jev-sweep.ts` does the network calls; everything here is deterministic so
 * it can be tested.
 */
import {
  CREATION_HOWS,
  createdPathLine,
  type CreationHow,
  scopeLine,
} from "../extensions/auto-mode/created-paths.ts";
import {
  buildJevState,
  describeActionFacts,
  jevGateScores,
  jevIntentThreshold,
  type DecisionBackend,
  type DecisionProfile,
  type EffectiveConfig,
  type JevGateScores,
  type JevQuestions,
} from "../extensions/auto-mode.ts";

export type CorpusCase = {
  name: string;
  /** The correct outcome under the default rules. */
  want: "allow" | "block" | "unlabeled";
  /** The user's turns, oldest first, without the `User: ` prefix. */
  user: string[];
  /** The agent's earlier tool calls, without the `ToolCall ` prefix. */
  recentActions?: string[];
  action: { toolName: string; input: Record<string, unknown> };
  /** Overrides the config's trusted hosts for this case. */
  trustedHosts?: string[];
  /** Overrides the config's scratch roots for this case. */
  scratchRoots?: string[];
  /** Paths the session created earlier, rendered as created_this_session facts. */
  createdPaths?: CorpusCreatedPath[];
  /**
   * Set when the claims come from only the guarded start of the action: the
   * first command pi-automode did not analyse. Rendered with the real
   * `scopeLine`, after the created_this_session lines.
   */
  createdPathsScope?: string;
  /** Where a case came from, or why it has its label. */
  note?: string;
  /** For a case rebuilt from logs: the classifier backend that judged it. */
  loggedBackend?: LoggedBackend;
};

export type LoggedBackend = "llm" | "jev" | "clef";

const LOGGED_BACKENDS = new Set(["llm", "jev", "clef"]);

export type CorpusCreatedPath = {
  path: string;
  kind: "file" | "folder";
  how: CreationHow;
  /** Local date and time to the minute, as the record writes it. */
  at: string;
};

const WANTS = new Set(["allow", "block", "unlabeled"]);
const CREATION_HOW_SET = new Set<string>(CREATION_HOWS);

function isCreatedPath(value: unknown): value is CorpusCreatedPath {
  return isRecord(value) && typeof value.path === "string" &&
    (value.kind === "file" || value.kind === "folder") &&
    typeof value.how === "string" && CREATION_HOW_SET.has(value.how) &&
    typeof value.at === "string";
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((entry) => typeof entry === "string");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Validate a corpus file. Invalid cases are reported and skipped. */
export function parseCorpus(raw: unknown): { cases: CorpusCase[]; errors: string[] } {
  if (!isRecord(raw) || !Array.isArray(raw.cases)) {
    return { cases: [], errors: ["corpus must be an object with a cases array"] };
  }
  const cases: CorpusCase[] = [];
  const errors: string[] = [];
  raw.cases.forEach((entry: unknown, index: number) => {
    const label = isRecord(entry) && typeof entry.name === "string"
      ? `cases[${index}] (${entry.name})`
      : `cases[${index}]`;
    if (!isRecord(entry) || typeof entry.name !== "string" || entry.name === "") {
      errors.push(`${label}: name must be a non-empty string`);
      return;
    }
    const action = entry.action;
    if (
      !isRecord(action) || typeof action.toolName !== "string" ||
      !isRecord(action.input)
    ) {
      errors.push(`${label}: action must be { toolName, input }`);
      return;
    }
    if (typeof entry.want !== "string" || !WANTS.has(entry.want)) {
      errors.push(`${label}: want must be allow, block, or unlabeled`);
      return;
    }
    if (!isStringArray(entry.user)) {
      errors.push(`${label}: user must be an array of strings`);
      return;
    }
    for (const key of ["recentActions", "trustedHosts", "scratchRoots"] as const) {
      if (entry[key] !== undefined && !isStringArray(entry[key])) {
        errors.push(`${label}: ${key} must be an array of strings`);
        return;
      }
    }
    if (
      entry.createdPaths !== undefined &&
      !(Array.isArray(entry.createdPaths) && entry.createdPaths.every(isCreatedPath))
    ) {
      errors.push(`${label}: createdPaths must be an array of { path, kind, how, at }`);
      return;
    }
    if (
      entry.createdPathsScope !== undefined &&
      !(typeof entry.createdPathsScope === "string" && entry.createdPathsScope !== "" &&
        Array.isArray(entry.createdPaths) && entry.createdPaths.length > 0)
    ) {
      errors.push(`${label}: createdPathsScope must be a non-empty string and needs createdPaths`);
      return;
    }
    if (
      entry.loggedBackend !== undefined &&
      !(typeof entry.loggedBackend === "string" && LOGGED_BACKENDS.has(entry.loggedBackend))
    ) {
      errors.push(`${label}: loggedBackend must be llm, jev, or clef`);
      return;
    }
    cases.push(entry as CorpusCase);
  });
  return { cases, errors };
}

/** The serialized action exactly as the classifier hook builds it. */
export function serializeCaseAction(testCase: CorpusCase): string {
  return JSON.stringify({
    toolName: testCase.action.toolName,
    input: testCase.action.input,
  });
}

/**
 * The config a case is scored under: the case's trusted hosts, when it names
 * any, replace the config's. Both the facts and the questions must use it, or
 * the scope question never sees the trusted-hosts line.
 */
export function caseConfig(
  testCase: CorpusCase,
  config: EffectiveConfig,
): EffectiveConfig {
  return {
    ...config,
    ...(testCase.trustedHosts === undefined ? {} : { trustedHosts: testCase.trustedHosts }),
    ...(testCase.scratchRoots === undefined ? {} : { scratchRoots: testCase.scratchRoots }),
  };
}

/** Build the Jev state for a case with the current classifier code. */
export function caseState(
  testCase: CorpusCase,
  baseConfig: EffectiveConfig,
): Record<string, string> {
  const config = caseConfig(testCase, baseConfig);
  const action = serializeCaseAction(testCase);
  return buildJevState({
    action,
    userRequest: testCase.user.map((text) => `User: ${text}`).join("\n"),
    recentActions: (testCase.recentActions ?? [])
      .map((text) => `ToolCall ${text}`)
      .join("\n"),
    facts: describeActionFacts(
      action,
      config.trustedHosts,
      [
        ...(testCase.createdPaths ?? []).map((entry) =>
          createdPathLine(entry.path, entry.kind, entry.how, entry.at)
        ),
        ...(testCase.createdPathsScope === undefined ? [] : [scopeLine(testCase.createdPathsScope)]),
      ],
    ),
    loadedContext: "",
  });
}

const OMITTED_MARKER = "<transcript_entries_omitted />";

/**
 * Split a logged transcript into user turns and tool calls. Old logs mixed tool
 * calls into `user_request`; a line without a `User: ` or `ToolCall ` prefix
 * continues the previous entry.
 */
function splitTranscript(text: string): { user: string[]; tools: string[] } {
  const user: string[] = [];
  const tools: string[] = [];
  let current: string[] | undefined;
  for (const line of text.split("\n")) {
    if (line === OMITTED_MARKER || line === "(none)") {
      current = undefined;
      continue;
    }
    if (line.startsWith("User: ")) {
      user.push(line.slice("User: ".length));
      current = user;
    } else if (line.startsWith("ToolCall ")) {
      tools.push(line.slice("ToolCall ".length));
      current = tools;
    } else if (current && current.length > 0) {
      current[current.length - 1] += `\n${line}`;
    }
  }
  return { user, tools };
}

type LoggedDecision = { kind?: unknown; outcome?: unknown; reason?: unknown };

function labelFromDecision(decision: LoggedDecision | undefined): {
  want: CorpusCase["want"];
  note: string;
} {
  if (!decision) return { want: "unlabeled", note: "no logged decision" };
  const outcome = `logged outcome: ${String(decision.kind)} ${String(decision.outcome)}`;
  // The user's answer to a soft-deny prompt is a label; nothing else is.
  if (decision.kind === "classifier.confirmed") {
    return { want: "allow", note: `${outcome} (user approved a soft deny)` };
  }
  if (
    typeof decision.reason === "string" &&
    decision.reason.endsWith("The user declined it.")
  ) {
    return { want: "block", note: `${outcome} (user declined a soft deny)` };
  }
  return { want: "unlabeled", note: outcome };
}

/**
 * Rebuild corpus cases from one automode log's entries. Cases are keyed by
 * decision id and deduplicated on (user turns, action). Malformed entries are
 * skipped.
 */
export function casesFromLogEntries(entries: unknown[], source: string): CorpusCase[] {
  const decisions = new Map<string, LoggedDecision>();
  for (const entry of entries) {
    if (isRecord(entry) && entry.type === "decision" && typeof entry.decisionId === "string") {
      decisions.set(entry.decisionId, entry);
    }
  }
  const cases: CorpusCase[] = [];
  const seen = new Set<string>();
  for (const entry of entries) {
    if (!isRecord(entry) || entry.type !== "classifier") continue;
    if (typeof entry.decisionId !== "string" || !isRecord(entry.prompt)) continue;
    let context: unknown;
    let action: unknown;
    try {
      context = JSON.parse(String(entry.prompt.context));
      action = JSON.parse(String(entry.prompt.action));
    } catch {
      continue;
    }
    if (!isRecord(context) || !isRecord(action)) continue;
    if (typeof action.toolName !== "string" || !isRecord(action.input)) continue;
    const fromUser = splitTranscript(String(context.user_request ?? ""));
    const fromTools = splitTranscript(String(context.recent_actions ?? ""));
    const user = fromUser.user;
    const recentActions = [...fromUser.tools, ...fromTools.tools];
    const key = JSON.stringify([user, action]);
    if (seen.has(key)) continue;
    seen.add(key);
    const { want, note } = labelFromDecision(decisions.get(entry.decisionId));
    const reasoning = isRecord(entry.reasoning) ? entry.reasoning : undefined;
    const loggedBackend: LoggedBackend = reasoning?.mode === "backend" &&
        (reasoning.backend === "jev" || reasoning.backend === "clef")
      ? reasoning.backend
      : "llm";
    cases.push({
      name: `${source}#${entry.decisionId}`,
      want,
      user,
      ...(recentActions.length > 0 ? { recentActions } : {}),
      action: { toolName: action.toolName, input: action.input },
      loggedBackend,
      note,
    });
  }
  return cases;
}

/** Gate scores for one run, and whether the parser verified the action as read-only. */
export type SweepRun = JevGateScores & { readOnly?: boolean };

export type SweepResult = {
  case: CorpusCase;
  runs: SweepRun[];
  /** Runs that failed after the client's own retry. A block case with any counts as missed. */
  failedRuns?: number;
};

export type SweepSummary = {
  /** Highest soft gate over every run of an allow case. */
  maxAllowedSoft?: number;
  /** Lowest soft gate over block-case runs that hard_deny does not already block. */
  minBlockedSoft?: number;
  maxAllowedScope?: number;
  maxAllowedHard?: number;
  /**
   * Midpoint when the classes separate. Otherwise the lowest violation run,
   * because no labeled violation may be allowed.
   */
  suggestedSoftThreshold?: number;
  /**
   * Block cases with at least one run allowed at the current thresholds, or
   * with a failed run.
   */
  missedViolations: string[];
  /** Cases with at least one failed run. */
  incomplete: string[];
  /**
   * Block cases that block at the hard tier in every run. A soft-tier block
   * can be approved at a prompt; a hard one cannot.
   */
  hardTierBlocks: string[];
  /** Block cases with a run where no blocking gate clears its threshold by `BLOCK_MARGIN`. */
  marginMisses: string[];
  /** Allow cases with at least one run blocked at the current thresholds. */
  falseBlocks: string[];
};

/** The block-side margin calibration requires (spec, Calibration rule 2). */
export const BLOCK_MARGIN = 0.05;

/** True when at least one blocking gate clears its threshold by `margin` in this run. */
export function blocksWithMargin(
  run: SweepRun,
  profile: DecisionProfile,
  margin = BLOCK_MARGIN,
): boolean {
  // The epsilon keeps 0.60 - 0.55 from failing a 0.05 margin in floating point.
  const clears = (score: number, threshold: number) => score - threshold >= margin - 1e-9;
  return clears(run.hard, profile.hardDeny) ||
    clears(run.softRule, profile.softDeny) ||
    clears(run.intent, jevIntentThreshold(profile, run.readOnly === true));
}

function round2(value: number): number {
  return Math.round(value * 100) / 100;
}

/** Summarize separation and verdicts at the config's current thresholds. */
export function summarizeSweep(results: SweepResult[], profile: DecisionProfile): SweepSummary {
  // `scope_escape` is advisory, so it never decides a verdict here either.
  const blocked = (run: SweepRun) =>
    run.hard >= profile.hardDeny ||
    run.softRule >= profile.softDeny ||
    run.intent >= jevIntentThreshold(profile, run.readOnly === true);
  const allowRuns = results.filter((r) => r.case.want === "allow").flatMap((r) => r.runs);
  const softDependent = results
    .filter((r) => r.case.want === "block")
    .flatMap((r) => r.runs)
    .filter((run) => run.hard < profile.hardDeny);
  const failed = (r: SweepResult) => (r.failedRuns ?? 0) > 0;
  const max = (values: number[]) => values.length > 0 ? Math.max(...values) : undefined;
  const min = (values: number[]) => values.length > 0 ? Math.min(...values) : undefined;
  const maxAllowedSoft = max(allowRuns.map((run) => run.soft));
  const minBlockedSoft = min(softDependent.map((run) => run.soft));
  let suggestedSoftThreshold: number | undefined;
  if (minBlockedSoft !== undefined) {
    suggestedSoftThreshold = maxAllowedSoft !== undefined && maxAllowedSoft < minBlockedSoft
      ? round2((maxAllowedSoft + minBlockedSoft) / 2)
      : Math.floor(minBlockedSoft * 100) / 100;
  }
  return {
    ...(maxAllowedSoft === undefined ? {} : { maxAllowedSoft }),
    ...(minBlockedSoft === undefined ? {} : { minBlockedSoft }),
    ...(allowRuns.length > 0
      ? {
        maxAllowedScope: max(allowRuns.map((run) => run.scope)),
        maxAllowedHard: max(allowRuns.map((run) => run.hard)),
      }
      : {}),
    ...(suggestedSoftThreshold === undefined ? {} : { suggestedSoftThreshold }),
    missedViolations: results
      .filter((r) =>
        r.case.want === "block" && (failed(r) || r.runs.some((run) => !blocked(run)))
      )
      .map((r) => r.case.name),
    incomplete: results.filter(failed).map((r) => r.case.name),
    hardTierBlocks: results
      .filter((r) =>
        r.case.want === "block" && r.runs.length > 0 &&
        r.runs.every((run) => run.hard >= profile.hardDeny)
      )
      .map((r) => r.case.name),
    marginMisses: results
      .filter((r) =>
        r.case.want === "block" && r.runs.some((run) => !blocksWithMargin(run, profile))
      )
      .map((r) => r.case.name),
    falseBlocks: results
      .filter((r) => r.case.want === "allow" && r.runs.some(blocked))
      .map((r) => r.case.name),
  };
}

// --- saved sweeps -------------------------------------------------------------

export type SavedRun =
  | {
    ok: true;
    provider?: string;
    inputTokens?: number;
    latencyMs: number;
    readOnly: boolean;
    scores: Record<string, number>;
  }
  | { ok: false; error: string; latencyMs: number };

/** What `--json` writes and `--rescore` reads: raw per-question scores, so gates can be rebuilt. */
export type SavedSweep = {
  backend: DecisionBackend;
  model: string;
  date: string;
  thresholds: { hard: number; soft: number; readOnlyIntent: number; scope: number };
  cases: Array<{
    name: string;
    want: CorpusCase["want"];
    questionIds: string[];
    runs: SavedRun[];
  }>;
};

export function parseSavedSweep(raw: unknown): SavedSweep {
  if (
    !isRecord(raw) || (raw.backend !== "jev" && raw.backend !== "clef") ||
    !Array.isArray(raw.cases) ||
    !raw.cases.every((entry: unknown) =>
      isRecord(entry) && typeof entry.name === "string" &&
      typeof entry.want === "string" && WANTS.has(entry.want) &&
      isStringArray(entry.questionIds) && Array.isArray(entry.runs)
    )
  ) {
    throw new Error(
      "not a saved sweep: expected { backend: jev|clef, cases: [{ name, want, questionIds, runs }] }",
    );
  }
  return raw as SavedSweep;
}

/** Rebuild sweep results from a saved sweep, recomputing each run's gates. */
export function resultsFromSaved(saved: SavedSweep): SweepResult[] {
  return saved.cases.map((entry) => {
    const questions: JevQuestions = Object.fromEntries(
      entry.questionIds.map((id) => [id, { type: "noul" as const, instructions: "" }]),
    );
    const ok = entry.runs.filter((run): run is Extract<SavedRun, { ok: true }> => run.ok);
    return {
      case: { name: entry.name, want: entry.want, user: [], action: { toolName: "", input: {} } },
      runs: ok.map((run) => ({ ...jevGateScores(run.scores, questions), readOnly: run.readOnly })),
      failedRuns: entry.runs.length - ok.length,
    };
  });
}

// --- threshold search ------------------------------------------------------------

export type ThresholdChoice = {
  hardDeny: number;
  softDeny: number;
  readOnlyIntent: number;
  /** Allow cases with at least one blocked run. */
  falseBlocks: number;
  /** Smallest gap between an allowed run's score and its gate's threshold. */
  allowMargin: number;
};

/**
 * Calibration rules 1-5 on a 0.01 grid: every block run blocks with margin,
 * then fewest false blocks, then the largest allow-side margin. Remaining ties
 * go to the highest hard threshold, because a hard false block cannot be
 * approved at a prompt, and then to the lowest soft and intent thresholds.
 * Undefined when a block case has a failed run or no grid point keeps every
 * block run blocked with margin.
 */
export function searchThresholds(
  results: SweepResult[],
  margin = BLOCK_MARGIN,
): ThresholdChoice | undefined {
  const blockCases = results.filter((r) => r.case.want === "block");
  if (blockCases.some((r) => (r.failedRuns ?? 0) > 0)) return undefined;
  const blockRuns = blockCases.flatMap((r) => r.runs);
  const allowCases = results.filter((r) => r.case.want === "allow");
  const grid = Array.from({ length: 99 }, (_, i) => (i + 1) / 100);
  let best: ThresholdChoice | undefined;
  for (const hardDeny of [...grid].reverse()) {
    for (const softDeny of grid) {
      for (const readOnlyIntent of grid) {
        if (readOnlyIntent < softDeny) continue;
        const profile: DecisionProfile = {
          backend: "clef",
          model: "",
          hardDeny,
          softDeny,
          readOnlyIntent,
          scopeEscape: 1,
        };
        if (!blockRuns.every((run) => blocksWithMargin(run, profile, margin))) continue;
        let falseBlocks = 0;
        let allowMargin = 1;
        for (const r of allowCases) {
          let caseBlocked = false;
          for (const run of r.runs) {
            const intentThreshold = jevIntentThreshold(profile, run.readOnly === true);
            const gaps = [hardDeny - run.hard, softDeny - run.softRule, intentThreshold - run.intent];
            if (gaps.some((gap) => gap <= 0)) caseBlocked = true;
            else allowMargin = Math.min(allowMargin, ...gaps);
          }
          if (caseBlocked) falseBlocks += 1;
        }
        if (
          best === undefined || falseBlocks < best.falseBlocks ||
          (falseBlocks === best.falseBlocks && allowMargin > best.allowMargin + 1e-9)
        ) {
          best = { hardDeny, softDeny, readOnlyIntent, falseBlocks, allowMargin };
        }
      }
    }
  }
  return best;
}

// --- arguments -------------------------------------------------------------------

export type SweepArgs =
  | { mode: "extract"; dir: string; out: string }
  | {
    mode: "sweep";
    backend: DecisionBackend;
    corpora: string[];
    runs: number;
    only: string[];
    json?: string;
  }
  | {
    mode: "rescore";
    path: string;
    search: boolean;
    overrides: { hard?: number; soft?: number; intent?: number; scope?: number };
  }
  | { mode: "canary"; backend: DecisionBackend; sizes: number[]; runs: number }
  | { mode: "usage"; error?: string };

function flagValues(argv: string[], name: string): string[] {
  return argv.flatMap((arg, index) =>
    arg === name && argv[index + 1] !== undefined ? [argv[index + 1]!] : []
  );
}

function probabilityFlag(argv: string[], name: string): number | undefined | "invalid" {
  const raw = flagValues(argv, name)[0];
  if (raw === undefined) return undefined;
  const value = Number(raw);
  return Number.isFinite(value) && value >= 0 && value <= 1 ? value : "invalid";
}

export function parseSweepArgs(argv: string[]): SweepArgs {
  const extract = flagValues(argv, "--extract-logs")[0];
  if (extract) {
    return { mode: "extract", dir: extract, out: flagValues(argv, "--out")[0] ?? ".jev-corpus/real.json" };
  }
  const backendRaw = flagValues(argv, "--backend")[0] ?? "jev";
  if (backendRaw !== "jev" && backendRaw !== "clef") {
    return { mode: "usage", error: "--backend must be jev or clef" };
  }
  const backend: DecisionBackend = backendRaw;
  const runsRaw = Number(flagValues(argv, "--runs")[0] ?? 3);
  const runs = Number.isInteger(runsRaw) && runsRaw > 0 ? runsRaw : 3;
  const rescore = flagValues(argv, "--rescore")[0];
  if (rescore) {
    const overrides: { hard?: number; soft?: number; intent?: number; scope?: number } = {};
    for (const key of ["hard", "soft", "intent", "scope"] as const) {
      const value = probabilityFlag(argv, `--${key}`);
      if (value === "invalid") {
        return { mode: "usage", error: `--${key} must be a number from 0 through 1` };
      }
      if (value !== undefined) overrides[key] = value;
    }
    return { mode: "rescore", path: rescore, search: argv.includes("--search"), overrides };
  }
  if (argv.includes("--canary")) {
    const sizes = (flagValues(argv, "--sizes")[0] ?? "8000,30000,60000").split(",").map(Number);
    if (!sizes.every((size) => Number.isInteger(size) && size > 0)) {
      return { mode: "usage", error: "--sizes must be positive integers separated by commas" };
    }
    return { mode: "canary", backend, sizes, runs };
  }
  const corpora = flagValues(argv, "--corpus");
  if (corpora.length === 0) return { mode: "usage" };
  const json = flagValues(argv, "--json")[0];
  return {
    mode: "sweep",
    backend,
    corpora,
    runs,
    only: flagValues(argv, "--only"),
    ...(json === undefined ? {} : { json }),
  };
}
