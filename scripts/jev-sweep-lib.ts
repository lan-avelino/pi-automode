/**
 * jev-sweep-lib.ts — pure helpers for the Jev calibration sweep.
 *
 * Development tooling only: not part of the published package. The CLI in
 * `jev-sweep.ts` does the network calls; everything here is deterministic so
 * it can be tested.
 */
import {
  buildJevState,
  describeActionFacts,
  jevIntentThreshold,
  type EffectiveConfig,
  type JevGateScores,
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
  /** Where a case came from, or why it has its label. */
  note?: string;
};

const WANTS = new Set(["allow", "block", "unlabeled"]);

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
    facts: describeActionFacts(action, config.trustedHosts),
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
    cases.push({
      name: `${source}#${entry.decisionId}`,
      want,
      user,
      ...(recentActions.length > 0 ? { recentActions } : {}),
      action: { toolName: action.toolName, input: action.input },
      note,
    });
  }
  return cases;
}

/** Gate scores for one run, and whether the parser verified the action as read-only. */
export type SweepRun = JevGateScores & { readOnly?: boolean };

export type SweepResult = { case: CorpusCase; runs: SweepRun[] };

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
  /** Block cases with at least one run allowed at the current thresholds. */
  missedViolations: string[];
  /** Allow cases with at least one run blocked at the current thresholds. */
  falseBlocks: string[];
};

function round2(value: number): number {
  return Math.round(value * 100) / 100;
}

/** Summarize separation and verdicts at the config's current thresholds. */
export function summarizeSweep(results: SweepResult[], config: EffectiveConfig): SweepSummary {
  // `scope_escape` is advisory, so it never decides a verdict here either.
  const blocked = (run: SweepRun) =>
    run.hard >= config.jevHardDenyThreshold ||
    run.softRule >= config.jevSoftDenyThreshold ||
    run.intent >= jevIntentThreshold(config, run.readOnly === true);
  const allowRuns = results.filter((r) => r.case.want === "allow").flatMap((r) => r.runs);
  const softDependent = results
    .filter((r) => r.case.want === "block")
    .flatMap((r) => r.runs)
    .filter((run) => run.hard < config.jevHardDenyThreshold);
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
      .filter((r) => r.case.want === "block" && r.runs.some((run) => !blocked(run)))
      .map((r) => r.case.name),
    falseBlocks: results
      .filter((r) => r.case.want === "allow" && r.runs.some(blocked))
      .map((r) => r.case.name),
  };
}
