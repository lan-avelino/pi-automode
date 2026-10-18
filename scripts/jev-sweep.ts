/**
 * jev-sweep.ts — replay a labeled corpus against a live decision backend
 * (Jev or Clef).
 *
 * Development tooling only: not part of the published package.
 *
 *   # Score a corpus (sends cases × runs requests; needs OPENROUTER_API_KEY):
 *   npm run jev:sweep -- --corpus tests/fixtures/jev-corpus.json --runs 3
 *   npm run jev:sweep -- --corpus tests/fixtures/jev-corpus.json --backend clef --json out.json
 *
 *   # Re-score a saved sweep at other thresholds, or search for thresholds (no network):
 *   npm run jev:sweep -- --rescore out.json --soft 0.5 --hard 0.6 --intent 0.7
 *   npm run jev:sweep -- --rescore out.json --search
 *
 *   # Check that the provider reads the start and the end of a long state:
 *   npm run jev:sweep -- --canary --backend clef --sizes 8000,30000,60000 --runs 3
 *
 *   # Rebuild cases from local automode logs for labeling (no network):
 *   npm run jev:sweep -- --extract-logs ~/.pi/agent/sessions --out .jev-corpus/real.json
 *
 * Cases are scored with the current question and state code and the built-in
 * rules, through the classifier's own client, so a sweep measures the code in
 * this checkout with the same retry policy and provider checks. Real logs
 * contain commands, hosts, and paths from your sessions: keep extracted
 * corpora out of the repository (`.jev-corpus/` is git-ignored).
 */
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import {
  buildDecisionRequest,
  buildEffectiveConfigFromSources,
  buildJevQuestions,
  decisionProfile,
  jevDecision,
  jevGateScores,
  relaxedIntentRead,
  requestDecisionScores,
  runDecisionCanary,
  type DecisionProfile,
} from "../extensions/auto-mode.ts";
import {
  caseConfig,
  caseState,
  casesFromLogEntries,
  parseCorpus,
  parseSavedSweep,
  parseSweepArgs,
  resultsFromSaved,
  searchThresholds,
  summarizeSweep,
  type CorpusCase,
  type SavedRun,
  type SavedSweep,
  type SweepArgs,
  type SweepResult,
} from "./jev-sweep-lib.ts";

/** The sweep runs outside Pi: no registry, no stored credential, no turn signal. */
const SWEEP_CTX = { signal: undefined, modelRegistry: undefined } as unknown as ExtensionContext;
const SWEEP_DEPS = { env: process.env, readStoredCredential: () => undefined };

function findLogs(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return findLogs(path);
    return entry.name.endsWith("-pi-automode.jsonl") ? [path] : [];
  });
}

function readJsonl(path: string): unknown[] {
  return readFileSync(path, "utf8").split("\n").flatMap((line) => {
    if (line.trim() === "") return [];
    try {
      return [JSON.parse(line)];
    } catch {
      return [];
    }
  });
}

function extractLogs(dir: string, out: string): void {
  const cases = findLogs(dir).flatMap((path) =>
    casesFromLogEntries(readJsonl(path), basename(path, "-pi-automode.jsonl"))
  );
  // Re-extracting keeps labels already reviewed in the output file.
  if (existsSync(out)) {
    const previous = parseCorpus(JSON.parse(readFileSync(out, "utf8"))).cases;
    const labels = new Map(previous.map((c) => [c.name, c] as const));
    for (const testCase of cases) {
      const prior = labels.get(testCase.name);
      if (prior && prior.want !== "unlabeled") {
        testCase.want = prior.want;
        if (prior.note) testCase.note = prior.note;
      }
    }
  }
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, `${JSON.stringify({
    description: "Cases rebuilt from local pi-automode logs. Label each want as allow or block. Do not commit.",
    cases,
  }, null, 2)}\n`);
  const counts = cases.reduce<Record<string, number>>((acc, c) => {
    acc[c.want] = (acc[c.want] ?? 0) + 1;
    return acc;
  }, {});
  console.log(`wrote ${cases.length} cases to ${out}`, counts);
}

function thresholdLine(profile: DecisionProfile): string {
  return `thresholds: hard=${profile.hardDeny} soft=${profile.softDeny} ` +
    `read-only intent=${profile.readOnlyIntent} scope=${profile.scopeEscape}`;
}

async function sweep(args: Extract<SweepArgs, { mode: "sweep" }>): Promise<void> {
  const config = buildEffectiveConfigFromSources({});
  const profile = decisionProfile(config, args.backend);
  const cases: CorpusCase[] = [];
  for (const path of args.corpora) {
    const parsed = parseCorpus(JSON.parse(readFileSync(path, "utf8")));
    for (const error of parsed.errors) console.error(`${path}: ${error}`);
    cases.push(...parsed.cases);
  }
  if (args.only.length > 0) {
    const keep = new Set(args.only);
    cases.splice(0, cases.length, ...cases.filter((c) => keep.has(c.name)));
  }
  console.log(
    `${args.backend} (${profile.model}): ${cases.length} cases × ${args.runs} runs = ` +
      `${cases.length * args.runs} requests`,
  );

  const saved: SavedSweep = {
    backend: args.backend,
    model: profile.model,
    date: new Date().toISOString(),
    thresholds: {
      hard: profile.hardDeny,
      soft: profile.softDeny,
      readOnlyIntent: profile.readOnlyIntent,
      scope: profile.scopeEscape,
    },
    cases: [],
  };
  const results: SweepResult[] = [];
  for (const testCase of cases) {
    const state = caseState(testCase, config);
    const scoredConfig = caseConfig(testCase, config);
    const caseQuestions = buildJevQuestions(scoredConfig);
    const readOnly = relaxedIntentRead(state.action ?? "", state.facts ?? "");
    const result: SweepResult = { case: testCase, runs: [] };
    const savedRuns: SavedRun[] = [];
    const verdicts: string[] = [];
    let failedRuns = 0;
    for (let run = 0; run < args.runs; run += 1) {
      const body = buildDecisionRequest(profile, state, caseQuestions);
      const response = await requestDecisionScores(
        SWEEP_CTX,
        scoredConfig,
        profile,
        body,
        caseQuestions,
        SWEEP_DEPS,
      );
      if (!response.ok) {
        failedRuns += 1;
        savedRuns.push({
          ok: false,
          error: response.error ?? response.reason,
          latencyMs: response.durationMs ?? 0,
        });
        continue;
      }
      savedRuns.push({
        ok: true,
        ...(response.provider === undefined ? {} : { provider: response.provider }),
        ...(response.inputTokens === undefined ? {} : { inputTokens: response.inputTokens }),
        latencyMs: response.durationMs,
        readOnly,
        scores: response.scores,
      });
      result.runs.push({ ...jevGateScores(response.scores, caseQuestions), readOnly });
      verdicts.push(
        jevDecision(response.scores, profile, scoredConfig.softDeny, caseQuestions, { readOnly })
          .decision,
      );
    }
    result.failedRuns = failedRuns;
    results.push(result);
    saved.cases.push({
      name: testCase.name,
      want: testCase.want,
      questionIds: Object.keys(caseQuestions),
      runs: savedRuns,
    });
    const wrong = testCase.want !== "unlabeled" &&
      (failedRuns > 0 || verdicts.some((verdict) => verdict !== testCase.want));
    const f = (pick: (r: SweepResult["runs"][number]) => number) =>
      result.runs.map((r) => pick(r).toFixed(2)).join("/");
    const top = result.runs[0]?.softRuleNumber;
    const okRuns = savedRuns.flatMap((r) => r.ok ? [r] : []);
    const providers = [...new Set(okRuns.flatMap((r) => r.provider ? [r.provider] : []))];
    const errors = savedRuns.flatMap((r) => r.ok ? [] : [r.error]);
    console.log(
      `${wrong ? "✗" : " "} ${testCase.name.padEnd(34).slice(0, 34)} ${testCase.want.padEnd(9)} ` +
        `soft=${f((r) => r.soft).padEnd(14)} rule=${f((r) => r.softRule).padEnd(14)}` +
        `${top === undefined ? "" : `#${top}`.padEnd(4)} intent=${f((r) => r.intent).padEnd(14)} ` +
        `scope=${f((r) => r.scope).padEnd(14)} hard=${f((r) => r.hard).padEnd(14)} ` +
        `${verdicts.join("/")}` +
        `${providers.length > 0 ? `  via ${providers.join(",")}` : ""}` +
        `${okRuns.some((r) => r.inputTokens !== undefined) ? ` in=${okRuns.map((r) => r.inputTokens ?? "?").join("/")}` : ""}` +
        `  ms=${savedRuns.map((r) => r.latencyMs).join("/")}` +
        `${errors.length > 0 ? `  errors: ${errors.join("; ")}` : ""}`,
    );
  }

  const summary = summarizeSweep(results, profile);
  console.log(`\nbackend: ${args.backend} (${profile.model}); ${thresholdLine(profile)}`);
  console.log(JSON.stringify(summary, null, 2));
  if (args.json) {
    mkdirSync(dirname(args.json), { recursive: true });
    writeFileSync(args.json, `${JSON.stringify(saved, null, 2)}\n`);
  }
}

function rescore(args: Extract<SweepArgs, { mode: "rescore" }>): void {
  const saved = parseSavedSweep(JSON.parse(readFileSync(args.path, "utf8")));
  const results = resultsFromSaved(saved);
  const base = decisionProfile(buildEffectiveConfigFromSources({}), saved.backend);
  const profile: DecisionProfile = {
    ...base,
    hardDeny: args.overrides.hard ?? base.hardDeny,
    softDeny: args.overrides.soft ?? base.softDeny,
    readOnlyIntent: args.overrides.intent ?? base.readOnlyIntent,
    scopeEscape: args.overrides.scope ?? base.scopeEscape,
  };
  console.log(`${saved.backend} sweep of ${saved.date}: ${results.length} cases`);
  console.log(thresholdLine(profile));
  console.log(JSON.stringify(summarizeSweep(results, profile), null, 2));
  if (args.search) {
    const choice = searchThresholds(results);
    console.log(
      choice === undefined
        ? "search: no thresholds keep every block case blocked with a 0.05 margin (or a block case has failed runs)"
        : `search: ${JSON.stringify(choice)}`,
    );
  }
}

async function canary(args: Extract<SweepArgs, { mode: "canary" }>): Promise<void> {
  const config = buildEffectiveConfigFromSources({});
  const profile = decisionProfile(config, args.backend);
  let allPass = true;
  for (const size of args.sizes) {
    for (let run = 1; run <= args.runs; run += 1) {
      const outcome = await runDecisionCanary(SWEEP_CTX, config, profile, size, SWEEP_DEPS);
      if (outcome.status !== "pass") allPass = false;
      console.log(
        `${size} tokens run ${run}: ${outcome.status}` +
          (outcome.status === "pass"
            ? ` (input ${outcome.inputTokens ?? "?"}; ${JSON.stringify(outcome.scores)})`
            : `: ${outcome.detail}`),
      );
    }
  }
  if (!allPass) process.exitCode = 1;
}

const args = parseSweepArgs(process.argv.slice(2));
switch (args.mode) {
  case "extract":
    extractLogs(args.dir, args.out);
    break;
  case "sweep":
    await sweep(args);
    break;
  case "rescore":
    rescore(args);
    break;
  case "canary":
    await canary(args);
    break;
  case "usage":
    if (args.error) console.error(args.error);
    console.error("usage: jev-sweep.ts --corpus <file> [--corpus <file>] [--backend jev|clef] [--runs N] [--only <name>]... [--json <out>]");
    console.error("       jev-sweep.ts --rescore <saved.json> [--hard P] [--soft P] [--intent P] [--scope P] [--search]");
    console.error("       jev-sweep.ts --canary [--backend clef] [--sizes 8000,30000,60000] [--runs N]");
    console.error("       jev-sweep.ts --extract-logs <sessions dir> [--out <file>]");
    process.exit(2);
}
