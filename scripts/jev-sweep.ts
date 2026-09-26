/**
 * jev-sweep.ts — replay a labeled corpus against the live Jev endpoint.
 *
 * Development tooling only: not part of the published package.
 *
 *   # Score a corpus (sends cases × runs requests; needs OPENROUTER_API_KEY):
 *   npm run jev:sweep -- --corpus tests/fixtures/jev-corpus.json --runs 3
 *
 *   # Rebuild cases from local automode logs for labeling (no network):
 *   npm run jev:sweep -- --extract-logs ~/.pi/agent/sessions --out .jev-corpus/real.json
 *
 * Cases are scored with the current question and state code and the built-in
 * rules, so a sweep measures the code in this checkout. Real logs contain
 * commands, hosts, and paths from your sessions: keep extracted corpora out of
 * the repository (`.jev-corpus/` is git-ignored).
 */
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import {
  buildEffectiveConfigFromSources,
  buildJevQuestions,
  DEFAULT_JEV_BASE_URL,
  DEFAULT_JEV_MODEL,
  jevDecision,
  jevGateScores,
  missingJevAnswers,
  openRouterDecisionsUrl,
  parseJevResponse,
} from "../extensions/auto-mode.ts";
import {
  caseConfig,
  caseState,
  casesFromLogEntries,
  parseCorpus,
  summarizeSweep,
  type CorpusCase,
  type SweepResult,
} from "./jev-sweep-lib.ts";

function argValues(name: string): string[] {
  const values: string[] = [];
  process.argv.forEach((arg, index) => {
    if (arg === name && process.argv[index + 1]) values.push(process.argv[index + 1]!);
  });
  return values;
}

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

async function sweep(corpusPaths: string[], runs: number, jsonOut?: string): Promise<void> {
  const key = process.env.OPENROUTER_API_KEY;
  if (!key) throw new Error("OPENROUTER_API_KEY is not set");
  const config = buildEffectiveConfigFromSources({});
  const questions = buildJevQuestions(config);
  const url = openRouterDecisionsUrl(DEFAULT_JEV_BASE_URL);
  const cases: CorpusCase[] = [];
  for (const path of corpusPaths) {
    const parsed = parseCorpus(JSON.parse(readFileSync(path, "utf8")));
    for (const error of parsed.errors) console.error(`${path}: ${error}`);
    cases.push(...parsed.cases);
  }
  const only = argValues("--only");
  if (only.length > 0) {
    const keep = new Set(only);
    cases.splice(0, cases.length, ...cases.filter((c) => keep.has(c.name)));
  }
  console.log(
    `${cases.length} cases × ${runs} runs = ${cases.length * runs} requests, ` +
      `${Object.keys(questions).length} questions each`,
  );

  const results: SweepResult[] = [];
  const raw: Array<{ name: string; scores: Record<string, number>[]; errors: string[] }> = [];
  for (const testCase of cases) {
    const state = caseState(testCase, config);
    const scoredConfig = caseConfig(testCase, config);
    const caseQuestions = buildJevQuestions(scoredConfig);
    const result: SweepResult = { case: testCase, runs: [] };
    const record = { name: testCase.name, scores: [] as Record<string, number>[], errors: [] as string[] };
    for (let run = 0; run < runs; run += 1) {
      try {
        const response = await fetch(url, {
          method: "POST",
          redirect: "error",
          headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
          body: JSON.stringify({ model: DEFAULT_JEV_MODEL, state, questions: caseQuestions }),
          signal: AbortSignal.timeout(config.jevTimeoutMs),
        });
        const parsed = parseJevResponse(response.status, await response.text());
        if (!parsed.ok) throw new Error(parsed.error);
        const missing = missingJevAnswers(parsed.scores, caseQuestions);
        if (missing.length > 0) throw new Error(`missing answers: ${missing.join(", ")}`);
        record.scores.push(parsed.scores);
        result.runs.push(jevGateScores(parsed.scores, caseQuestions));
      } catch (error) {
        record.errors.push(error instanceof Error ? error.message : String(error));
      }
    }
    results.push(result);
    raw.push(record);
    const verdicts = record.scores.map((scores) =>
      jevDecision(scores, scoredConfig, caseQuestions).decision
    );
    const wrong = testCase.want !== "unlabeled" &&
      verdicts.some((verdict) => verdict !== testCase.want);
    const f = (pick: (r: SweepResult["runs"][number]) => number) =>
      result.runs.map((r) => pick(r).toFixed(2)).join("/");
    const top = result.runs[0]?.softRuleNumber;
    console.log(
      `${wrong ? "✗" : " "} ${testCase.name.padEnd(34).slice(0, 34)} ${testCase.want.padEnd(9)} ` +
        `soft=${f((r) => r.soft).padEnd(14)} rule=${f((r) => r.softRule).padEnd(14)}` +
        `${top === undefined ? "" : `#${top}`.padEnd(4)} intent=${f((r) => r.intent).padEnd(14)} ` +
        `scope=${f((r) => r.scope).padEnd(14)} hard=${f((r) => r.hard).padEnd(14)} ` +
        `${verdicts.join("/")}${record.errors.length > 0 ? `  errors: ${record.errors.join("; ")}` : ""}`,
    );
  }

  const summary = summarizeSweep(results, config);
  console.log("\nthresholds: " +
    `hard=${config.jevHardDenyThreshold} soft=${config.jevSoftDenyThreshold} scope=${config.jevScopeEscapeThreshold}`);
  console.log(JSON.stringify(summary, null, 2));
  if (jsonOut) {
    mkdirSync(dirname(jsonOut), { recursive: true });
    writeFileSync(jsonOut, `${JSON.stringify({ summary, results: raw }, null, 2)}\n`);
  }
}

const extractDir = argValues("--extract-logs")[0];
if (extractDir) {
  extractLogs(extractDir, argValues("--out")[0] ?? ".jev-corpus/real.json");
} else {
  const corpora = argValues("--corpus");
  if (corpora.length === 0) {
    console.error("usage: jev-sweep.ts --corpus <file> [--corpus <file>] [--runs N] [--only <name>]... [--json <out>]");
    console.error("       jev-sweep.ts --extract-logs <sessions dir> [--out <file>]");
    process.exit(2);
  }
  const runs = Number(argValues("--runs")[0] ?? 3);
  await sweep(corpora, Number.isInteger(runs) && runs > 0 ? runs : 3, argValues("--json")[0]);
}
