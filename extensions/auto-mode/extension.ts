import { existsSync, realpathSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type {
  ExtensionAPI,
  ExtensionCommandContext,
  ExtensionContext,
  ToolCallEvent,
} from "@earendil-works/pi-coding-agent";
import { StringEnum } from "@earendil-works/pi-ai";
import { Type } from "typebox";
import {
  classifierReasoningForConfig,
  defaultClassifyAction,
  serializeClassifierAction,
} from "./classifier.ts";
import { approvalSignature, type ApprovalSignature } from "./approvals.ts";
import { analyzeBash, type BashAnalysis } from "./bash.ts";
import {
  AUTO_MODE_GUIDANCE,
  CLEF_CANARY_SIZES,
  DEFAULT_ALLOW,
  DEFAULT_ENVIRONMENT,
  DEFAULT_HARD_DENY,
  DEFAULT_PROTECTED_PATHS,
  DEFAULT_SOFT_DENY,
  PATH_BEARING_TOOLS,
  PI_GLOBAL_SETTINGS,
  READ_ONLY_TOOLS,
} from "./constants.ts";
import {
  type GlobalAutoModeSettingKey,
  type GlobalConfigPreparation,
  loadEffectiveConfigWithDiagnostics,
  prepareGlobalConfig,
  isClassifierBackend,
  scratchRootPath,
  writeGlobalAutoModeSetting,
} from "./config.ts";
import {
  CreatedPaths,
  type CreatedPathsFs,
  NODE_CREATED_PATHS_FS,
  type ClaimSet,
  birthTimesUsable as probeBirthTimes,
  planActionOrPrefix,
} from "./created-paths.ts";
import { describeActionFacts } from "./facts.ts";
import { deterministicHardDeny } from "./hard-deny.ts";
import {
  decisionLabel,
  decisionProfile,
  defaultJevClassifyAction,
  factsReadOnly,
  isDecisionBackend,
  jevCredentialDiagnostics,
  jevStatusText,
  probeJevClassifier,
  resolveJevKey,
  runDecisionCanary,
} from "./jev.ts";
import {
  createLogger,
  newDecisionId,
  resolveLogPath,
  type Logger,
} from "./log.ts";
import { formatModelSpec, parseModelSpec } from "./model.ts";
import { promptForClassifierModel } from "./model-selector.ts";
import {
  matchesAllowedToolPatterns,
  matchesDeniedPath,
  matchesToolPattern,
  matchingBashCommandText,
  recursiveSearchMayReachDeniedPath,
} from "./permissions.ts";
import {
  extractInputPath,
  isInside,
  isProtectedPath,
  resolvePathForPolicy,
  resolveToolInputPath,
} from "./paths.ts";
import {
  actionSummary,
  classifierStatusLines,
  formatDenials,
  pushDenial,
  restoreState,
  statusLine,
  statusText,
} from "./state.ts";
import { loadedContextFromSystemPromptOptions } from "./transcript.ts";
import type {
  AutoModeState,
  ClassifierReasoningLog,
  ClassifyAction,
  ClassifyResult,
  ConfigLoadResult,
  DecisionBackend,
  DecisionKind,
  DenialRecord,
  EffectiveConfig,
} from "./types.ts";
import { safeJson, truncateMiddle } from "./utils.ts";

const INSPECT_TOOL = "automode_inspect";
const INSPECTION_ACTIONS = ["status", "config", "defaults", "denials"] as const;
type InspectionAction = (typeof INSPECTION_ACTIONS)[number];

function matchedCommandSummary(command: string | undefined): string | undefined {
  return command ? truncateMiddle(command, 500) : undefined;
}

function canonicalPath(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    return resolve(path);
  }
}

const EXTENSION_PATH = canonicalPath(fileURLToPath(import.meta.url));
const EXTENSION_ENTRY_PATH = canonicalPath(
  resolve(dirname(EXTENSION_PATH), "../auto-mode.ts"),
);

export function modelVisibleConfigDiagnostics(
  diagnostics: string[],
): string[] {
  return diagnostics.map((diagnostic) =>
    diagnostic.replace(
      /invalid JSON \([\s\S]*\)$/,
      "invalid JSON (parser details omitted from model-visible output)",
    )
  );
}

function projectIsTrusted(
  ctx: { isProjectTrusted?: () => boolean },
): boolean {
  return typeof ctx.isProjectTrusted === "function"
    ? ctx.isProjectTrusted()
    : false;
}

export type PiAutomodeOptions = {
  /** Override config loading in tests. Runtime code uses Pi-owned disk settings. */
  loadConfig?: (cwd: string, projectTrusted: boolean) => EffectiveConfig;
  /** Override classifier calls in tests so unit tests never need a real LLM/API key. */
  classifyAction?: ClassifyAction;
  /** Override the Jev classifier in tests. */
  jevClassifyAction?: ClassifyAction;
  /** Override classifier-model persistence in tests. Runtime code writes the active global config. */
  saveClassifierModel?: (classifierModel: string) => void;
  /** Override one autoMode setting's global persistence in tests. */
  saveAutoModeSetting?: (key: PersistableSettingKey, value: string) => void;
  /** Override global config migration and path selection in tests. */
  prepareGlobalConfig?: () => GlobalConfigPreparation;
  /** Override the application-owned observability log root in tests. */
  logRoot?: string;
  /** Override the observability log clock in tests. */
  now?: () => Date;
  /** Override Bash analysis in tests. Runtime code uses unbash. */
  analyzeBash?: typeof analyzeBash;
  /** Override the filesystem of the session-created path record in tests. */
  createdPathsFs?: CreatedPathsFs;
  /** Override the session-created path record's clock in tests. */
  createdPathsNow?: () => Date;
  /** Override the birth-time probe in tests. */
  birthTimesUsable?: () => Promise<boolean>;
};

type PersistableSettingKey = GlobalAutoModeSettingKey;

/**
 * True only when a person can answer a dialog. pi reports `hasUI` in RPC mode
 * too, but an RPC client such as a pi-subagents child never answers, so a
 * prompt there would block the agent forever.
 */
/**
 * The folder offered by "Allow edits under … for this session": the git
 * repository containing the file, or else the file's own folder. Undefined when
 * that folder is not a valid scratch root, such as the home directory.
 */
function sessionEditFolder(path: string): string | undefined {
  const start = dirname(path);
  for (let dir = start; ; dir = dirname(dir)) {
    if (existsSync(join(dir, ".git"))) return scratchRootPath(dir);
    if (dirname(dir) === dir) break;
  }
  return scratchRootPath(start);
}

function canAskUser(ctx: ExtensionContext): boolean {
  return ctx.hasUI && ctx.mode === "tui";
}

type LogCtx = {
  logger: Logger;
  decisionId: string;
  classifierModel?: string;
  reasoning: ClassifierReasoningLog;
};

/** Append ccusage-compatible usage and optional classifier I/O entries. */
function logClassifierIo(decision: ClassifyResult, log: LogCtx): void {
  if (decision.reasoning) log.reasoning = decision.reasoning;
  if (decision.io) log.reasoning = decision.io.reasoning;
  if (!log.logger.enabled || !decision.io) return;

  for (const attempt of decision.io.attempts) {
    const response = attempt.response;
    if (!response) continue;
    log.logger.append({
      type: "message",
      timestamp: new Date(response.timestamp).toISOString(),
      message: {
        role: "assistant",
        model: response.model,
        usage: response.usage,
      },
    });
  }

  if (!log.logger.classifierIo) return;
  log.logger.append({
    type: "classifier",
    ts: new Date().toISOString(),
    decisionId: log.decisionId,
    model: decision.io.model,
    reasoning: decision.io.reasoning,
    prompt: decision.io.prompt,
    attempts: decision.io.attempts,
    durationMs: decision.io.durationMs,
    ...(decision.io.cached ? { cached: true } : {}),
    parsed: {
      decision: decision.decision,
      tier: decision.tier,
      reason: decision.reason,
    },
  });
}

/** Create a Pi extension instance. Default export uses production dependencies. */
export function createPiAutomode(options: PiAutomodeOptions = {}) {
  const classifyLlm = options.classifyAction ?? defaultClassifyAction;
  const classifyJev = options.jevClassifyAction ?? defaultJevClassifyAction;
  const selectClassify = (cfg: EffectiveConfig) =>
    isDecisionBackend(cfg.classifierBackend) ? classifyJev : classifyLlm;
  const now = options.now ?? (() => new Date());

  return function piAutomode(pi: ExtensionAPI) {
    const globalConfig = options.prepareGlobalConfig?.() ??
      (options.loadConfig
        ? { status: "current" as const, activePath: PI_GLOBAL_SETTINGS[0] }
        : prepareGlobalConfig());
    const loadConfigWithDiagnostics = (
      cwd: string,
      projectTrusted: boolean,
    ): ConfigLoadResult => {
      const result = options.loadConfig
        ? {
          config: options.loadConfig(cwd, projectTrusted),
          diagnostics: [],
        }
        : loadEffectiveConfigWithDiagnostics(
          cwd,
          projectTrusted,
          globalConfig.activePath,
        );
      return globalConfig.diagnostic
        ? {
          ...result,
          diagnostics: [...result.diagnostics, globalConfig.diagnostic],
        }
        : result;
    };
    const writeBlockedReason = globalConfig.writeBlockedReason;
    const persistAutoModeSetting = options.saveAutoModeSetting ??
      ((key: PersistableSettingKey, value: string) =>
        writeGlobalAutoModeSetting(key, value, globalConfig.activePath));
    const saveAutoModeSetting = writeBlockedReason
      ? (_key: PersistableSettingKey, _value: string): void => {
        throw new Error(writeBlockedReason);
      }
      : persistAutoModeSetting;
    const persistClassifierModel = options.saveClassifierModel ??
      ((classifierModel: string) =>
        persistAutoModeSetting("classifierModel", classifierModel));
    const saveClassifierModel = writeBlockedReason
      ? (_classifierModel: string): void => {
        throw new Error(writeBlockedReason);
      }
      : persistClassifierModel;
    let loadResult = loadConfigWithDiagnostics(process.cwd(), false);
    let config: EffectiveConfig = loadResult.config;
    let configDiagnostics: string[] = loadResult.diagnostics;
    // Parser-derived patterns the user chose to allow for this session after a
    // Jev soft deny. In memory only and cleared at session start.
    const sessionApprovals = new Map<string, string>();
    // Folders the user chose "Allow edits under … for this session" for. They
    // act as scratch roots until the session starts again.
    const sessionEditRoots = new Set<string>();
    // pi shows one extension dialog at a time: opening a second replaces the
    // first, whose promise then never settles. Parallel tool calls (such as a
    // codemode Promise.all) would hang on the hidden dialog, so dialogs from
    // this extension wait for the previous one to close.
    let dialogQueue: Promise<unknown> = Promise.resolve();
    const oneDialogAtATime = <T>(open: () => Promise<T>): Promise<T> => {
      const result = dialogQueue.then(open);
      dialogQueue = result.catch(() => undefined);
      return result;
    };
    let state: AutoModeState = {
      checkedActions: 0,
      blockedActions: 0,
      classifierAllowed: 0,
      classifierDenied: 0,
      recentDenials: [],
    };
    let loadedContext = "";
    let globalConfigNoticeShown = false;

    function effectiveConfig(): EffectiveConfig {
      return {
        ...config,
        enabled: state.enabledOverride ?? config.enabled,
      };
    }

    const APPROVALS_CLEARED =
      "; session approvals cleared because the classifier changed";

    /** The classifier a session approval answers: the backend and, for a decision backend, its model. */
    function classifierIdentity(cfg: EffectiveConfig): string {
      const backend = cfg.classifierBackend;
      return isDecisionBackend(backend)
        ? `${backend}:${decisionProfile(cfg, backend).model}`
        : backend;
    }

    /**
     * Apply a config load. A session approval answers one model's soft denies,
     * so approvals are cleared when the backend or its model changes. Edit
     * roots skip the classifier, like scratch roots, and are kept.
     */
    function applyLoadResult(
      next: ConfigLoadResult,
    ): { approvalsCleared: boolean } {
      const before = classifierIdentity(config);
      loadResult = next;
      config = next.config;
      configDiagnostics = next.diagnostics;
      if (
        classifierIdentity(config) === before || sessionApprovals.size === 0
      ) {
        return { approvalsCleared: false };
      }
      sessionApprovals.clear();
      return { approvalsCleared: true };
    }

    function ownsInspectionTool(): boolean {
      const tool = pi.getAllTools().find(({ name }) => name === INSPECT_TOOL);
      if (!tool) return false;
      const sourcePath = canonicalPath(tool.sourceInfo.path);
      return sourcePath === EXTENSION_PATH || sourcePath === EXTENSION_ENTRY_PATH;
    }

    function persist(): void {
      pi.appendEntry("pi-automode-state", state);
    }

    function updateUi(ctx: ExtensionContext): void {
      if (!ctx.hasUI) return;
      const cfg = effectiveConfig();
      const text = statusLine(cfg, state);
      ctx.ui.setStatus(
        "pi-automode",
        cfg.enabled
          ? ctx.ui.theme.fg("accent", text)
          : ctx.ui.theme.fg("dim", text),
      );
    }

    function inspectAutomode(
      action: InspectionAction,
      ctx: ExtensionContext,
    ): unknown {
      const cfg = effectiveConfig();
      if (action === "status") {
        const status = [
          `enabled: ${cfg.enabled ? "yes" : "no"}`,
          ...classifierStatusLines(cfg),
          `checked actions: ${state.checkedActions}`,
          `blocked actions: ${state.blockedActions}`,
          `classifier allowed: ${state.classifierAllowed}`,
          `classifier denied: ${state.classifierDenied}`,
          `permissions.deny rules: ${cfg.permissionDeny.length}`,
          `permissions.ask rules: ${cfg.permissionAsk.length}`,
          `permissions.allow rules: ${cfg.permissionAllow.length}`,
          `environment entries: ${cfg.environment.length}`,
          `allow entries: ${cfg.allow.length}`,
          `soft_deny entries: ${cfg.softDeny.length}`,
          `hard_deny entries: ${cfg.hardDeny.length}`,
          `last decision: ${state.lastDecision ?? "none"}`,
          "last reason: omitted from model-visible inspection",
        ].join("\n");
        return {
          status,
          state: {
            enabledOverride: state.enabledOverride,
            lastDecision: state.lastDecision,
            checkedActions: state.checkedActions,
            blockedActions: state.blockedActions,
            classifierAllowed: state.classifierAllowed,
            classifierDenied: state.classifierDenied,
          },
        };
      }
      if (action === "config") {
        return {
          config: cfg,
          logFile: resolveLogPath(
            ctx.sessionManager.getSessionFile?.(),
            ctx.sessionManager.getSessionDir?.() ?? "",
            ctx.sessionManager.getSessionId?.() ?? "unknown",
            ctx.cwd,
            options.logRoot,
            now(),
          ),
          diagnostics: modelVisibleConfigDiagnostics(configDiagnostics),
        };
      }
      if (action === "defaults") {
        return {
          environment: DEFAULT_ENVIRONMENT,
          allow: DEFAULT_ALLOW,
          protectedPaths: DEFAULT_PROTECTED_PATHS,
          soft_deny: DEFAULT_SOFT_DENY,
          hard_deny: DEFAULT_HARD_DENY,
        };
      }
      const denials = state.recentDenials.slice().reverse().map((denial) => ({
        timestamp: denial.timestamp,
        kind: denial.kind,
        toolName: denial.toolName,
      }));
      return {
        summary: denials.length === 0
          ? "No recent auto-mode denials."
          : `${denials.length} recent auto-mode denial(s). Reasons and action payloads are omitted.`,
        denials,
      };
    }

    function blockedToolReason(reason: string): string {
      return `[pi-automode] Action blocked; the tool did not run. ${reason} Do not claim success, rely on effects from this call, or attempt an equivalent workaround. Report the block to the user before continuing with dependent work. Independent work can continue.`;
    }

    /**
     * Classifier provenance belongs only on classifier-routed decisions. A
     * deterministic or permission decision never calls the classifier, so recording a
     * classifier model and reasoning mode on it implies a verdict that was never
     * requested and sends a reader looking for a `classifier` entry that does not exist.
     */
    function classifierFields(
      kind: DecisionKind,
      logCtx: LogCtx,
    ): { classifierModel?: string; reasoning?: ClassifierReasoningLog } {
      return kind === "classifier" || kind === "classifier.confirmed"
        ? {
            classifierModel: logCtx.classifierModel,
            reasoning: logCtx.reasoning,
          }
        : {};
    }

    function block(
      ctx: ExtensionContext,
      denial: DenialRecord,
      logCtx: LogCtx,
    ): { block: true; reason: string } {
      state.blockedActions += 1;
      state.lastDecision = "block";
      state.lastReason = denial.reason;
      pushDenial(state, denial);
      persist();
      updateUi(ctx);
      if (logCtx.logger.enabled) {
        logCtx.logger.append({
          type: "decision",
          ts: new Date().toISOString(),
          decisionId: logCtx.decisionId,
          sessionId: ctx.sessionManager.getSessionId?.(),
          cwd: ctx.cwd,
          tool: denial.toolName,
          summary: denial.action,
          kind: denial.kind,
          outcome: "block",
          reason: denial.reason,
          ...classifierFields(denial.kind, logCtx),
        });
      }
      if (ctx.hasUI) {
        ctx.ui.notify(
          `Auto mode blocked ${denial.toolName}: ${denial.reason}`,
          "warning",
        );
      }
      return {
        block: true,
        reason: blockedToolReason(denial.reason),
      };
    }

    function allow(
      ctx: ExtensionContext,
      kind: DecisionKind,
      reason: string,
      toolName: string,
      summary: string,
      logCtx: LogCtx,
    ): undefined {
      state.lastDecision = "allow";
      state.lastReason = reason;
      persist();
      updateUi(ctx);
      if (logCtx.logger.enabled) {
        logCtx.logger.append({
          type: "decision",
          ts: new Date().toISOString(),
          decisionId: logCtx.decisionId,
          sessionId: ctx.sessionManager.getSessionId?.(),
          cwd: ctx.cwd,
          tool: toolName,
          summary,
          kind,
          outcome: "allow",
          reason,
          ...classifierFields(kind, logCtx),
        });
      }
      return undefined;
    }

    // Paths the agent created this session, for Jev's created_this_session
    // facts. Memory only: the agent can write session entries, so nothing is
    // restored from them. Off until birth times are known to be real.
    const createdPaths = new CreatedPaths({
      fs: options.createdPathsFs ?? NODE_CREATED_PATHS_FS,
      now: options.createdPathsNow,
    });
    void (options.birthTimesUsable ?? probeBirthTimes)().then(
      (usable) => createdPaths.setUsable(usable),
      () => createdPaths.setUsable(false),
    );
    /** Claims computed for a call in progress, read by the classifier call. */
    const callClaims = new Map<string, { claims: ClaimSet; shownToJev: boolean }>();

    pi.on("session_start", (_event, ctx) => {
      createdPaths.clear();
      applyLoadResult(loadConfigWithDiagnostics(ctx.cwd, projectIsTrusted(ctx)));
      // Names already in the session folder count as the user's, even if the
      // user moves them away before the first bash call. Best effort.
      if (effectiveConfig().enabled && isDecisionBackend(effectiveConfig().classifierBackend)) {
        void createdPaths.baseline(ctx.cwd);
      }
      state = restoreState(ctx);
      sessionApprovals.clear();
      sessionEditRoots.clear();
      if (
        ctx.hasUI &&
        globalConfig.notification &&
        !globalConfigNoticeShown
      ) {
        ctx.ui.notify(
          globalConfig.notification,
          globalConfig.status === "migrated" ? "info" : "warning",
        );
        globalConfigNoticeShown = true;
      }
      updateUi(ctx);
    });

    pi.on("before_agent_start", (event) => {
      const cfg = effectiveConfig();
      if (!cfg.enabled) return undefined;
      loadedContext = loadedContextFromSystemPromptOptions(
        event.systemPromptOptions,
      );
      return { systemPrompt: `${event.systemPrompt}\n\n${AUTO_MODE_GUIDANCE}` };
    });

    const makeLogCtx = (cfg: EffectiveConfig, ctx: ExtensionContext): LogCtx => {
      const backend = cfg.classifierBackend;
      const decisionModel = isDecisionBackend(backend)
        ? decisionProfile(cfg, backend).model
        : undefined;
      return {
        logger: createLogger({
          enabled: cfg.log.enabled,
          classifierIo: cfg.log.classifierIo,
          sessionFile: ctx.sessionManager.getSessionFile?.(),
          sessionDir: ctx.sessionManager.getSessionDir?.() ?? "",
          sessionCwd: ctx.cwd,
          sessionId: ctx.sessionManager.getSessionId?.() ?? "unknown",
          logRoot: options.logRoot,
          now: now(),
        }),
        decisionId: newDecisionId(),
        classifierModel: decisionModel ?? cfg.classifierModel,
        reasoning: isDecisionBackend(backend)
          ? { mode: "backend", backend, model: decisionModel! }
          : classifierReasoningForConfig(cfg.classifierReasoningLevel),
      };
    };

    const decideToolCall = async (
      event: ToolCallEvent,
      ctx: ExtensionContext,
    ): Promise<{ block: true; reason: string } | undefined> => {
      // Enforcement order:
      // 1. permission deny/ask rules,
      // 2. deterministic hard-deny checks that never consult the model,
      // 3. extension-owned read-only inspection tool,
      // 4. deterministic path denials,
      // 5. accepted ask rules force classifier review and skip all allow tiers,
      // 6. inside-CWD, permissions.allow, and read-only allow tiers,
      // 7. classifier for every remaining action, fail-closed on setup/parse errors.
      const cfg = effectiveConfig();
      if (!cfg.enabled) return undefined;

      const input = event.input as Record<string, unknown>;
      const summary = actionSummary(event.toolName, input);
      const logCtx = makeLogCtx(cfg, ctx);

      if (ctx.signal?.aborted) {
        state.checkedActions += 1;
        return block(ctx, {
          timestamp: Date.now(),
          toolName: event.toolName,
          reason: "Cancelled",
          action: summary,
          kind: "setup",
        }, logCtx);
      }

      const isOwnedInspection = event.toolName === INSPECT_TOOL &&
        ownsInspectionTool();
      let bashAnalysis: BashAnalysis | undefined;
      if (event.toolName === "bash") {
        const source = typeof input.command === "string" ? input.command : "";
        try {
          bashAnalysis = (options.analyzeBash ?? analyzeBash)(source);
        } catch (error) {
          bashAnalysis = {
            source,
            commands: [],
            redirects: [],
            redirectTargets: [],
            structure: [],
            allowStructureSafe: false,
            errors: [{
              message: `Bash analysis failed: ${
                error instanceof Error ? error.message : String(error)
              }`,
            }],
          };
        }
      }
      if (!isOwnedInspection) state.checkedActions += 1;

      for (const pattern of cfg.permissionDeny) {
        if (
          matchesToolPattern(
            pattern,
            event.toolName,
            input,
            ctx.cwd,
            "match",
            bashAnalysis,
          )
        ) {
          const matchedCommand = matchedCommandSummary(
            matchingBashCommandText(pattern, bashAnalysis),
          );
          if (isOwnedInspection) state.checkedActions += 1;
          return block(ctx, {
            timestamp: Date.now(),
            toolName: event.toolName,
            reason: `Blocked by permissions.deny: ${pattern.raw}${
              matchedCommand ? `; matched command: ${matchedCommand}` : ""
            }`,
            action: summary,
            kind: "permissions.deny",
          }, logCtx);
        }
      }

      // One confirmation per tool call, however many ask rules match it.
      const askMatches = cfg.permissionAsk.filter((pattern) =>
        matchesToolPattern(
          pattern,
          event.toolName,
          input,
          ctx.cwd,
          "match",
          bashAnalysis,
        )
      );
      let askRequiresClassifier = false;
      if (askMatches.length > 0) {
        const askRules = askMatches.map((pattern) => pattern.raw).join(", ");
        const matchedCommand = matchedCommandSummary(
          matchingBashCommandText(askMatches[0], bashAnalysis),
        );
        if (!canAskUser(ctx)) {
          if (isOwnedInspection) state.checkedActions += 1;
          return block(ctx, {
            timestamp: Date.now(),
            toolName: event.toolName,
            reason:
              `Matched permissions.ask (${askRules})${
                matchedCommand ? ` for command: ${matchedCommand}` : ""
              } but no interactive terminal is available`,
            action: summary,
            kind: "permissions.ask",
          }, logCtx);
        }
        const allowed = await oneDialogAtATime(() =>
          ctx.ui.confirm(
            "Auto mode permission ask",
            `${
              askMatches.length === 1 ? "Rule" : "Rules"
            }: ${askRules}\n\nAction:\n${summary}\n\nAllow this action to continue to auto-mode classification?`,
            { signal: ctx.signal },
          )
        );
        if (!allowed) {
          if (isOwnedInspection) state.checkedActions += 1;
          return block(ctx, {
            timestamp: Date.now(),
            toolName: event.toolName,
            reason: `Declined permissions.ask: ${askRules}${
              matchedCommand ? `; matched command: ${matchedCommand}` : ""
            }`,
            action: summary,
            kind: "permissions.ask",
          }, logCtx);
        }
        askRequiresClassifier = true;
      }

      const deterministicReason = deterministicHardDeny(
        event.toolName,
        input,
        ctx.cwd,
        bashAnalysis,
      );
      if (deterministicReason) {
        if (isOwnedInspection) state.checkedActions += 1;
        return block(ctx, {
          timestamp: Date.now(),
          toolName: event.toolName,
          reason: deterministicReason,
          action: summary,
          kind: "deterministic-hard-deny",
        }, logCtx);
      }

      if (isOwnedInspection && !askRequiresClassifier) return undefined;
      if (isOwnedInspection) state.checkedActions += 1;

      // Deterministic path gate for file tools.
      //
      // `deniedPaths` always applies: a matching path is hard-denied before any
      // classifier or fast path, so secrets and system dirs never reach the
      // model. `allowInsideWorkingDirectory` adds a deterministic silent-allow
      // tier for file tools whose resolved path is inside the working
      // directory, and routes outside-CWD file access to the classifier
      // (bypassing the read-only fast path so reads outside the tree are
      // reviewed too).
      //
      // The gate is skipped entirely when both features are off, so the
      // default configuration costs no extra filesystem calls.
      let readOnlyFastPath =
        !askRequiresClassifier &&
        !cfg.classifyReadOnlyTools &&
        READ_ONLY_TOOLS.has(event.toolName);
      if (
        (cfg.deniedPaths.length > 0 || cfg.allowInsideWorkingDirectory ||
          cfg.scratchRoots.length > 0 || sessionEditRoots.size > 0) &&
        PATH_BEARING_TOOLS.has(event.toolName)
      ) {
        const inputPath = extractInputPath(event.toolName, input);
        if (inputPath !== undefined) {
          const resolved =
            resolveToolInputPath(event.toolName, ctx.cwd, inputPath) ??
            inputPath;
          const policyPath = resolvePathForPolicy(resolved) ?? resolved;
          const denied =
            cfg.deniedPaths.length > 0 &&
            (matchesDeniedPath(resolved, cfg.deniedPaths) ||
              matchesDeniedPath(policyPath, cfg.deniedPaths));
          if (denied) {
            return block(ctx, {
              timestamp: Date.now(),
              toolName: event.toolName,
              reason: `Path denied by policy: ${policyPath}`,
              action: summary,
              kind: "deterministic-path-deny",
            }, logCtx);
          }
          let recursiveSearch =
            event.toolName === "grep" || event.toolName === "find";
          if (recursiveSearch) {
            try {
              recursiveSearch = statSync(policyPath).isDirectory();
            } catch {
              // A missing search root will fail in the tool. Treat it as a
              // directory here so a denied scope cannot fail open in a race.
            }
          }
          const deniedSearchScope =
            recursiveSearch &&
            cfg.deniedPaths.length > 0 &&
            (recursiveSearchMayReachDeniedPath(resolved, cfg.deniedPaths) ||
              recursiveSearchMayReachDeniedPath(
                policyPath,
                cfg.deniedPaths,
              ));
          if (deniedSearchScope) {
            return block(ctx, {
              timestamp: Date.now(),
              toolName: event.toolName,
              reason: `Search scope can contain a path denied by policy: ${policyPath}`,
              action: summary,
              kind: "deterministic-path-deny",
            }, logCtx);
          }
          if (cfg.allowInsideWorkingDirectory) {
            const policyCwd = resolvePathForPolicy(ctx.cwd) ?? ctx.cwd;
            if (isInside(policyPath, policyCwd)) {
              // Protected in-tree writes and accepted ask rules must still
              // reach the classifier. They cannot use the inside-CWD tier.
              const protectedWrite =
                (event.toolName === "write" || event.toolName === "edit") &&
                isProtectedPath(policyPath, policyCwd, cfg.protectedPaths);
              if (!askRequiresClassifier && !protectedWrite) {
                return allow(
                  ctx,
                  "inside-working-directory",
                  `Path inside working directory: ${policyPath}`,
                  event.toolName,
                  summary,
                  logCtx,
                );
              }
            }
            // Outside the working directory, protected writes, and accepted
            // ask rules must not use the read-only fast path.
            readOnlyFastPath = false;
          }
          // Scratch roots are user-declared throwaway directories, such as a
          // clone the session made under /tmp. Writes there skip the classifier,
          // except protected paths (matched at any depth) and accepted ask rules.
          if (
            (event.toolName === "write" || event.toolName === "edit") &&
            (cfg.scratchRoots.length > 0 || sessionEditRoots.size > 0) &&
            !askRequiresClassifier
          ) {
            const root = [...cfg.scratchRoots, ...sessionEditRoots]
              .map((entry) => resolvePathForPolicy(entry) ?? entry)
              .find((entry) => isInside(policyPath, entry));
            if (
              root !== undefined &&
              !isProtectedPath(policyPath, root, cfg.protectedPaths)
            ) {
              return allow(
                ctx,
                "scratch-root",
                `Path inside scratch root ${root}: ${policyPath}`,
                event.toolName,
                summary,
                logCtx,
              );
            }
          }
        }
      }

      // Deterministic allow tier. It runs after every deterministic denial.
      // Accepted ask rules skip this tier and always reach the classifier.
      if (!askRequiresClassifier) {
        if (
          matchesAllowedToolPatterns(
            cfg.permissionAllow,
            event.toolName,
            input,
            ctx.cwd,
            bashAnalysis,
          )
        ) {
          // A protected-path write/edit is never covered by permissions.allow;
          // it stays on the classifier path (same rule as the inside-CWD tier).
          let protectedWrite = false;
          if (event.toolName === "write" || event.toolName === "edit") {
            const inputPath = extractInputPath(event.toolName, input);
            const resolved = inputPath === undefined
              ? undefined
              : resolveToolInputPath(event.toolName, ctx.cwd, inputPath) ??
                inputPath;
            if (
              resolved !== undefined &&
              isProtectedPath(resolved, ctx.cwd, cfg.protectedPaths)
            ) {
              protectedWrite = true;
            }
          }
          if (!protectedWrite) {
            return allow(
              ctx,
              "permissions.allow",
              "Allowed by permissions.allow",
              event.toolName,
              summary,
              logCtx,
            );
          }
        }
      }

      if (readOnlyFastPath) {
        return allow(
          ctx,
          "read-only",
          `Read-only built-in tool: ${event.toolName}`,
          event.toolName,
          summary,
          logCtx,
        );
      }

      // Session-created path claims, computed by the tool_call wrapper.
      const pending = callClaims.get(event.toolCallId);
      const extraFacts = pending?.claims.lines ?? [];
      if (pending && extraFacts.length > 0) pending.shownToJev = true;
      const decision = await selectClassify(cfg)(
        ctx,
        cfg,
        serializeClassifierAction(event.toolName, input),
        loadedContext,
        ...(extraFacts.length > 0 ? [{ extraFacts }] as const : []),
      );
      logClassifierIo(decision, logCtx);
      if (decision.decision === "allow") {
        state.classifierAllowed += 1;
        return allow(
          ctx,
          "classifier",
          decision.reason,
          event.toolName,
          summary,
          logCtx,
        );
      }

      // When a script is blocked as "overwriting existing files" but the files
      // are where the edit tools are already allowed, say so, so the agent can
      // redo the change with them instead of repeating the script.
      const declineHint = (): string => {
        if (event.toolName !== "bash" || typeof input.command !== "string") return "";
        if (decision.softDenyRule !== DEFAULT_SOFT_DENY[3]) return "";
        const source = input.command;
        const mentions = (location: string) =>
          new RegExp(`${location.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?=/|\\s|$|["';])`).test(source);
        const locations = [...cfg.scratchRoots, ...sessionEditRoots].filter(mentions);
        const leavesProject = /(^|[\s;&|(])cd\s+["']?[/~]/.test(source) && !mentions(ctx.cwd);
        if (cfg.allowInsideWorkingDirectory && !leavesProject) locations.push(ctx.cwd);
        if (locations.length === 0) return "";
        return ` Hint: this was flagged as overwriting existing files, but the edit and write tools are allowed without review under ${
          [...new Set(locations)].join(", ")
        } (protected files excepted). Make this change with them instead of a script.`;
      };

      const askSoftDeny = async (
        signature: ApprovalSignature | undefined,
      ): Promise<ReturnType<typeof block> | undefined> => {
        const allowOnce = "Allow once";
        // One-off commands would never match again, so "similar" is offered
        // only for patterns short enough to recur.
        const allowSimilar = signature?.recurs
          ? `Allow similar for this session: ${signature.description}`
          : undefined;
        // For an edit, offer its repository or folder for the rest of the
        // session, so a run of edits in one clone asks once.
        const editPath = event.toolName === "write" || event.toolName === "edit"
          ? extractInputPath(event.toolName, input)
          : undefined;
        const resolvedEditPath = editPath === undefined
          ? undefined
          : resolveToolInputPath(event.toolName, ctx.cwd, editPath) ?? editPath;
        const editFolder = resolvedEditPath === undefined
          ? undefined
          : sessionEditFolder(resolvePathForPolicy(resolvedEditPath) ?? resolvedEditPath);
        const allowFolder = editFolder === undefined
          ? undefined
          : `Allow edits under ${editFolder} for this session`;
        const deny = "Deny";
        let choice: string | undefined;
        let outcome = "The user declined it.";
        try {
          choice = await oneDialogAtATime(() =>
            ctx.ui.select(
              `Auto mode soft deny\n\n${decision.reason}\n\nAction:\n${summary}`,
              [
                allowOnce,
                ...(allowSimilar ? [allowSimilar] : []),
                ...(allowFolder ? [allowFolder] : []),
                deny,
              ],
              { signal: ctx.signal },
            )
          );
        } catch {
          // A cancelled or failed prompt is not an approval.
          outcome = "The approval prompt was cancelled or failed.";
        }
        if (allowFolder && choice === allowFolder) {
          sessionEditRoots.add(editFolder!);
          state.classifierAllowed += 1;
          return allow(
            ctx,
            "classifier.confirmed",
            `User approved edits under ${editFolder} for this session: ${decision.reason}`,
            event.toolName,
            summary,
            logCtx,
          );
        }
        if (choice === allowOnce || (allowSimilar && choice === allowSimilar)) {
          if (signature && choice === allowSimilar) {
            sessionApprovals.set(signature.key, signature.description);
          }
          state.classifierAllowed += 1;
          return allow(
            ctx,
            "classifier.confirmed",
            `${
              choice === allowOnce
                ? `User approved a ${
                  decisionLabel(cfg.classifierBackend as DecisionBackend)
                } soft deny once`
                : `User approved similar actions for this session (${signature!.description})`
            }: ${decision.reason}`,
            event.toolName,
            summary,
            logCtx,
          );
        }
        state.classifierDenied += 1;
        return block(ctx, {
          timestamp: Date.now(),
          toolName: event.toolName,
          reason: `${decision.reason} ${outcome}${declineHint()}`,
          action: summary,
          kind: "classifier",
        }, logCtx);
      };

      // A Jev soft deny is a probability near a measured threshold, not a rule
      // match, so an interactive user may approve it: once, or for the rest of
      // the session for a parser-derived pattern. Hard denies and classifier
      // failures (tier "none") never ask, and neither do headless runs.
      if (
        isDecisionBackend(cfg.classifierBackend) &&
        cfg.jevConfirmSoftDeny &&
        decision.tier === "soft_deny"
      ) {
        const signature = approvalSignature(
          serializeClassifierAction(event.toolName, input),
        );
        const approved = signature && sessionApprovals.get(signature.key);
        if (approved !== undefined) {
          state.classifierAllowed += 1;
          return allow(
            ctx,
            "classifier.confirmed",
            `Matched a session approval (${approved}): ${decision.reason}`,
            event.toolName,
            summary,
            logCtx,
          );
        }
        if (canAskUser(ctx)) return await askSoftDeny(signature);
        state.classifierDenied += 1;
        return block(ctx, {
          timestamp: Date.now(),
          toolName: event.toolName,
          reason: `${decision.reason} Not asked: no interactive terminal.${declineHint()}`,
          action: summary,
          kind: "classifier",
        }, logCtx);
      }

      state.classifierDenied += 1;
      return block(ctx, {
        timestamp: Date.now(),
        toolName: event.toolName,
        reason: decision.reason,
        action: summary,
        kind: "classifier",
      }, logCtx);
    };

    // The tool_call hook: the decision above, plus session-created paths on a
    // decision backend (Jev or Clef). Claims are computed before the decision
    // so the classifier sees them, checked again after it (a dialog can take
    // minutes), and the call joins the running set before it is allowed. See
    // created-paths.ts.
    pi.on("tool_call", async (event, ctx) => {
      const cfg = effectiveConfig();
      const id = event.toolCallId;
      if (!cfg.enabled || !isDecisionBackend(cfg.classifierBackend) || typeof id !== "string") {
        return decideToolCall(event, ctx);
      }
      const input = event.input as Record<string, unknown>;
      // The plan covers the whole action, or only its guarded prefix (`scope`
      // names the first command pi-automode did not analyse).
      const planned = event.toolName === "bash" && typeof input.command === "string"
        ? planActionOrPrefix(input.command)
        : undefined;
      const plan = planned?.plan;
      const call = {
        claims: plan && !planned.noClaims
          ? await createdPaths.claimsFor(plan, ctx.signal, planned.scope)
          : { claims: [], lines: [] },
        shownToJev: false,
      };
      callClaims.set(id, call);
      let result: Awaited<ReturnType<typeof decideToolCall>>;
      try {
        result = await decideToolCall(event, ctx);
      } finally {
        callClaims.delete(id);
      }
      if (result?.block) return result;

      const finalBlock = (reason: string) =>
        block(ctx, {
          timestamp: Date.now(),
          toolName: event.toolName,
          reason,
          action: actionSummary(event.toolName, input),
          kind: "classifier",
        }, makeLogCtx(cfg, ctx));
      // The recheck is the last await before admit, so nothing changes the
      // running set between the final check and admission.
      const planPaths = plan ? await createdPaths.runningPaths(plan) : undefined;
      // After a prefix, the unanalysed rest may change any file.
      const paths = planned?.scope === undefined ? planPaths : undefined;
      const claimsHold = await createdPaths.recheck(call.claims, ctx.signal);
      if (!claimsHold && call.shownToJev) {
        return finalBlock("A session-created path changed while this action was reviewed; run it again.");
      }
      const claims = claimsHold ? call.claims : { claims: [], lines: [] };
      const readOnly = READ_ONLY_TOOLS.has(event.toolName) ||
        (event.toolName === "bash" &&
          factsReadOnly(describeActionFacts(serializeClassifierAction(event.toolName, input), cfg.trustedHosts)));
      const waitReason = createdPaths.admit(id, {
        readOnly,
        ...(paths ? { paths } : {}),
        protects: call.shownToJev && claims.claims.length > 0
          ? planPaths ?? claims.claims.map((claim) => claim.canonical)
          : [],
      });
      if (waitReason) return finalBlock(waitReason);
      if (event.toolName === "bash" && typeof input.command === "string") {
        // A bash call that may change files also gets a before/after listing
        // of the session cwd, the one folder with a session-start baseline.
        // That records what a script the guard cannot read leaves behind. A
        // leading `cd` folder elsewhere is not listed: its earlier history is
        // unseen, so a restored user file would look new.
        const folders = readOnly || typeof ctx.cwd !== "string" ? [] : [ctx.cwd];
        if (plan || folders.length > 0) await createdPaths.prepare(id, plan, input, claims, folders);
      } else if (
        (event.toolName === "write" || event.toolName === "edit") && typeof ctx.cwd === "string"
      ) {
        // Pi's own file tools: record a created file and keep the record of a
        // recorded one valid across the agent's own writes. No claims.
        const path = resolveToolInputPath(event.toolName, ctx.cwd, input.path);
        if (path) await createdPaths.prepareFileTool(id, event.toolName, path, input);
      }
      return result;
    });

    pi.on("tool_result", async (event) => {
      await createdPaths.complete(event.toolCallId, event.input);
      return undefined;
    });

    pi.on("tool_execution_end", (event) => {
      createdPaths.release(event.toolCallId);
    });

    pi.on("agent_end", () => {
      createdPaths.endTurn();
    });

    pi.registerTool({
      name: INSPECT_TOOL,
      label: "Inspect Auto Mode",
      description:
        "Inspect the active pi-automode status, effective config, built-in defaults, or recent denial metadata. This tool is read-only and cannot enable, disable, reload, reset, or reconfigure auto mode. Its output is sent to the current model; denial reasons and action payloads are omitted.",
      promptSnippet:
        "Inspect active pi-automode state and diagnostic information without changing it",
      parameters: Type.Object({
        action: StringEnum(INSPECTION_ACTIONS, {
          description: "The read-only auto-mode view to return",
        }),
      }),
      async execute(_toolCallId, params, signal, _onUpdate, ctx) {
        if (signal?.aborted) throw new Error("Auto-mode inspection cancelled");
        const result = inspectAutomode(params.action, ctx);
        return {
          content: [{ type: "text", text: safeJson(result, 16000) }],
          details: result,
        };
      },
    });

    async function handleAutomodeCommand(
      args: string,
      ctx: ExtensionCommandContext,
    ): Promise<void> {
      const [command = "status", ...rest] = args
        .trim()
        .split(/\s+/)
        .filter(Boolean);
      const remainder = rest.join(" ").trim();

      if (command === "status") {
        ctx.ui.notify(statusText(effectiveConfig(), state), "info");
        return;
      }
      if (command === "on") {
        state.enabledOverride = true;
        persist();
        updateUi(ctx);
        ctx.ui.notify("pi-automode enabled for this session", "info");
        return;
      }
      if (command === "off") {
        state.enabledOverride = false;
        persist();
        updateUi(ctx);
        ctx.ui.notify("pi-automode disabled for this session", "warning");
        return;
      }
      if (command === "reload") {
        const { approvalsCleared } = applyLoadResult(
          loadConfigWithDiagnostics(ctx.cwd, projectIsTrusted(ctx)),
        );
        persist();
        updateUi(ctx);
        ctx.ui.notify(
          `pi-automode config reloaded${approvalsCleared ? APPROVALS_CLEARED : ""}`,
          configDiagnostics.length > 0 ? "warning" : "info",
        );
        return;
      }
      if (command === "reset") {
        state = {
          checkedActions: 0,
          blockedActions: 0,
          classifierAllowed: 0,
          classifierDenied: 0,
          recentDenials: [],
          enabledOverride: state.enabledOverride,
        };
        persist();
        updateUi(ctx);
        ctx.ui.notify("pi-automode counters reset", "info");
        return;
      }
      if (command === "defaults") {
        ctx.ui.notify(
          safeJson(
            {
              environment: DEFAULT_ENVIRONMENT,
              allow: DEFAULT_ALLOW,
              protectedPaths: DEFAULT_PROTECTED_PATHS,
              soft_deny: DEFAULT_SOFT_DENY,
              hard_deny: DEFAULT_HARD_DENY,
            },
            12000,
          ),
          "info",
        );
        return;
      }
      if (command === "config") {
        const logFile = resolveLogPath(
          ctx.sessionManager.getSessionFile?.(),
          ctx.sessionManager.getSessionDir?.() ?? "",
          ctx.sessionManager.getSessionId?.() ?? "unknown",
          ctx.cwd,
          options.logRoot,
          now(),
        );
        ctx.ui.notify(
          safeJson(
            {
              config: effectiveConfig(),
              logFile,
              diagnostics: configDiagnostics,
            },
            16000,
          ),
          configDiagnostics.length > 0 ? "warning" : "info",
        );
        return;
      }
      if (command === "approvals") {
        if (rest.join(" ").trim() === "clear") {
          const count = sessionApprovals.size + sessionEditRoots.size;
          sessionApprovals.clear();
          sessionEditRoots.clear();
          ctx.ui.notify(
            `Cleared ${count} session approval${count === 1 ? "" : "s"}.`,
            "info",
          );
          return;
        }
        const patterns = [
          ...sessionApprovals.values(),
          ...[...sessionEditRoots].map((root) => `edits under ${root}`),
        ];
        ctx.ui.notify(
          patterns.length === 0
            ? "No session approvals. Choosing \"Allow similar for this session\" on a soft-deny prompt adds one."
            : [
              `${patterns.length} session approval${patterns.length === 1 ? "" : "s"} (cleared when the session starts; /automode approvals clear removes them):`,
              ...patterns.map((pattern) => `- ${pattern}`),
            ].join("\n"),
          "info",
        );
        return;
      }
      if (command === "denials") {
        ctx.ui.notify(
          formatDenials(state),
          state.recentDenials.length > 0 ? "warning" : "info",
        );
        return;
      }
      if (command === "backend") {
        if (!isClassifierBackend(remainder)) {
          ctx.ui.notify("Usage: /automode backend <llm|jev|clef>", "error");
          return;
        }
        try {
          saveAutoModeSetting("classifierBackend", remainder);
        } catch (error) {
          ctx.ui.notify(
            `Failed to save classifier backend: ${
              error instanceof Error ? error.message : String(error)
            }`,
            "error",
          );
          return;
        }
        const { approvalsCleared } = applyLoadResult(
          loadConfigWithDiagnostics(ctx.cwd, projectIsTrusted(ctx)),
        );
        persist();
        updateUi(ctx);
        const active = effectiveConfig().classifierBackend;
        ctx.ui.notify(
          `pi-automode classifier backend saved globally: ${remainder}${
            active === remainder ? "" : `; current config uses ${active}`
          }${approvalsCleared ? APPROVALS_CLEARED : ""}`,
          "info",
        );
        return;
      }
      if (command === "jev" || command === "clef") {
        const backend: DecisionBackend = command;
        const label = decisionLabel(backend);
        const cfg = effectiveConfig();
        if (remainder === "test") {
          const probe = await probeJevClassifier(ctx, cfg, backend);
          if (!probe.ok) {
            ctx.ui.notify(`${label} probe failed: ${probe.reason}`, "error");
            return;
          }
          const lines = [`${label} probe (${probe.model}):`];
          let unexpected = false;
          for (const result of probe.probes) {
            lines.push(
              `${result.label}: ${result.decision.decision} (${result.decision.reason})`,
            );
            if (result.label === "safe" && result.decision.decision !== "allow") {
              unexpected = true;
            }
            if (
              result.label === "dangerous" &&
              result.decision.decision !== "block"
            ) {
              unexpected = true;
            }
          }
          if (unexpected) {
            lines.push(
              "Unexpected probe result. Check the thresholds and that the endpoint returns danger-side-up noul probabilities.",
            );
          }
          if (backend === "clef") {
            const profile = decisionProfile(cfg, "clef");
            let failed = false;
            let inconclusive = false;
            for (const size of CLEF_CANARY_SIZES) {
              const outcome = await runDecisionCanary(ctx, cfg, profile, size);
              if (outcome.status === "pass") {
                lines.push(
                  `canary at ${size} tokens: pass (${outcome.inputTokens ?? "unknown"} input tokens read)`,
                );
                continue;
              }
              unexpected = true;
              if (outcome.status === "fail") failed = true;
              else inconclusive = true;
              lines.push(`canary at ${size} tokens: ${outcome.status}: ${outcome.detail}`);
            }
            if (failed) {
              lines.push(
                "The canary checks that the provider reads the start and the end of a long state. A failure means Clef may be judging a cut-off state; switch backend until it passes.",
              );
            } else if (inconclusive) {
              lines.push(
                "An inconclusive canary hit a timeout or network error; run /automode clef test again.",
              );
            }
          }
          ctx.ui.notify(lines.join("\n"), unexpected ? "warning" : "info");
          return;
        }
        if (remainder !== "") {
          ctx.ui.notify(`Usage: /automode ${backend} [test]`, "error");
          return;
        }
        const { source } = await resolveJevKey(ctx, cfg);
        ctx.ui.notify(
          jevStatusText(cfg, backend, source, [
            ...new Set([...configDiagnostics, ...jevCredentialDiagnostics(cfg)]),
          ]),
          "info",
        );
        return;
      }
      if (command === "model") {
        const cfg = effectiveConfig();
        const backend = cfg.classifierBackend;
        const decision = isDecisionBackend(backend) ? backend : undefined;
        if (decision && !remainder) {
          const label = decisionLabel(decision);
          ctx.ui.notify(
            `${label} classifier model: ${decisionProfile(cfg, decision).model}. Set it with /automode model <provider/model-id>; the Pi model picker lists LLM providers and does not apply to the ${label} backend.`,
            "info",
          );
          return;
        }
        const selected = remainder || await promptForClassifierModel(
          ctx,
          cfg.classifierModel,
        );
        if (!selected) {
          ctx.ui.notify("Classifier model unchanged", "info");
          return;
        }
        if (decision) {
          const label = decisionLabel(decision);
          if (!parseModelSpec(selected)) {
            ctx.ui.notify(
              `Invalid ${label} model spec (expected provider/model): ${selected}`,
              "error",
            );
            return;
          }
          try {
            saveAutoModeSetting(
              decision === "clef" ? "clefModel" : "jevModel",
              selected,
            );
          } catch (error) {
            ctx.ui.notify(
              `Failed to save ${label} classifier model: ${
                error instanceof Error ? error.message : String(error)
              }`,
              "error",
            );
            return;
          }
          const { approvalsCleared } = applyLoadResult(
            loadConfigWithDiagnostics(ctx.cwd, projectIsTrusted(ctx)),
          );
          persist();
          updateUi(ctx);
          const active = decisionProfile(effectiveConfig(), decision).model;
          ctx.ui.notify(
            `${
              active === selected
                ? `pi-automode ${label} classifier saved globally: ${selected}`
                : `pi-automode ${label} classifier saved globally: ${selected}; current config uses ${active}`
            }${approvalsCleared ? APPROVALS_CLEARED : ""}`,
            "info",
          );
          return;
        }
        const parsed = parseModelSpec(selected);
        const model = parsed
          ? ctx.modelRegistry.find(parsed.provider, parsed.id)
          : undefined;
        if (!model) {
          ctx.ui.notify(`Model not found: ${selected}`, "error");
          return;
        }
        const auth = await ctx.modelRegistry.getApiKeyAndHeaders(model);
        if (!auth.ok) {
          ctx.ui.notify(auth.error, "error");
          return;
        }
        const modelSpec = formatModelSpec(model);
        try {
          saveClassifierModel(modelSpec);
        } catch (error) {
          ctx.ui.notify(
            `Failed to save classifier model: ${
              error instanceof Error ? error.message : String(error)
            }`,
            "error",
          );
          return;
        }
        applyLoadResult(loadConfigWithDiagnostics(ctx.cwd, projectIsTrusted(ctx)));
        persist();
        updateUi(ctx);
        const active = effectiveConfig().classifierModel ??
          "current session model";
        ctx.ui.notify(
          active === modelSpec
            ? `pi-automode classifier saved globally: ${modelSpec}`
            : `pi-automode classifier saved globally: ${modelSpec}; current config uses ${active}`,
          "info",
        );
        return;
      }

      ctx.ui.notify(
        "Usage: /automode [status|on|off|reload|reset|defaults|config|denials|approvals [clear]|backend <llm|jev|clef>|jev [test]|clef [test]|model [provider/id]]",
        "error",
      );
    }

    pi.registerCommand("automode", {
      description:
        "Control pi-automode: status, on, off, reload, reset, defaults, config, denials, approvals, backend, jev, clef, model",
      handler: handleAutomodeCommand,
    });

    pi.registerCommand("auto-mode", {
      description: "Alias for /automode",
      handler: handleAutomodeCommand,
    });
  };
}
