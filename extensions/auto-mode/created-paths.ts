/**
 * created-paths.ts — paths the agent created earlier in this session.
 *
 * Jev soft-deny rule 4 cannot tell a file that existed before the session
 * from one the agent made an hour ago. This module records paths that
 * pi-automode saw absent before one of the agent's bash actions and present
 * after it, and tells Jev when a later action overwrites or removes one of
 * them while it is provably still the same filesystem object.
 *
 * The record is evidence for Jev only. It never allows or blocks an action
 * by itself, it lives in memory only (the agent can write session entries),
 * and every failure means no claim.
 */
import { chmod, lstat, mkdtemp, readdir, realpath, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { analyzeBash, type BashCommandAnalysis } from "./bash.ts";
import { commandIsReadOnly, isWriteRedirect } from "./facts.ts";

export type CreationHow = "redirect" | "mkdir" | "git worktree add";

/** What a guarded bash action creates, removes, writes, and links. */
export type ActionPlan = {
  creations: { path: string; how: CreationHow }[];
  removals: string[];
  writes: string[];
  links: string[];
};

/**
 * True for an absolute path with no `.`, `..`, or empty segment, no control
 * character, and no glob character. `path.resolve` would collapse `..` before
 * the kernel follows symlinks, so such paths are never recorded or claimed.
 */
export function isPlainAbsolutePath(path: string): boolean {
  if (!path.startsWith("/") || path.length === 1) return false;
  if (/[\u0000-\u001f\u007f\u0085\u2028\u2029*?[]/.test(path)) return false;
  return path.slice(1).split("/").every((segment) =>
    segment !== "" && segment !== "." && segment !== ".."
  );
}

/** Non-option operands, honouring `--`. */
function operandsOf(args: string[]): string[] {
  const end = args.indexOf("--");
  return end < 0
    ? args.filter((arg) => !arg.startsWith("-"))
    : [
      ...args.slice(0, end).filter((arg) => !arg.startsWith("-")),
      ...args.slice(end + 1),
    ];
}

/** Operands when every option matches `allowed`, else undefined. */
function strictOperands(args: string[], allowed: RegExp): string[] | undefined {
  const end = args.indexOf("--");
  const options = (end < 0 ? args : args.slice(0, end)).filter((arg) => arg.startsWith("-"));
  return options.every((option) => allowed.test(option)) ? operandsOf(args) : undefined;
}

/**
 * Options each path-changing command may use. Options that take a value,
 * such as `mkdir -m MODE` or `ln -t DIR`, are left out: a value can name a
 * folder the operands do not show. `git worktree add -b/-B` is left out
 * because `-B` resets a branch the user may own. `ln -f` also needs `-n`:
 * without it, a link path that is a symlink to a folder is followed, and the
 * entry inside that folder is replaced.
 */
const OPTIONS = {
  rm: /^(-[rRfdv]+|--recursive|--force|--dir|--verbose)$/,
  mkdir: /^(-[pv]+|--parents|--verbose)$/,
  ln: /^(-[sfnv]+|--symbolic|--force|--no-dereference|--verbose)$/,
  worktreeAdd: /^(-q|--quiet|--detach|-f|--force|--lock)$/,
  worktreeRemove: /^(-f|--force)$/,
  worktreeList: /^--porcelain$/,
};

/**
 * Structure the guard refuses: functions and coprocesses hide what runs, a
 * backgrounded statement outlives the action, and a nested shell or `eval`
 * runs text the guard did not read as commands.
 */
function refusedStructure(token: string): boolean {
  return token.startsWith("node:Function") || token.startsWith("node:Coproc") ||
    token.startsWith("node:Statement:background") || token.startsWith("wrapper:");
}

type CommandEffect = Partial<ActionPlan> | undefined;

/**
 * The effect of one command, or undefined when the guard refuses it. Only
 * the table commands create or remove paths; every other command must print
 * or only read.
 */
function commandEffect(command: BashCommandAnalysis): CommandEffect {
  const name = command.name;
  if (!name || command.dynamicName) return undefined;
  // `VAR=value cmd` or a bare assignment can change PATH for later commands.
  if (command.words.length !== command.args.length + 1) return undefined;
  // `/tmp/evil/mkdir` would be read as `mkdir`.
  if (command.words[0]!.includes("/")) return undefined;
  // `env`, `command`, `exec`, and `timeout` run another program by name.
  if (command.effectiveCommand.name !== name || name === "timeout") return undefined;
  if (command.effectiveCommand.unresolvedTransparentDispatch) return undefined;
  const args = command.args;

  if (name === "echo") return {};
  if (name === "printf") {
    // `printf -v VAR` assigns a shell variable, such as PATH.
    const first = command.argTexts[0] ?? "";
    return args[0]?.startsWith("-") || /[$`]/.test(first) ? undefined : {};
  }
  if (name === "rm" || name === "mkdir" || name === "ln") {
    if (command.dynamic) return undefined;
    const operands = strictOperands(args, OPTIONS[name]);
    if (!operands || operands.length === 0) return undefined;
    if (name === "ln") {
      // Only options count: after `--`, `-n` is a file name.
      const end = args.indexOf("--");
      const options = (end < 0 ? args : args.slice(0, end)).filter((arg) => arg.startsWith("-"));
      const has = (short: string, long: string) =>
        options.some((arg) => arg === long || new RegExp(`^-[a-z]*${short}`).test(arg));
      const symbolic = has("s", "--symbolic");
      if (has("f", "--force") && !has("n", "--no-dereference")) return undefined;
      if (!symbolic || operands.length !== 2 || !isPlainAbsolutePath(operands[1]!)) {
        return undefined;
      }
      return { links: [operands[1]!] };
    }
    if (!operands.every(isPlainAbsolutePath)) return undefined;
    return name === "rm"
      ? { removals: operands }
      : { creations: operands.map((path) => ({ path, how: "mkdir" as const })) };
  }
  if (name === "git") {
    let rest = args;
    if (rest[0] === "-C") rest = rest.slice(2);
    if (rest[0] !== "worktree") return commandIsReadOnly(command, false) ? {} : undefined;
    if (command.dynamic || args.length === 0) return undefined;
    const [, subcommand, ...worktreeArgs] = rest;
    if (subcommand === "list") {
      return strictOperands(worktreeArgs, OPTIONS.worktreeList)?.length === 0 ? {} : undefined;
    }
    if (subcommand === "remove") {
      const operands = strictOperands(worktreeArgs, OPTIONS.worktreeRemove);
      return operands?.length === 1 && isPlainAbsolutePath(operands[0]!)
        ? { removals: operands }
        : undefined;
    }
    if (subcommand === "add") {
      const operands = strictOperands(worktreeArgs, OPTIONS.worktreeAdd);
      if (!operands || operands.length < 1 || operands.length > 2) return undefined;
      if (!isPlainAbsolutePath(operands[0]!)) return undefined;
      return { creations: [{ path: operands[0]!, how: "git worktree add" }] };
    }
    return undefined;
  }
  return commandIsReadOnly(command, false) ? {} : undefined;
}

/**
 * Key for comparing two paths: APFS and other case-insensitive or
 * normalization-insensitive filesystems treat these spellings as one name.
 */
export function pathKey(path: string): string {
  return path.normalize("NFC").toLowerCase();
}

/** True when `ancestor` is a folder strictly above `path`. */
function strictlyAbove(ancestor: string, path: string): boolean {
  const a = pathKey(ancestor);
  return pathKey(path).startsWith(a.endsWith("/") ? a : `${a}/`);
}

/**
 * True when no path the action changes can redirect another of its paths:
 * nothing it creates, removes, links, or writes is a folder above a path it
 * creates, removes, or writes, and no link lands on one of those paths.
 */
export function rerouteFree(plan: ActionPlan): boolean {
  const targets = [...plan.creations.map((entry) => entry.path), ...plan.removals, ...plan.writes];
  const changed = [...targets, ...plan.links];
  if (changed.some((path) => targets.some((target) => strictlyAbove(path, target)))) {
    return false;
  }
  const keys = new Set(targets.map(pathKey));
  return !plan.links.some((link) => keys.has(pathKey(link)));
}

/**
 * Parse a bash action and return what it creates, removes, writes, and
 * links, or undefined when any part of it is outside the guard. See the
 * session-created-paths spec for the rules.
 */
export function planAction(source: string): ActionPlan | undefined {
  const analysis = analyzeBash(source);
  if (analysis.errors.length > 0 || analysis.commands.length === 0) return undefined;
  if (analysis.structure.some(refusedStructure)) return undefined;

  const plan: ActionPlan = { creations: [], removals: [], writes: [], links: [] };
  for (const command of analysis.commands) {
    const effect = commandEffect(command);
    if (!effect) return undefined;
    plan.creations.push(...effect.creations ?? []);
    plan.removals.push(...effect.removals ?? []);
    plan.links.push(...effect.links ?? []);
  }
  for (const redirect of analysis.redirects) {
    if (!isWriteRedirect(redirect)) continue;
    const target = redirect.target;
    if (redirect.targetDynamic || target === undefined) return undefined;
    if (target === "/dev/null") continue;
    if (!isPlainAbsolutePath(target)) return undefined;
    if (plan.writes.includes(target)) continue;
    plan.writes.push(target);
    plan.creations.push({ path: target, how: "redirect" });
  }
  return rerouteFree(plan) ? plan : undefined;
}

/** The parts of `fs.Stats` the record uses. */
export type StatLike = {
  dev: number;
  ino: number;
  nlink: number;
  size: number;
  birthtimeMs: number;
  ctimeMs: number;
  isFile(): boolean;
  isDirectory(): boolean;
  isSymbolicLink(): boolean;
};

/** Filesystem calls, injected so tests can use an in-memory filesystem. */
export type CreatedPathsFs = {
  lstat(path: string): Promise<StatLike>;
  realpath(path: string): Promise<string>;
  readdir(path: string): Promise<string[]>;
};

/** A filesystem object as the record compares it. */
export type Identity = {
  dev: number;
  ino: number;
  kind: "file" | "folder";
  birthtimeMs: number;
  ctimeMs: number;
  size: number;
  nlink: number;
};

export type CreatedRecord = {
  /** The path as the agent wrote it. */
  path: string;
  /** The parent's real path plus the final name: the record's key. */
  canonical: string;
  identity: Identity;
  how: CreationHow;
  /** Local date and time to the minute. */
  at: string;
};

export type Claim = {
  path: string;
  canonical: string;
  record: CreatedRecord;
  /** True when the action removes this recorded folder. */
  folderRemoval: boolean;
};

/** The claims for one action, and the fact lines that describe them. */
export type ClaimSet = { claims: Claim[]; lines: string[] };

const NO_CLAIMS: ClaimSet = { claims: [], lines: [] };

type PendingCreation = {
  path: string;
  canonical: string;
  how: CreationHow;
  parent: string;
  parentIdentity: { dev: number; ino: number };
  /** `replace` holds the claim's record, which this action may recreate. */
  replace?: CreatedRecord;
};

type Pending = {
  inputJson: string;
  startMs: number;
  creations: PendingCreation[];
  /** Claims that passed the final check: refreshed or expired at `tool_result`. */
  claimed: Claim[];
};

const DEFAULT_MAX_RECORDS = 500;
const DEFAULT_MAX_PENDING = 1000;
const DEFAULT_MAX_WALK_ENTRIES = 20_000;
/** Birth-time slack for clock granularity. */
const BIRTH_SLACK_MS = 1000;

function identityOf(stat: StatLike): Identity | undefined {
  const kind = stat.isSymbolicLink()
    ? undefined
    : stat.isFile()
    ? "file"
    : stat.isDirectory()
    ? "folder"
    : undefined;
  if (kind === undefined || !(stat.birthtimeMs > 0)) return undefined;
  return {
    dev: stat.dev,
    ino: stat.ino,
    kind,
    birthtimeMs: stat.birthtimeMs,
    ctimeMs: stat.ctimeMs,
    size: stat.size,
    nlink: stat.nlink,
  };
}

/** Same object: device, inode, kind, and birth time. */
function sameObject(a: Identity, b: Identity): boolean {
  return a.dev === b.dev && a.ino === b.ino && a.kind === b.kind &&
    a.birthtimeMs === b.birthtimeMs;
}

/** Same object, and for a file, unchanged since the record was taken. */
function unchanged(record: Identity, now: Identity): boolean {
  if (!sameObject(record, now)) return false;
  if (record.kind === "folder") return true;
  return now.nlink === 1 && now.ctimeMs === record.ctimeMs && now.size === record.size;
}

function isMissing(error: unknown): boolean {
  return (error as { code?: string } | undefined)?.code === "ENOENT";
}

function localMinute(date: Date): string {
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${
    pad(date.getHours())
  }:${pad(date.getMinutes())}`;
}

/** Parent of an absolute path, as a string. */
function parentOf(path: string): string {
  const index = path.lastIndexOf("/");
  return index <= 0 ? "/" : path.slice(0, index);
}

function nameOf(path: string): string {
  return path.slice(path.lastIndexOf("/") + 1);
}

function joinPath(folder: string, name: string): string {
  return folder === "/" ? `/${name}` : `${folder}/${name}`;
}

/** The `created_this_session` fact line for one path. */
export function createdPathLine(
  path: string,
  kind: Identity["kind"],
  how: CreationHow,
  at: string,
): string {
  return kind === "file"
    ? `created_this_session: ${path} (file; absent before and present after the agent's ${how} at ${at}; size and change time match the agent's last recorded write)`
    : `created_this_session: ${path} (folder; absent before and present after the agent's ${how} at ${at}; every entry inside was created after the folder)`;
}

function claimLine(claim: Claim): string {
  const { record } = claim;
  return createdPathLine(claim.path, record.identity.kind, record.how, record.at);
}

/**
 * An allowed call that has not reached `tool_execution_end`. `paths` is set
 * only for a guarded bash action, whose effects are known; without it the
 * call may change any file.
 */
export type RunningCall = {
  readOnly: boolean;
  paths?: string[];
  /**
   * Every path of a call whose claims Jev saw. Until it ends, no other call
   * may change anything at, inside, or above them, so the claims and the
   * missing operands stay as Jev was told.
   */
  protects?: string[];
};

/** True when `paths` is unknown or has a path at, inside, or above a protected one. */
function overlaps(protectedPaths: string[], paths: string[] | undefined): boolean {
  if (paths === undefined) return true;
  return protectedPaths.some((folder) =>
    paths.some((path) =>
      pathKey(path) === pathKey(folder) || strictlyAbove(folder, path) || strictlyAbove(path, folder)
    )
  );
}

export type CreatedPathsOptions = {
  fs: CreatedPathsFs;
  now?: () => Date;
  maxRecords?: number;
  maxPending?: number;
  maxWalkEntries?: number;
};

/**
 * The session's record of paths the agent created, with the claims built
 * from it. One instance lives inside each `createPiAutomode` closure.
 */
export class CreatedPaths {
  private readonly fs: CreatedPathsFs;
  private readonly now: () => Date;
  private readonly maxRecords: number;
  private readonly maxPending: number;
  private readonly maxWalkEntries: number;
  private readonly records = new Map<string, CreatedRecord>();
  private readonly pending = new Map<string, Pending>();
  private readonly running = new Map<string, RunningCall>();
  private usable = false;

  constructor(options: CreatedPathsOptions) {
    this.fs = options.fs;
    this.now = options.now ?? (() => new Date());
    this.maxRecords = options.maxRecords ?? DEFAULT_MAX_RECORDS;
    this.maxPending = options.maxPending ?? DEFAULT_MAX_PENDING;
    this.maxWalkEntries = options.maxWalkEntries ?? DEFAULT_MAX_WALK_ENTRIES;
  }

  /** Turn recording and claims on once birth times are known to be real. */
  setUsable(usable: boolean): void {
    this.usable = usable;
  }

  /** Forget everything: records, pending entries, and running calls. */
  clear(): void {
    this.records.clear();
    this.endTurn();
  }

  /** `agent_end`: no call of this run will report a result any more. */
  endTurn(): void {
    this.pending.clear();
    this.running.clear();
  }

  /**
   * Admit an allowed call into the running set, or say why it must wait.
   * Call this synchronously right before allowing, with no `await` between
   * the final checks and this call, so two calls cannot both pass.
   *
   * - A call whose claims Jev saw waits for every running call that could
   *   change files, unless that call is guarded and touches nothing at,
   *   inside, or above the call's paths.
   * - While such a call runs, a call that may change files waits the same
   *   way.
   *
   * Calls whose id is a prefix of this one, such as the codemode call that
   * issued a nested call, are not counted.
   */
  admit(toolCallId: string, call: RunningCall): string | undefined {
    for (const [id, other] of this.running) {
      if (id === toolCallId || toolCallId.startsWith(`${id}/`)) continue;
      if (call.protects?.length && !other.readOnly && overlaps(call.protects, other.paths)) {
        return "Another action is still running; run this again after it finishes.";
      }
      if (other.protects?.length && !call.readOnly && overlaps(other.protects, call.paths)) {
        return "Another action is changing a session-created path; run this after it finishes.";
      }
    }
    if (!call.readOnly) this.running.set(toolCallId, call);
    return undefined;
  }

  /** Recorded canonical paths, oldest first. For tests and diagnostics. */
  recordedPaths(): string[] {
    return [...this.records.keys()];
  }

  /**
   * The parent's real path plus the final name. A missing parent is resolved
   * through its nearest existing folder, so every spelling of a path that
   * runs through a symlink, such as `/tmp` on macOS, gives one key.
   */
  private async canonical(path: string): Promise<string> {
    const parent = parentOf(path);
    let real: string;
    try {
      real = await this.fs.realpath(parent);
    } catch (error) {
      if (!isMissing(error) || parent === "/") throw error;
      real = await this.canonical(parent);
    }
    return joinPath(real, nameOf(path));
  }

  private async identity(canonical: string): Promise<Identity | undefined> {
    return identityOf(await this.fs.lstat(canonical));
  }

  /** The plan with every path replaced by its canonical form. */
  private async canonicalPlan(plan: ActionPlan): Promise<ActionPlan> {
    const map = (paths: string[]) => Promise.all(paths.map((path) => this.canonical(path)));
    return {
      creations: await Promise.all(
        plan.creations.map(async (entry) => ({ ...entry, path: await this.canonical(entry.path) })),
      ),
      removals: await map(plan.removals),
      writes: await map(plan.writes),
      links: await map(plan.links),
    };
  }

  /**
   * True when every entry below the folder was created after it, on the same
   * device, and is a single-link file, a folder, or a symlink. Symlinks are
   * not followed: `rm -rf` and `git worktree remove` do not follow them.
   */
  private async walkPasses(folder: string, identity: Identity, signal?: AbortSignal): Promise<boolean> {
    const stack = [folder];
    let entries = 0;
    while (stack.length > 0) {
      if (signal?.aborted) return false;
      const current = stack.pop()!;
      for (const name of await this.fs.readdir(current)) {
        if (++entries > this.maxWalkEntries) return false;
        const path = joinPath(current, name);
        const stat = await this.fs.lstat(path);
        if (stat.dev !== identity.dev || !(stat.birthtimeMs >= identity.birthtimeMs)) return false;
        if (stat.isDirectory()) stack.push(path);
        else if (stat.isFile()) {
          if (stat.nlink !== 1) return false;
        } else if (!stat.isSymbolicLink()) return false;
      }
    }
    return !signal?.aborted;
  }

  /**
   * Claims for an action's removals and existing write targets. Every one of
   * them must hold a valid claim, or the action gets none: a claim line next
   * to an unclaimed deletion would read as cover for it. `ln -fn` replaces
   * an existing link path, so one may exist only inside a folder the action
   * removes under a claim, and must not be a folder (the link would go
   * inside it).
   */
  async claimsFor(plan: ActionPlan, signal?: AbortSignal): Promise<ClaimSet> {
    if (!this.usable || this.records.size === 0) return NO_CLAIMS;
    try {
      const canonical = await this.canonicalPlan(plan);
      if (!rerouteFree(canonical)) return NO_CLAIMS;
      const claims: Claim[] = [];
      const seen = new Set<string>();
      const targets = [
        ...plan.removals.map((path, index) => ({ path, canonical: canonical.removals[index]!, removal: true })),
        ...plan.writes.map((path, index) => ({ path, canonical: canonical.writes[index]!, removal: false })),
      ];
      for (const target of targets) {
        if (seen.has(target.canonical)) continue;
        seen.add(target.canonical);
        let stat: StatLike;
        try {
          stat = await this.fs.lstat(target.canonical);
        } catch (error) {
          if (isMissing(error)) continue;
          throw error;
        }
        const record = this.records.get(target.canonical);
        const now = identityOf(stat);
        if (!record || !now || !unchanged(record.identity, now)) {
          if (record) this.records.delete(target.canonical);
          return NO_CLAIMS;
        }
        const folderRemoval = record.identity.kind === "folder";
        if (folderRemoval && !target.removal) return NO_CLAIMS;
        if (folderRemoval && !await this.walkPasses(target.canonical, record.identity, signal)) {
          return NO_CLAIMS;
        }
        claims.push({ path: target.path, canonical: target.canonical, record, folderRemoval });
      }
      for (const link of canonical.links) {
        let stat: StatLike;
        try {
          stat = await this.fs.lstat(link);
        } catch (error) {
          if (isMissing(error)) continue;
          throw error;
        }
        if (stat.isDirectory()) return NO_CLAIMS;
        if (!claims.some((claim) => claim.folderRemoval && strictlyAbove(claim.canonical, link))) {
          return NO_CLAIMS;
        }
      }
      return { claims, lines: claims.map(claimLine) };
    } catch {
      return NO_CLAIMS;
    }
  }

  /** The second check: true when every claim still holds, walk included. */
  async recheck(set: ClaimSet, signal?: AbortSignal): Promise<boolean> {
    try {
      for (const claim of set.claims) {
        if (this.records.get(claim.canonical) !== claim.record) return false;
        if (await this.canonical(claim.path) !== claim.canonical) return false;
        const now = await this.identity(claim.canonical);
        if (!now || !unchanged(claim.record.identity, now)) return false;
        if (claim.folderRemoval && !await this.walkPasses(claim.canonical, now, signal)) return false;
      }
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Store what to check at `tool_result`: each creation candidate whose
   * parent exists, and which is either absent or held a claim that passed the
   * final check. `claims` must be the set that passed it.
   */
  async prepare(
    toolCallId: string,
    plan: ActionPlan,
    input: Record<string, unknown>,
    claims: ClaimSet,
  ): Promise<void> {
    this.pending.delete(toolCallId);
    if (!this.usable) return;
    const startMs = this.now().getTime();
    const creations: PendingCreation[] = [];
    try {
      const canonical = await this.canonicalPlan(plan);
      if (!rerouteFree(canonical)) return;
      const seen = new Set<string>();
      for (const [index, entry] of plan.creations.entries()) {
        const path = canonical.creations[index]!.path;
        if (seen.has(path)) continue;
        seen.add(path);
        const parent = parentOf(path);
        let parentStat: StatLike;
        try {
          parentStat = await this.fs.lstat(parent);
        } catch {
          continue;
        }
        if (!parentStat.isDirectory()) continue;
        const claim = claims.claims.find((candidate) => candidate.canonical === path);
        let exists = true;
        try {
          await this.fs.lstat(path);
        } catch (error) {
          if (!isMissing(error)) continue;
          exists = false;
        }
        if (exists && !claim) continue;
        creations.push({
          path: entry.path,
          canonical: path,
          how: entry.how,
          parent,
          parentIdentity: { dev: parentStat.dev, ino: parentStat.ino },
          ...(claim ? { replace: claim.record } : {}),
        });
      }
    } catch {
      return;
    }
    this.pending.set(toolCallId, {
      inputJson: JSON.stringify(input),
      startMs,
      creations,
      claimed: claims.claims,
    });
    while (this.pending.size > this.maxPending) {
      this.pending.delete(this.pending.keys().next().value!);
    }
  }

  private remember(record: CreatedRecord): void {
    this.records.delete(record.canonical);
    this.records.set(record.canonical, record);
    while (this.records.size > this.maxRecords) {
      this.records.delete(this.records.keys().next().value!);
    }
  }

  /** `tool_result`: record new paths, refresh claimed files, expire the rest. */
  async complete(toolCallId: string, input: Record<string, unknown>): Promise<void> {
    const pending = this.pending.get(toolCallId);
    this.pending.delete(toolCallId);
    if (!pending || !this.usable) return;
    // Another extension may have changed the input after pi-automode saw it.
    if (JSON.stringify(input) !== pending.inputJson) {
      for (const claim of pending.claimed) this.records.delete(claim.canonical);
      return;
    }
    const at = localMinute(this.now());
    const settled = new Set<string>();
    for (const creation of pending.creations) {
      try {
        if (await this.fs.realpath(creation.parent) !== creation.parent) continue;
        const parent = await this.fs.lstat(creation.parent);
        if (parent.dev !== creation.parentIdentity.dev || parent.ino !== creation.parentIdentity.ino) {
          continue;
        }
        const now = await this.identity(creation.canonical);
        if (!now) continue;
        const old = creation.replace;
        if (old && sameObject(old.identity, now)) {
          // Written in place: refresh a file the claim covered.
          if (now.kind === "file" && now.nlink === 1 && this.records.get(old.canonical) === old) {
            this.remember({ ...old, identity: now });
            settled.add(creation.canonical);
          }
          continue;
        }
        if (now.kind === "file" && now.nlink !== 1) continue;
        if (now.birthtimeMs < pending.startMs - BIRTH_SLACK_MS) continue;
        this.remember({
          path: creation.path,
          canonical: creation.canonical,
          identity: now,
          how: creation.how,
          at,
        });
        settled.add(creation.canonical);
      } catch {
        // No record.
      }
    }
    for (const claim of pending.claimed) {
      if (settled.has(claim.canonical)) continue;
      try {
        const now = await this.identity(claim.canonical);
        if (now && unchanged(claim.record.identity, now)) continue;
      } catch {
        // Missing or unreadable: expire.
      }
      if (this.records.get(claim.canonical) === claim.record) this.records.delete(claim.canonical);
    }
  }

  /** `tool_execution_end`: the call is over. */
  release(toolCallId: string): void {
    this.pending.delete(toolCallId);
    this.running.delete(toolCallId);
  }

  /** Canonical forms of every path a plan touches, for `admit`. */
  async runningPaths(plan: ActionPlan): Promise<string[] | undefined> {
    try {
      const canonical = await this.canonicalPlan(plan);
      return [
        ...canonical.creations.map((entry) => entry.path),
        ...canonical.removals,
        ...canonical.writes,
        ...canonical.links,
      ];
    } catch {
      return undefined;
    }
  }
}

/** The filesystem calls of `birthTimesUsable`, injected in tests. */
export type BirthTimeProbeDeps = {
  mkdtemp(prefix: string): Promise<string>;
  writeFile(path: string, data: string): Promise<void>;
  chmod(path: string, mode: number): Promise<void>;
  stat(path: string): Promise<{ birthtimeMs: number }>;
  rm(path: string, options: { recursive: boolean; force: boolean }): Promise<void>;
  wait(ms: number): Promise<void>;
};

const PROBE_DEPS: BirthTimeProbeDeps = {
  mkdtemp,
  writeFile,
  chmod,
  stat,
  rm,
  wait: (ms) => new Promise((resolve) => setTimeout(resolve, ms).unref()),
};

/**
 * True when this process sees real birth times. macOS reports them. On
 * Linux, Node reports them only with `statx`; without it, libuv reports the
 * change time instead, which a rename or `chmod` moves. So on Linux a file
 * is created, changed after a wait, and its birth time must not have moved.
 * Other platforms are not supported.
 */
export async function birthTimesUsable(
  platform: NodeJS.Platform = process.platform,
  deps: BirthTimeProbeDeps = PROBE_DEPS,
): Promise<boolean> {
  if (platform === "darwin") return true;
  if (platform !== "linux") return false;
  let folder: string | undefined;
  try {
    folder = await deps.mkdtemp(join(tmpdir(), "pi-automode-birth-"));
    const file = join(folder, "probe");
    await deps.writeFile(file, "");
    const before = (await deps.stat(file)).birthtimeMs;
    await deps.wait(1100);
    await deps.chmod(file, 0o600);
    const after = (await deps.stat(file)).birthtimeMs;
    return before > 0 && after === before;
  } catch {
    return false;
  } finally {
    if (folder !== undefined) await deps.rm(folder, { recursive: true, force: true }).catch(() => {});
  }
}

/** The real filesystem. */
export const NODE_CREATED_PATHS_FS: CreatedPathsFs = { lstat, realpath, readdir };
