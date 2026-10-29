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
import { parse } from "unbash";
import { analyzeBash, type BashAnalysis, type BashCommandAnalysis } from "./bash.ts";
import { commandIsReadOnly, isWriteRedirect } from "./facts.ts";

/**
 * How a path came to exist, worded for the fact line: "the agent's <how> at
 * <time>". `write tool call` is Pi's `write` tool; `bash command` is a
 * directory snapshot around a bash call, for outputs the guard cannot read
 * (a script the command ran).
 */
export const CREATION_HOWS = [
  "redirect",
  "mkdir",
  "git worktree add",
  "write tool call",
  "bash command",
] as const;
export type CreationHow = typeof CREATION_HOWS[number];

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
 * An operand as an absolute path. With a verified leading `cd`, a relative
 * operand is joined to its folder. Without one the operand is returned as it
 * is, and the path rules refuse it. `~` is never joined: the shell would
 * expand it to the home folder.
 */
function resolveOperand(base: string | undefined, operand: string): string {
  if (base === undefined || operand.startsWith("/") || operand.startsWith("~")) return operand;
  return `${base}/${operand}`;
}

/**
 * The effect of one command, or undefined when the guard refuses it. Only
 * the table commands create or remove paths; every other command must print
 * or only read.
 */
function commandEffect(command: BashCommandAnalysis, base: string | undefined): CommandEffect {
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
    const found = strictOperands(args, OPTIONS[name]);
    if (!found || found.length === 0) return undefined;
    // `ln -s TARGET LINK`: TARGET is stored as written, only LINK is a path.
    const operands = name === "ln"
      ? [found[0]!, ...found.slice(1).map((operand) => resolveOperand(base, operand))]
      : found.map((operand) => resolveOperand(base, operand));
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
    // `git -C DIR` moves the base of its own relative paths.
    const gitBase = rest[0] === "-C" ? undefined : base;
    if (rest[0] === "-C") rest = rest.slice(2);
    if (rest[0] !== "worktree") return commandIsReadOnly(command, false) ? {} : undefined;
    if (command.dynamic || args.length === 0) return undefined;
    const [, subcommand, ...worktreeArgs] = rest;
    if (subcommand === "list") {
      return strictOperands(worktreeArgs, OPTIONS.worktreeList)?.length === 0 ? {} : undefined;
    }
    if (subcommand === "remove") {
      const operands = strictOperands(worktreeArgs, OPTIONS.worktreeRemove)
        ?.map((operand) => resolveOperand(gitBase, operand));
      return operands?.length === 1 && isPlainAbsolutePath(operands[0]!)
        ? { removals: operands }
        : undefined;
    }
    if (subcommand === "add") {
      const operands = strictOperands(worktreeArgs, OPTIONS.worktreeAdd);
      if (!operands || operands.length < 1 || operands.length > 2) return undefined;
      const path = resolveOperand(gitBase, operands[0]!);
      if (!isPlainAbsolutePath(path)) return undefined;
      return { creations: [{ path, how: "git worktree add" }] };
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

const DIRECTORY_CHANGERS = new Set(["cd", "pushd", "popd"]);

/** The folder of a plain `cd` command (see `leadingCdDirectory`), or undefined. */
function plainCdFolder(cd: BashCommandAnalysis | undefined): string | undefined {
  if (!cd || cd.name !== "cd" || cd.words[0] !== "cd" || cd.dynamic || cd.dynamicName) return undefined;
  if (cd.words.length !== cd.args.length + 1 || cd.args.length !== 1) return undefined;
  const folder = cd.args[0]!;
  if (folder.startsWith("-") || !isPlainAbsolutePath(folder)) return undefined;
  if (cd.redirects.length > 0 || cd.effectiveCommand.name !== "cd") return undefined;
  return folder;
}

/** True for `cd`, `pushd`, `popd`, also through `command`, `env`, or a path. */
function changesDirectory(command: BashCommandAnalysis): boolean {
  return DIRECTORY_CHANGERS.has(command.name ?? "") ||
    DIRECTORY_CHANGERS.has(command.effectiveCommand.name ?? "") ||
    command.effectiveCommand.unresolvedTransparentDispatch;
}

/**
 * The folder of a leading `cd`, when it can be trusted as the folder every
 * later command runs in. All of these must hold:
 *
 * - the action is one statement, a chain of commands joined only by `&&`, and
 *   the first is a plain `cd` with no redirect, so a failed `cd` stops
 *   everything after it;
 * - the `cd` has exactly one literal operand, no option, and that operand is
 *   a plain absolute path (so not `-`, `..`, `~`, or a glob);
 * - no other command in the action is `cd`, `pushd`, or `popd`, even through
 *   `command`, `env`, a pipe, or a substitution.
 *
 * A relative path does not pass: the folder Pi's bash tool starts in is not
 * something this module has verified.
 */
export function leadingCdDirectory(
  source: string,
  analysis: BashAnalysis = analyzeBash(source),
): string | undefined {
  if (analysis.errors.length > 0) return undefined;
  const [cd, ...rest] = analysis.commands;
  const folder = plainCdFolder(cd);
  if (folder === undefined || rest.some(changesDirectory)) return undefined;
  // The structure: one statement, `&&` all the way, and the `cd` first.
  try {
    const script = parse(source);
    if (script.commands.length !== 1) return undefined;
    const statement = script.commands[0]!;
    if (statement.type !== "Statement" || statement.background || statement.redirects.length > 0) {
      return undefined;
    }
    const chain = statement.command;
    if (chain.type !== "AndOr" || !chain.operators.every((operator) => operator === "&&")) {
      return undefined;
    }
    const first = chain.commands[0];
    if (first?.type !== "Command" || first.prefix.length > 0 || first.pos !== cd!.pos) return undefined;
  } catch {
    return undefined;
  }
  return folder;
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
  const base = leadingCdDirectory(source, analysis);

  const plan: ActionPlan = { creations: [], removals: [], writes: [], links: [] };
  for (const command of analysis.commands) {
    const effect = commandEffect(command, base);
    if (!effect) return undefined;
    plan.creations.push(...effect.creations ?? []);
    plan.removals.push(...effect.removals ?? []);
    plan.links.push(...effect.links ?? []);
  }
  for (const redirect of analysis.redirects) {
    if (!isWriteRedirect(redirect)) continue;
    if (redirect.targetDynamic || redirect.target === undefined) return undefined;
    if (redirect.target === "/dev/null") continue;
    const target = resolveOperand(base, redirect.target);
    if (!isPlainAbsolutePath(target)) return undefined;
    if (plan.writes.includes(target)) continue;
    plan.writes.push(target);
    plan.creations.push({ path: target, how: "redirect" });
  }
  return rerouteFree(plan) ? plan : undefined;
}

/**
 * What a guarded action's leading commands do, plus what could not be read.
 * `scope` is set when the plan covers only a prefix: it names the first
 * command pi-automode did not analyse. `noClaims` is set when something in
 * the unanalysed rest could delete, move, or overwrite files in a way a claim
 * would read as cover for; the plan is still used for recording.
 */
export type PlannedAction = { plan: ActionPlan; scope?: string; noClaims?: true };

/** Commands the whole action may not contain: they run text or run later. */
function refusedAnywhere(command: BashCommandAnalysis): boolean {
  const names = [command.name, command.effectiveCommand.name, ...command.words];
  return command.dynamicShellScript || names.some((name) => name === "eval" || name === "trap" || name === "exec");
}

/**
 * Commands that delete, move, overwrite, truncate, copy over, or link files.
 * A deny-list: it leaks by construction (interpreters, scripts, unlisted
 * tools), so it only keeps a claim line off the visible cases.
 */
const DELETING_COMMANDS = new Set([
  "rm", "rmdir", "unlink", "shred", "mv",
  "grm", "grmdir", "gunlink", "gshred", "gmv",
  "srm", "trash",
  "tee", "truncate", "dd", "cp", "install", "rsync", "ln",
]);
const FIND_ACTIONS = new Set(["-delete", "-exec", "-execdir", "-ok", "-okdir"]);
/** `git` subcommands that discard or replace working-tree files or stash them away. */
const GIT_DESTRUCTIVE = new Set(["clean", "rm", "checkout", "restore", "stash"]);
/** `sed -i`, `sed -i.bak`, `sed -ni`, `perl -pi`, `--in-place`. */
const IN_PLACE_FLAG = /^(-[a-zA-Z]*i|--in-place)/;

/**
 * True when an unanalysed command visibly deletes, moves, or overwrites
 * files, or its name is not known: a claim line next to it would read as
 * cover for it. Every word counts, so `xargs rm`, `sudo rm`, and
 * `timeout 5 rm` are caught.
 */
function visiblyDeletes(command: BashCommandAnalysis): boolean {
  if (command.dynamicName) return true;
  const words = [command.name ?? "", command.effectiveCommand.name ?? "", ...command.words].map((word) =>
    word.slice(word.lastIndexOf("/") + 1)
  );
  if (words.some((word) => DELETING_COMMANDS.has(word))) return true;
  if (words.includes("find") && command.words.some((word) => FIND_ACTIONS.has(word))) return true;
  if ((words.includes("sed") || words.includes("perl")) && command.words.some((word) => IN_PLACE_FLAG.test(word))) {
    return true;
  }
  if (words.includes("git")) {
    if (command.words.some((word) => GIT_DESTRUCTIVE.has(word))) return true;
    if (command.words.includes("worktree") && command.words.includes("remove")) return true;
    if (command.words.includes("reset") && command.words.includes("--hard")) return true;
  }
  return false;
}

/** The effects of one top-level simple command, with its write redirects. */
function itemEffect(
  analysis: BashAnalysis,
  node: { pos: number; end: number },
  base: string | undefined,
): { plan: ActionPlan; redirects: BashCommandAnalysis["redirects"] } | undefined {
  const commands = analysis.commands.filter((command) => command.pos >= node.pos && command.end <= node.end);
  if (commands.length === 0) return undefined;
  const plan: ActionPlan = { creations: [], removals: [], writes: [], links: [] };
  for (const command of commands) {
    const effect = commandEffect(command, base);
    if (!effect) return undefined;
    plan.creations.push(...effect.creations ?? []);
    plan.removals.push(...effect.removals ?? []);
    plan.links.push(...effect.links ?? []);
    for (const redirect of command.redirects) {
      if (!isWriteRedirect(redirect)) continue;
      if (redirect.targetDynamic || redirect.target === undefined) return undefined;
      const target = resolveOperand(base, redirect.target);
      if (!isPlainAbsolutePath(target)) return undefined;
      if (plan.writes.includes(target)) continue;
      plan.writes.push(target);
      plan.creations.push({ path: target, how: "redirect" });
    }
  }
  return { plan, redirects: commands.flatMap((command) => command.redirects) };
}

const SCOPE_NAME = /^[A-Za-z0-9._+-]{1,40}$/;

/**
 * Plan the leading part of an action whose later part the guard cannot read,
 * such as `cd D && rm -rf out && timeout 400 pwsh -File run.ps1 | tail`.
 *
 * The prefix is the leading run of top-level items that each pass the guard.
 * Items are joined by `&&`, `||`, or `;`, and each is a simple command: a
 * loop, `if`, `case`, group, subshell, function, or pipeline is never part of
 * the prefix, because it can run again later or beside unanalysed code. The
 * prefix runs before any unanalysed command, so removals in it act on what
 * the claims describe. The whole action must still pass the structural
 * refusals: no background, coprocess, function, nested shell, `eval`, `trap`,
 * or `exec` anywhere, and no redirect on a compound statement.
 *
 * A relative operand resolves only against a leading `cd` that every item up
 * to it follows through `&&` alone, when nothing later changes directory.
 *
 * With claims from a prefix, `scope` names the first unanalysed command.
 * `noClaims` is set when the rest could delete, move, or overwrite files, or
 * has a command of unknown name.
 */
export function planActionPrefix(source: string): PlannedAction | undefined {
  const analysis = analyzeBash(source);
  if (analysis.errors.length > 0 || analysis.commands.length === 0) return undefined;
  if (analysis.structure.some(refusedStructure)) return undefined;
  if (analysis.commands.some(refusedAnywhere)) return undefined;

  let items: Array<{ node: { type: string; pos: number; end: number; commands?: unknown[] }; inCdRun: boolean }>;
  try {
    const script = parse(source);
    items = [];
    for (const [index, statement] of script.commands.entries()) {
      if (statement.type !== "Statement" || statement.background || statement.redirects.length > 0) {
        return undefined;
      }
      const chain = statement.command;
      if (chain.type !== "AndOr") {
        items.push({ node: chain, inCdRun: false });
        continue;
      }
      // Items reached from the first one through `&&` alone run only if it succeeded.
      let run = index === 0;
      for (const [position, node] of chain.commands.entries()) {
        if (position > 0 && chain.operators[position - 1] !== "&&") run = false;
        items.push({ node, inCdRun: run });
      }
    }
  } catch {
    return undefined;
  }

  const [first, ...laterCommands] = analysis.commands;
  const folder = items[0]?.node.type === "Command" && first?.pos === items[0].node.pos
    ? plainCdFolder(first)
    : undefined;
  const base = folder !== undefined && !laterCommands.some(changesDirectory) ? folder : undefined;

  const plan: ActionPlan = { creations: [], removals: [], writes: [], links: [] };
  const prefixRedirects: BashCommandAnalysis["redirects"] = [];
  let suffixAt = -1;
  for (const [index, item] of items.entries()) {
    const effect = item.node.type === "Command"
      ? itemEffect(analysis, item.node, item.inCdRun && index > 0 ? base : undefined)
      : undefined;
    if (!effect) {
      suffixAt = index;
      break;
    }
    plan.creations.push(...effect.plan.creations);
    plan.removals.push(...effect.plan.removals);
    plan.writes.push(...effect.plan.writes);
    plan.links.push(...effect.plan.links);
    prefixRedirects.push(...effect.redirects);
  }
  // Everything passed (the whole-action plan refused it) or nothing did.
  if (suffixAt <= 0) return undefined;
  if (
    plan.creations.length + plan.removals.length + plan.writes.length + plan.links.length === 0 ||
    !rerouteFree(plan)
  ) return undefined;

  const suffixNode = items[suffixAt]!.node as { type: string; pos: number; commands?: unknown[] };
  const head = suffixNode.type === "Pipeline"
    ? analysis.commands.find((command) => command.pos >= suffixNode.pos)
    : suffixNode.type === "Command"
    ? analysis.commands.find((command) => command.pos === suffixNode.pos)
    : undefined;
  const scope = head?.name !== undefined && SCOPE_NAME.test(head.name) ? head.name : "a command";

  const suffix = analysis.commands.filter((command) => command.pos >= suffixNode.pos);
  // Fail closed: every command must sit inside a prefix item or at or after
  // the start of the rest. The parser positions here-doc bodies after their
  // owner's range, so their commands fall in neither and would escape both the
  // prefix check and the scan of the rest. (A quoted here-doc body is literal
  // text and yields no commands.)
  const prefixNodes = items.slice(0, suffixAt).map((item) => item.node);
  if (!analysis.commands.every((command) =>
    command.pos >= suffixNode.pos ||
    prefixNodes.some((node) => command.pos >= node.pos && command.end <= node.end)
  )) return undefined;
  // A write redirect outside the prefix, such as `pwsh > ~/notes.md` or one
  // on a compound command, may overwrite a file.
  const unaccounted = new Map<string, number>();
  const key = (redirect: BashCommandAnalysis["redirects"][number]) =>
    `${redirect.operator}|${redirect.fileDescriptor ?? ""}|${redirect.target ?? ""}|${redirect.targetDynamic}`;
  for (const redirect of analysis.redirects.filter(isWriteRedirect)) {
    unaccounted.set(key(redirect), (unaccounted.get(key(redirect)) ?? 0) + 1);
  }
  for (const redirect of prefixRedirects.filter(isWriteRedirect)) {
    unaccounted.set(key(redirect), (unaccounted.get(key(redirect)) ?? 0) - 1);
  }
  const outsideRedirect = [...unaccounted.values()].some((count) => count > 0);
  return {
    plan,
    scope,
    ...(suffix.some(visiblyDeletes) || outsideRedirect ? { noClaims: true as const } : {}),
  };
}

/** The plan of a whole guarded action, or of its guarded prefix. */
export function planActionOrPrefix(source: string): PlannedAction | undefined {
  const whole = planAction(source);
  return whole ? { plan: whole } : planActionPrefix(source);
}

/**
 * `git` subcommands that only read. Any other `git` invocation counts as
 * restoring (`stash pop`, `checkout`, `restore`, `reset`, `pull`, `merge`,
 * `clone`, `add`, `commit`, an alias, an unknown form): a deny-list of git
 * would miss aliases and new subcommands.
 */
const GIT_READ_ONLY = new Set([
  "status", "diff", "log", "show", "rev-parse", "ls-files", "ls-tree", "blame", "grep", "describe",
  "shortlog", "cat-file", "rev-list", "merge-base", "for-each-ref", "name-rev",
]);
/**
 * Global options that take no value and cannot run a program. `-p` and
 * `--paginate` are left out: they start a pager.
 */
const GIT_PLAIN_GLOBALS = new Set([
  "--no-pager", "-P", "--no-optional-locks", "--no-replace-objects", "--literal-pathspecs",
]);
/** `diff`, `log`, `show` options that write a file or run a program. */
const GIT_DIFF_RUNNERS = /^(--output(=.*)?|--ext-diff|--textconv)$/;
/** `git grep -O[CMD]` and `--open-files-in-pager[=CMD]` run a program. */
const GIT_GREP_RUNNERS = /^(-[a-zA-Z]*O|--open-files-in-pager)/;
const GIT_BRANCH_LISTING = new Set([
  "-a", "-r", "-v", "-vv", "--all", "--remotes", "--verbose", "--list", "-l", "--show-current", "--no-color",
  "--color", "--merged", "--no-merged", "--contains", "--no-contains",
]);
const GIT_CONFIG_READING = new Set(["--get", "--get-all", "--get-regexp", "--list", "-l", "--get-urlmatch"]);

/** True when a `git` subcommand and its arguments only list or read. */
function gitReadsOnly(subcommand: string, rest: string[]): boolean {
  if (subcommand === "diff" || subcommand === "log" || subcommand === "show") {
    return !rest.some((word) => GIT_DIFF_RUNNERS.test(word));
  }
  if (subcommand === "grep") return !rest.some((word) => GIT_GREP_RUNNERS.test(word));
  if (GIT_READ_ONLY.has(subcommand)) return true;
  const options = rest.every((word) => word.startsWith("-"));
  switch (subcommand) {
    case "branch":
      // `git branch NAME` creates one; `--list PATTERN` lists.
      return rest.every((word) => GIT_BRANCH_LISTING.has(word)) ||
        (rest.some((word) => word === "--list" || word === "-l") &&
          rest.every((word) => GIT_BRANCH_LISTING.has(word) || !word.startsWith("-")));
    case "tag":
      return rest.length === 0 || (rest.some((word) => word === "-l" || word === "--list") &&
        rest.every((word) => ["-l", "--list", "-n", "--contains", "--merged"].includes(word) || !word.startsWith("-")));
    case "remote":
      return rest.length === 0 || (options && rest.every((word) => word === "-v" || word === "--verbose")) ||
        rest[0] === "show" || rest[0] === "get-url";
    case "config":
      return rest.length > 0 && GIT_CONFIG_READING.has(rest[0]!);
    case "stash":
      return rest[0] === "list";
    default:
      return false;
  }
}

/**
 * True when a `git` invocation (the words from `git` on) is not a plain read.
 * `-c` and `--config-env` count (an alias can rename a subcommand), and so
 * does any global option or subcommand this cannot place.
 */
function gitMayRestore(words: string[]): boolean {
  let index = 0;
  while (index < words.length) {
    const word = words[index]!;
    if (word === "-C") {
      index += 2;
      continue;
    }
    if (/^-c/.test(word) || word.startsWith("--config-env")) return true;
    if (GIT_PLAIN_GLOBALS.has(word)) {
      index += 1;
      continue;
    }
    if (word.startsWith("-")) return true;
    return !gitReadsOnly(word, words.slice(index + 1));
  }
  return true; // `git` with no subcommand: cannot tell
}

/** Archive, sync, and download tools that write files with content from elsewhere. */
const RESTORING_COMMANDS = new Set([
  "tar", "unzip", "bsdtar", "ditto", "rsync", "7z", "7za", "gunzip", "unxz", "unzstd", "bunzip2",
  "cpio", "pax", "jar", "unrar", "zcat", "gzcat", "xzcat", "zstdcat", "bzcat", "scp", "sftp", "curl", "wget",
]);
/** `-d`, `-dk`, `--decompress`, `--uncompress` for `gzip`, `xz`, `zstd`, and `bzip2`. */
const DECOMPRESS_FLAG = /^(-[a-zA-Z]*d|--decompress|--uncompress)/;

/**
 * True when a bash action may bring file content back from outside the
 * session: any `git` that is not a plain read (`stash pop`, `checkout`,
 * `restore`, `reset`, `pull`, a clone, `-c` with an alias), an archive
 * extract, an `rsync`, a download. The restored files are new objects with
 * fresh birth and modification times, and nothing in this session's listings
 * names them, so a directory snapshot would record the user's data as created
 * by the agent. Such an action gets no snapshot, and a snapshot that overlaps
 * a running one records nothing either. Plan-recorded creations are
 * unaffected.
 *
 * Words are matched by basename, nested commands included, so `sudo git stash
 * pop` and `timeout 5 tar x` count. An action that cannot be parsed, or that
 * runs a script the parser cannot read (`bash -c "$X"`), counts too: fail
 * closed. This is a deny-list: a script the guard cannot read (`pwsh -File
 * restore.ps1`) can still restore data, the same class as the unanalysed rest
 * of an action. A full allow-list was rejected: it would disable C for
 * `pwsh -File` and similar runners, the case C exists for.
 */
export function restoresData(source: string): boolean {
  const analysis = analyzeBash(source);
  if (analysis.errors.length > 0) return true;
  return analysis.commands.some((command) => {
    if (command.dynamicShellScript) return true;
    const words = [command.name ?? "", command.effectiveCommand.name ?? "", ...command.words].map((word) =>
      word.slice(word.lastIndexOf("/") + 1)
    );
    if (words.some((word) => RESTORING_COMMANDS.has(word))) return true;
    // Every `git` word starts an invocation, wrappers included (`sudo git ...`).
    for (const [index, word] of command.words.entries()) {
      if (word.slice(word.lastIndexOf("/") + 1) !== "git") continue;
      // `GIT_PAGER=…`, `PAGER=…`, `GIT_EXTERNAL_DIFF=…`, `GIT_CONFIG_*=…`, any `VAR=…`
      // before `git` (a prefix assignment, or after `env`) can make a read run a program.
      if (command.words.slice(0, index).some((before) => /^[A-Za-z_][A-Za-z0-9_]*=/.test(before))) return true;
      if (gitMayRestore(command.words.slice(index + 1))) return true;
    }
    return words.some((word) => word === "gzip" || word === "xz" || word === "zstd" || word === "bzip2") &&
      command.words.some((word) => DECOMPRESS_FLAG.test(word));
  });
}

/** The parts of `fs.Stats` the record uses. */
export type StatLike = {
  dev: number;
  ino: number;
  nlink: number;
  size: number;
  birthtimeMs: number;
  ctimeMs: number;
  /** Modification time: a cross-device `mv` copies it along, unlike the birth time. */
  mtimeMs: number;
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
  /** A cross-device `mv` copies it along; the birth time of the copy is fresh. */
  mtimeMs: number;
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
  /**
   * With `replace`: the call writes in place (Pi's `write` and `edit` tools),
   * so only the same object may keep the record. Another object means the
   * path was replaced by something else, and the record goes.
   */
  inPlace?: boolean;
};

/** What the snapshot keeps of an entry: enough to tell a recreation. */
type EntryMark = { name: string; dev: number; ino: number; birthtimeMs: number };

/** A folder as it was listed before a bash call. */
type FolderBefore = {
  /** Real path: the key of every entry recorded from it. */
  real: string;
  dev: number;
  ino: number;
  /** Keyed by `pathKey(name)`: APFS treats `README.md` and `readme.md` as one name. */
  entries: Map<string, EntryMark>;
  /** Keys that two entries of this listing share (a case-sensitive filesystem). */
  collisions: Set<string>;
};

/**
 * Names in a baselined folder that held an object the agent did not
 * demonstrably make, in any listing this session. C never records one: a user's file that was
 * moved away or stashed and then restored comes back as a new object, and
 * would look like a creation. Memory only, cleared with the record.
 */
type FolderTaint = { keys: Set<string>; full: boolean };

type Pending = {
  inputJson: string;
  startMs: number;
  creations: PendingCreation[];
  /** Claims that passed the final check: refreshed or expired at `tool_result`. */
  claimed: Claim[];
  /** Top-level listings taken at admission, compared at `tool_result`. */
  folders: FolderBefore[];
  /**
   * A call that may restore data from outside the session ran, or was admitted,
   * while this snapshot was open: whatever it restored lands inside this
   * window and cannot be told from the call's own output. Nothing is recorded.
   */
  restoreOverlapped?: boolean;
};

const DEFAULT_MAX_RECORDS = 500;
const DEFAULT_MAX_PENDING = 1000;
const DEFAULT_MAX_WALK_ENTRIES = 20_000;
const DEFAULT_MAX_SNAPSHOT_ENTRIES = 5_000;
const DEFAULT_MAX_TAINT_NAMES = 20_000;
/** Entries examined at once while listing a folder. */
const LIST_BATCH = 64;
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
    mtimeMs: stat.mtimeMs,
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

/**
 * Said when claims come from a prefix of the action: the rest was not read,
 * so it may do anything, including touching a claimed path.
 */
export function scopeLine(firstUnanalysed: string): string {
  return `created_this_session_scope: claims cover only commands before \`${firstUnanalysed}\`; pi-automode did not analyse that command or anything after it`;
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
  /** A folder with more entries than this is not snapshotted. */
  maxSnapshotEntries?: number;
  /** A folder with more tainted names than this is fully tainted. */
  maxTaintNames?: number;
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
  private readonly maxSnapshotEntries: number;
  private readonly maxTaintNames: number;
  private readonly records = new Map<string, CreatedRecord>();
  private readonly pending = new Map<string, Pending>();
  private readonly taint = new Map<string, FolderTaint>();
  /** Folders whose session-start baseline succeeded: the only ones C records in. */
  private readonly baselined = new Set<string>();
  private readonly running = new Map<string, RunningCall>();
  /** Admitted calls that may restore data (`restoresData`), until `release`. */
  private readonly restoring = new Set<string>();
  private restoreEpoch = 0;
  private usable = false;

  constructor(options: CreatedPathsOptions) {
    this.fs = options.fs;
    this.now = options.now ?? (() => new Date());
    this.maxRecords = options.maxRecords ?? DEFAULT_MAX_RECORDS;
    this.maxPending = options.maxPending ?? DEFAULT_MAX_PENDING;
    this.maxWalkEntries = options.maxWalkEntries ?? DEFAULT_MAX_WALK_ENTRIES;
    this.maxSnapshotEntries = options.maxSnapshotEntries ?? DEFAULT_MAX_SNAPSHOT_ENTRIES;
    this.maxTaintNames = options.maxTaintNames ?? DEFAULT_MAX_TAINT_NAMES;
  }

  /** Turn recording and claims on once birth times are known to be real. */
  setUsable(usable: boolean): void {
    this.usable = usable;
  }

  /** Forget everything: records, taint, baselines, pending entries, and running calls. */
  clear(): void {
    this.records.clear();
    this.taint.clear();
    this.baselined.clear();
    this.endTurn();
  }

  /** `agent_end`: no call of this run will report a result any more. */
  endTurn(): void {
    this.pending.clear();
    this.running.clear();
    this.restoring.clear();
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
   * True when every entry below the folder was created after it (birth time,
   * and also modification time, which a cross-device `mv` preserves), on the
   * same device, and is a single-link file, a folder, or a symlink. Symlinks are
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
        // GNU `mv` across devices copies and unlinks: the copy has a fresh
        // birth time but keeps its modification time, folders included.
        if (!(stat.mtimeMs >= identity.birthtimeMs - BIRTH_SLACK_MS)) return false;
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
  async claimsFor(plan: ActionPlan, signal?: AbortSignal, scope?: string): Promise<ClaimSet> {
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
      if (claims.length === 0) return NO_CLAIMS;
      return { claims, lines: [...claims.map(claimLine), ...scope === undefined ? [] : [scopeLine(scope)]] };
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
   * The top-level names of a real folder, with their stats unless it has more
   * entries than the snapshot cap. An entry that vanishes between the listing
   * and its `lstat` is left out of `entries`.
   */
  private async listing(real: string): Promise<{ names: string[]; entries?: Map<string, StatLike> }> {
    const names = await this.fs.readdir(real);
    if (names.length > this.maxSnapshotEntries) return { names };
    const entries = new Map<string, StatLike>();
    for (let index = 0; index < names.length; index += LIST_BATCH) {
      await Promise.all(names.slice(index, index + LIST_BATCH).map(async (name) => {
        try {
          entries.set(name, await this.fs.lstat(joinPath(real, name)));
        } catch (error) {
          if (!isMissing(error)) throw error;
        }
      }));
    }
    return { names, entries };
  }

  /** Taint names (by `pathKey`) in a folder; past the cap the whole folder is tainted. */
  private taintNames(folderKey: string, names: Iterable<string>): void {
    let taint = this.taint.get(folderKey);
    if (!taint) this.taint.set(folderKey, taint = { keys: new Set(), full: false });
    if (taint.full) return;
    for (const name of names) {
      taint.keys.add(pathKey(name));
      if (taint.keys.size > this.maxTaintNames) {
        taint.full = true;
        taint.keys.clear();
        return;
      }
    }
  }

  private isTainted(folderKey: string, name: string): boolean {
    const taint = this.taint.get(folderKey);
    return taint !== undefined && (taint.full || taint.keys.has(pathKey(name)));
  }

  /**
   * `session_start`: list the session folder once, so names that exist before
   * the first bash call are covered even if the user moves them away before
   * it. C records only in folders that had a successful baseline: a folder
   * first listed later has history this module never saw (a user file moved
   * out by an earlier call and restored by a later one would look new).
   *
   * A missing folder has no names, and counts as baselined. Any other error
   * fails closed: the folder is fully tainted and not baselined, so nothing is
   * recorded in it that session.
   */
  async baseline(folder: string): Promise<void> {
    let key = pathKey(folder);
    try {
      const real = await this.fs.realpath(folder);
      key = pathKey(real);
      this.taintNames(key, await this.fs.readdir(real));
      this.baselined.add(key);
    } catch (error) {
      if (isMissing(error)) {
        this.baselined.add(key);
        return;
      }
      this.taintNames(key, []);
      this.taint.get(key)!.full = true;
    }
  }

  /**
   * The listings to compare at `tool_result`; a folder that cannot be listed
   * is skipped. Every name that holds an object without a valid record is
   * tainted (see `FolderTaint`).
   */
  private async snapshotFolders(folders: string[]): Promise<FolderBefore[]> {
    const taken: FolderBefore[] = [];
    const seen = new Set<string>();
    for (const folder of folders) {
      try {
        const real = await this.fs.realpath(folder);
        const folderKey = pathKey(real);
        if (seen.has(folderKey)) continue;
        seen.add(folderKey);
        // No baseline, no recording: this folder's earlier history is unseen.
        if (!this.baselined.has(folderKey)) continue;
        const stat = await this.fs.lstat(real);
        if (!stat.isDirectory()) continue;
        const { names, entries: listed } = await this.listing(real);
        if (!listed) {
          this.taintNames(folderKey, names);
          continue;
        }
        const entries = new Map<string, EntryMark>();
        const collisions = new Set<string>();
        for (const [name, entry] of listed) {
          const key = pathKey(name);
          if (entries.has(key)) collisions.add(key);
          else entries.set(key, { name, dev: entry.dev, ino: entry.ino, birthtimeMs: entry.birthtimeMs });
        }
        this.taintNames(folderKey, [...listed].filter(([name, entry]) => {
          const record = this.records.get(joinPath(real, name));
          const identity = identityOf(entry);
          return collisions.has(pathKey(name)) ||
            !(record && identity && unchanged(record.identity, identity));
        }).map(([name]) => name));
        taken.push({ real, dev: stat.dev, ino: stat.ino, entries, collisions });
      } catch {
        // No snapshot of this folder.
      }
    }
    return taken;
  }

  /**
   * Store what to check at `tool_result`:
   *
   * - for a guarded plan, each creation candidate whose parent exists and
   *   which is either absent or held a claim that passed the final check
   *   (`claims` must be the set that passed it);
   * - for each folder in `snapshotFolders`, its top-level listing, so the
   *   entries the call added or recreated can be recorded even when the guard
   *   cannot read what the call does (a script it runs).
   */
  async prepare(
    toolCallId: string,
    plan: ActionPlan | undefined,
    input: Record<string, unknown>,
    claims: ClaimSet,
    snapshotFolders: string[] = [],
  ): Promise<void> {
    this.pending.delete(toolCallId);
    if (!this.usable) return;
    const epoch = this.restoreEpoch;
    const creations: PendingCreation[] = [];
    if (plan) {
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
    }
    const folders = await this.snapshotFolders(snapshotFolders);
    if (!plan && folders.length === 0) return;
    this.store(toolCallId, {
      inputJson: JSON.stringify(input),
      // After the listings, so an entry created while they ran is not
      // mistaken for the call's own.
      startMs: this.now().getTime(),
      creations,
      claimed: claims.claims,
      folders,
      // A restoring call running now, or admitted while the listings ran
      // (even if it has finished since), overlaps this snapshot.
      restoreOverlapped: this.restoreEpoch !== epoch || this.restoringBeside(toolCallId),
    });
  }

  /**
   * Store what to check when a `write` or `edit` call finishes. Pi writes
   * both tools in place, with no temporary file, so the inode does not change.
   *
   * - `write` to an absent path in an existing folder: a creation, recorded
   *   as `write tool call` if the result checks pass.
   * - `write` or `edit` of a recorded file that is still unchanged: its size
   *   and change time are refreshed when the call ends.
   * - `write` or `edit` of a recorded path that is not unchanged any more
   *   (the user may have changed it): the record is deleted now, for good.
   *
   * No claim or fact line comes from these calls; path policy decides them.
   * `path` must already be resolved the way Pi resolves it.
   */
  async prepareFileTool(
    toolCallId: string,
    tool: "write" | "edit",
    path: string,
    input: Record<string, unknown>,
  ): Promise<void> {
    this.pending.delete(toolCallId);
    if (!this.usable || !isPlainAbsolutePath(path)) return;
    try {
      const canonical = await this.canonical(path);
      const record = this.records.get(canonical);
      let now: Identity | undefined;
      let exists = true;
      try {
        now = await this.identity(canonical);
      } catch (error) {
        if (!isMissing(error)) throw error;
        exists = false;
      }
      const parent = parentOf(canonical);
      const parentStat = await this.fs.lstat(parent);
      if (!parentStat.isDirectory()) return;
      const parentIdentity = { dev: parentStat.dev, ino: parentStat.ino };
      const startMs = this.now().getTime();
      const inputJson = JSON.stringify(input);
      if (record) {
        if (!exists || !now || !unchanged(record.identity, now)) {
          this.records.delete(canonical);
          return;
        }
        if (record.identity.kind !== "file") return;
        this.store(toolCallId, {
          inputJson,
          startMs,
          creations: [{
            path,
            canonical,
            how: record.how,
            parent,
            parentIdentity,
            replace: record,
            inPlace: true,
          }],
          claimed: [{ path, canonical, record, folderRemoval: false }],
          folders: [],
        });
        return;
      }
      if (tool !== "write" || exists) return;
      this.store(toolCallId, {
        inputJson,
        startMs,
        creations: [{ path, canonical, how: "write tool call", parent, parentIdentity }],
        claimed: [],
        folders: [],
      });
    } catch {
      // Nothing is recorded or refreshed.
    }
  }

  private store(toolCallId: string, pending: Pending): void {
    this.pending.set(toolCallId, pending);
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
    // The pending entry is gone from here on, so `markRestoring` can no longer
    // mark it: a restoring call admitted during the awaits below is seen by
    // its epoch (and by the running set) after the after-listing.
    const epoch = this.restoreEpoch;
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
        // A tool that writes in place did not make a different object.
        if (creation.inPlace) continue;
        if (now.kind === "file" && now.nlink !== 1) continue;
        if (now.birthtimeMs < pending.startMs - BIRTH_SLACK_MS) continue;
        // A cross-device `mv` into the path keeps the old modification time.
        if (now.mtimeMs < pending.startMs - BIRTH_SLACK_MS) continue;
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
    const claimed = new Set(pending.claimed.map((claim) => claim.canonical));
    for (const folder of pending.folders) {
      await this.completeFolder(folder, pending.startMs, at, settled, claimed, pending.restoreOverlapped === true, {
        toolCallId,
        epoch,
      });
    }
  }

  /**
   * Record the top-level entries a bash call added in a folder. An entry
   * counts only when all of these hold:
   *
   * - it is a single-link regular file or a folder, never a symlink;
   * - its birth time and its modification time both fall inside the call (a
   *   cross-device `mv` leaves a fresh birth time but the old mtime);
   * - the folder is still the same real folder as at admission;
   * - its name is not tainted, and does not collide with another spelling;
   * - it is absent from the first listing, or it replaced an object that this
   *   action's own claim covered (the action removed it, a later command in
   *   it recreated it). Any other same-name replacement is refused: `sed -i`,
   *   `perl -i`, and atomic saves rename a new file over the user's, and the
   *   listing cannot tell a script's rewrite of the agent's file from a user
   *   edit made in the same window, so even an agent-owned file rewritten
   *   atomically by a script loses its record (it fails safe).
   *
   * If a call that may restore data overlapped this one (`markRestoring`),
   * nothing is recorded, but stale records are still deleted and every new or
   * changed name is tainted.
   *
   * Any other process that adds an entry to the folder while the call runs is
   * recorded too: the record is evidence for Jev, not proof. Afterwards every
   * name without a valid record is tainted.
   */
  private async completeFolder(
    before: FolderBefore,
    startMs: number,
    at: string,
    settled: Set<string>,
    claimed: Set<string>,
    overlapped: boolean,
    completing: { toolCallId: string; epoch: number },
  ): Promise<void> {
    const folderKey = pathKey(before.real);
    try {
      const { names, entries: listed } = await this.listing(before.real);
      if (!listed) {
        this.taintNames(folderKey, names);
        return;
      }
      if (await this.fs.realpath(before.real) !== before.real) return;
      const folder = await this.fs.lstat(before.real);
      if (folder.dev !== before.dev || folder.ino !== before.ino) return;
      // Re-check after the after-listing: a restoring call admitted while it
      // ran may have restored files before it was taken.
      overlapped ||= this.restoreEpoch !== completing.epoch || this.restoringBeside(completing.toolCallId);
      const afterCount = new Map<string, number>();
      for (const name of listed.keys()) afterCount.set(pathKey(name), (afterCount.get(pathKey(name)) ?? 0) + 1);
      for (const [key, mark] of before.entries) {
        // Removed during the call: its record, if any, is stale.
        const path = joinPath(before.real, mark.name);
        if (!afterCount.has(key) && !settled.has(path)) this.records.delete(path);
      }
      for (const [name, stat] of listed) {
        const key = pathKey(name);
        const canonical = joinPath(before.real, name);
        if (settled.has(canonical)) continue;
        const mark = before.entries.get(key);
        if (mark && mark.dev === stat.dev && mark.ino === stat.ino && mark.birthtimeMs === stat.birthtimeMs) {
          continue;
        }
        // Absent before, or a different object under the same name.
        this.records.delete(canonical);
        // A restoring call overlapped: record nothing; the taint below keeps
        // the name from being recorded by a later call.
        if (overlapped) continue;
        if (afterCount.get(key)! > 1 || before.collisions.has(key)) continue;
        const own = claimed.has(canonical);
        if (!own && (mark || this.isTainted(folderKey, name))) continue;
        const identity = identityOf(stat);
        if (!identity) continue;
        if (identity.kind === "file" && identity.nlink !== 1) continue;
        if (identity.birthtimeMs < startMs - BIRTH_SLACK_MS) continue;
        if (identity.mtimeMs < startMs - BIRTH_SLACK_MS) continue;
        this.remember({ path: canonical, canonical, identity, how: "bash command", at });
      }
      this.taintNames(folderKey, [...listed].filter(([name, stat]) => {
        const record = this.records.get(joinPath(before.real, name));
        const identity = identityOf(stat);
        return afterCount.get(pathKey(name))! > 1 || !(record && identity && unchanged(record.identity, identity));
      }).map(([name]) => name));
    } catch {
      // No records from this folder.
    }
  }

  /** `tool_execution_end`: the call is over. */
  release(toolCallId: string): void {
    this.pending.delete(toolCallId);
    this.running.delete(toolCallId);
    this.restoring.delete(toolCallId);
  }

  /** True when a restoring call other than this one (or its codemode parent) is running. */
  private restoringBeside(toolCallId: string): boolean {
    return [...this.restoring].some((id) => id !== toolCallId && !toolCallId.startsWith(`${id}/`));
  }

  /**
   * Register an admitted call that may restore data from outside the session
   * (`restoresData`), until `release`. Every open snapshot is marked: what the
   * call restores would land inside its window. A snapshot prepared while the
   * call runs is marked too. Call this synchronously at admission.
   */
  markRestoring(toolCallId: string): void {
    this.restoring.add(toolCallId);
    this.restoreEpoch += 1;
    for (const pending of this.pending.values()) {
      if (pending.folders.length > 0) pending.restoreOverlapped = true;
    }
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
