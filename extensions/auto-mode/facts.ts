/**
 * facts.ts — deterministic action facts for the Jev classifier.
 *
 * Jev scores text; it does not parse shell. These facts come from
 * pi-automode's own Bash parser, never from agent-written text, so the
 * classifier can see whether an action writes anything and where it runs.
 *
 * Facts are evidence only. They never allow or block an action by themselves,
 * and `read_only=true` is claimed only when every parsed command is on a small
 * allowlist with no unsafe options. Anything else is `unverified`.
 */
import { analyzeBash, type BashCommandAnalysis } from "./bash.ts";

/** Commands that only read, provided their arguments pass `hasUnsafeArgument`. */
const READ_ONLY_COMMANDS = new Set([
  "cat",
  "cd",
  "date",
  "df",
  "du",
  "echo",
  "egrep",
  "fgrep",
  "find",
  "free",
  "grep",
  "head",
  "hostname",
  "id",
  "jq",
  "ls",
  "nproc",
  "ps",
  "pwd",
  "rg",
  "sort",
  "stat",
  "tail",
  "true",
  "uname",
  "uptime",
  "wc",
  "which",
  "whoami",
]);

/** Arguments that make an allowlisted command write, delete, or execute. */
const UNSAFE_ARGUMENTS: Record<string, (arg: string) => boolean> = {
  find: (arg) =>
    /^-(delete|exec|execdir|ok|okdir|fprint|fprint0|fprintf|fls)$/.test(arg),
  // Any short-option cluster containing `o` may be `-o FILE`.
  sort: (arg) => /^-[^-]*o/.test(arg) || arg.startsWith("--output"),
  rg: (arg) => arg === "--pre" || arg.startsWith("--pre="),
  // `hostname NAME` and `hostname -F FILE` set the host name.
  hostname: (arg) =>
    !arg.startsWith("-") || /^-[^-]*[bF]/.test(arg) || arg.startsWith("--file") ||
    arg.startsWith("--boot"),
  // `date -s` and a bare `date MMDDhhmm` set the clock; `+FORMAT` only reads.
  date: (arg) =>
    /^-[^-]*s/.test(arg) || arg.startsWith("--set") ||
    (!arg.startsWith("-") && !arg.startsWith("+")),
};

/** curl short flags that neither write files nor change the request. */
const CURL_SAFE_FLAGS = new Set(["s", "S", "L", "f", "v", "I", "i", "N"]);
/** curl long flags that neither write files nor change the request. */
const CURL_SAFE_LONG_FLAGS = new Set([
  "--silent",
  "--show-error",
  "--location",
  "--fail",
  "--head",
  "--include",
  "--verbose",
  "--no-buffer",
  "--compressed",
]);
/** curl options whose value is output formatting, headers, or a timeout. */
const CURL_SAFE_VALUE_OPTIONS = new Set([
  "-w",
  "--write-out",
  "-H",
  "--header",
  "-m",
  "--max-time",
  "--connect-timeout",
  "-A",
  "--user-agent",
]);

/**
 * True when every curl argument is a URL or a known read-only option. Writing
 * files (`-o FILE`, `-O`, `-D FILE`, `-c`, `--trace`), sending data (`-d`, `-F`,
 * `-T`, `--json`), changing the method (`-X`), reading a config (`-K`), and
 * `-k` (TLS verification off) are all unverified. `-o /dev/null` and `-D -`
 * only discard or print.
 */
function curlIsReadOnly(args: string[]): boolean {
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]!;
    if (!arg.startsWith("-")) continue;
    const next = args[index + 1];
    if (arg === "-o" || arg === "--output") {
      if (next !== "/dev/null") return false;
      index += 1;
      continue;
    }
    if (arg === "-D" || arg === "--dump-header") {
      if (next !== "-") return false;
      index += 1;
      continue;
    }
    if (CURL_SAFE_VALUE_OPTIONS.has(arg)) {
      index += 1;
      continue;
    }
    if (arg.startsWith("--")) {
      if (!CURL_SAFE_LONG_FLAGS.has(arg)) return false;
      continue;
    }
    if (![...arg.slice(1)].every((flag) => CURL_SAFE_FLAGS.has(flag))) {
      return false;
    }
  }
  return true;
}

/** ssh options that take a value and are safe for a one-shot command. */
const SSH_VALUE_OPTIONS = new Set(["-p", "-l", "-i"]);
/** ssh flags that take no value and are safe for a one-shot command. */
const SSH_FLAG_PATTERN = /^-[46qTtvnCx]+$/;
/** `-o Key=Value` settings that do not run commands, forward ports, or weaken host checks. */
const SSH_SAFE_OPTION_KEYS = new Set([
  "batchmode",
  "connecttimeout",
  "connectionattempts",
  "serveraliveinterval",
  "serveralivecountmax",
  "loglevel",
  "requesttty",
]);

/** Redirect operators that write to a file target. */
const WRITE_OPERATORS = new Set([">", ">>", ">|", "<>", "&>", "&>>"]);

type ActionShape = { toolName?: unknown; input?: { command?: unknown } };

type RemoteShell = {
  host?: string;
  commands: string[];
  readOnly: boolean;
};

function hasUnsafeArgument(name: string, args: string[]): boolean {
  const unsafe = UNSAFE_ARGUMENTS[name];
  return unsafe ? args.some(unsafe) : false;
}

function isWriteRedirect(
  redirect: BashCommandAnalysis["redirects"][number],
): boolean {
  if (redirect.heredoc) return false;
  if (redirect.operator === ">&") {
    // `2>&1` and `>&-` duplicate or close descriptors; `>&file` writes a file.
    return redirect.targetDynamic ||
      !/^(\d+|-)$/.test(redirect.target ?? "");
  }
  if (!WRITE_OPERATORS.has(redirect.operator)) return false;
  return redirect.targetDynamic || redirect.target !== "/dev/null";
}

function fileWriteTargets(commands: BashCommandAnalysis[]): string[] {
  return commands.flatMap((command) =>
    command.redirects.filter(isWriteRedirect).map((redirect) =>
      redirect.targetDynamic ? "(dynamic)" : redirect.target ?? "(unknown)"
    )
  );
}

/** Strip a leading `timeout [opts] DURATION`, which only bounds run time. */
function unwrapTimeout(name: string | undefined, args: string[]): {
  name?: string;
  args: string[];
} {
  if (name !== "timeout") return { name, args };
  let index = 0;
  while (index < args.length && args[index]!.startsWith("-")) {
    const option = args[index]!;
    index += option === "-s" || option === "-k" ? 2 : 1;
  }
  index += 1; // duration
  const inner = args[index];
  return inner === undefined
    ? { name, args }
    : { name: inner.split("/").pop()!.toLowerCase(), args: args.slice(index + 1) };
}

/**
 * Parse `ssh [safe options] HOST COMMAND...`. Returns `readOnly: false` for any
 * option outside the safe set, a missing command (interactive shell), or a
 * remote command that is not verifiably read-only.
 */
function analyzeSsh(args: string[]): RemoteShell {
  let optionsSafe = true;
  let index = 0;
  while (index < args.length && args[index]!.startsWith("-")) {
    const option = args[index]!;
    if (option === "--") {
      index += 1;
      break;
    }
    if (SSH_VALUE_OPTIONS.has(option)) {
      index += 2;
      continue;
    }
    if (option === "-o") {
      const key = (args[index + 1] ?? "").split("=")[0]!.toLowerCase();
      if (!SSH_SAFE_OPTION_KEYS.has(key)) optionsSafe = false;
      index += 2;
      continue;
    }
    if (!SSH_FLAG_PATTERN.test(option)) optionsSafe = false;
    index += 1;
  }
  const target = args[index];
  const host = target?.split("@").pop()?.toLowerCase();
  const remoteSource = args.slice(index + 1).join(" ");
  if (!host || remoteSource.trim() === "") {
    return { host, commands: [], readOnly: false };
  }
  const remote = analyzeBash(remoteSource);
  const commands = remote.commands.map((command) =>
    command.effectiveCommand.name ?? "(dynamic)"
  );
  const readOnly = optionsSafe &&
    remote.errors.length === 0 &&
    fileWriteTargets(remote.commands).length === 0 &&
    remote.commands.every((command) => commandIsReadOnly(command, false));
  return { host, commands, readOnly };
}

function commandIsReadOnly(
  command: BashCommandAnalysis,
  allowRemoteShell: boolean,
): boolean {
  if (command.dynamic || command.effectiveCommand.unresolvedTransparentDispatch) {
    return false;
  }
  const { name, args } = unwrapTimeout(
    command.effectiveCommand.name,
    command.effectiveCommand.args,
  );
  if (!name) return false;
  if (name === "ssh") return allowRemoteShell && analyzeSsh(args).readOnly;
  if (name === "curl") return curlIsReadOnly(args);
  return READ_ONLY_COMMANDS.has(name) && !hasUnsafeArgument(name, args);
}

/**
 * Describe a serialized classifier action as `key: value` lines, or return ""
 * when the action is not a parseable `bash` call. See the module comment for
 * what `read_only` means.
 */
export function describeActionFacts(
  action: string,
  trustedHosts: string[],
): string {
  let parsed: ActionShape;
  try {
    parsed = JSON.parse(action) as ActionShape;
  } catch {
    return "";
  }
  const command = parsed?.input?.command;
  if (parsed?.toolName !== "bash" || typeof command !== "string") return "";

  const analysis = analyzeBash(command);
  if (analysis.errors.length > 0) {
    return ["parser: failed", "read_only: unverified"].join("\n");
  }

  const trusted = new Set(trustedHosts.map((host) => host.toLowerCase()));
  const writes = fileWriteTargets(analysis.commands);
  const names = analysis.commands.flatMap((c) => {
    const name = c.effectiveCommand.name ?? "(dynamic)";
    const inner = unwrapTimeout(c.effectiveCommand.name, c.effectiveCommand.args)
      .name;
    return inner && inner !== name ? [name, inner] : [name];
  });
  const lines = [
    "parser: ok",
    `commands: ${names.join(", ") || "(none)"}`,
    `local_file_writes: ${writes.join(", ") || "none"}`,
  ];
  let remoteShells = 0;
  let remoteReadOnly = true;
  for (const bashCommand of analysis.commands) {
    const unwrapped = unwrapTimeout(
      bashCommand.effectiveCommand.name,
      bashCommand.effectiveCommand.args,
    );
    if (unwrapped.name !== "ssh") continue;
    const remote = analyzeSsh(unwrapped.args);
    const verified = remote.readOnly && !bashCommand.dynamic;
    remoteShells += 1;
    remoteReadOnly &&= verified;
    lines.push(
      `remote_shell: ssh host=${remote.host ?? "(unknown)"} trusted=${
        remote.host !== undefined && trusted.has(remote.host)
      } commands=${remote.commands.join(", ") || "(none)"} read_only=${
        verified ? "true" : "unverified"
      }`,
    );
  }
  // A redirect after `ssh HOST '...'` is performed by the local shell. Say so,
  // so a local write is not read as a write through the remote shell.
  if (remoteShells > 0 && remoteReadOnly && writes.length > 0) {
    lines.push(
      `write_location: local only: the local shell writes ${writes.join(", ")} on this machine; the remote command writes nothing`,
    );
  }
  const readOnly = writes.length === 0 &&
    analysis.commands.length > 0 &&
    analysis.commands.every((c) => commandIsReadOnly(c, true));
  lines.push(`read_only: ${readOnly ? "true" : "unverified"}`);
  return lines.join("\n");
}
