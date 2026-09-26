/**
 * approvals.ts — parser-derived patterns for "allow similar for this session".
 *
 * A pattern pins every command in a `bash` action: the command names in order,
 * the separators between them, every flag, every non-numeric argument, the ssh
 * host and its remote commands, and every redirect. Only numbers in value
 * positions (`-n 50`, `head -20`, `ConnectTimeout=15`, a `timeout` duration)
 * and `--flag=value` values may vary. Anything the parser cannot pin down gets
 * no pattern, so the user can only allow it once.
 *
 * A pattern only replaces the soft-deny prompt. It never overrides a hard deny
 * or any deterministic layer, which run before the classifier.
 */
import { analyzeBash, type BashAnalysis, type BashCommandAnalysis } from "./bash.ts";
import { parseSshArgs, unwrapTimeout } from "./facts.ts";

export type ApprovalSignature = {
  /** Stable key compared between actions. */
  key: string;
  /** The pattern as shown to the user, with `<n>` and `…` for what may vary. */
  description: string;
};

const NUMBER = /^-?\d+(?:\.\d+)?[a-zA-Z%]{0,3}$/;

/** Commands whose numbers are targets (PIDs, modes, ids, ports), never free. */
const EXACT_NUMBER_COMMANDS = new Set([
  "kill",
  "pkill",
  "killall",
  "chmod",
  "chown",
  "chgrp",
  "umask",
  "renice",
  "ulimit",
  "iptables",
  "ip6tables",
  "ufw",
  "firewall-cmd",
  "nft",
]);

/** Commands that run another shell; their inner script is not pinned down. */
const NESTED_SHELLS = new Set(["bash", "sh", "zsh", "dash", "eval", "source", "."]);

function normalizeArgs(name: string, args: string[]): string[] {
  // `sudo chmod -R 755` must stay exact too, so any word naming one of these
  // commands keeps every number exact.
  const exactNumbers = EXACT_NUMBER_COMMANDS.has(name) ||
    args.some((arg) => EXACT_NUMBER_COMMANDS.has(arg));
  return args.map((arg, index) => {
    if (arg.startsWith("-") && !NUMBER.test(arg) && arg.includes("=")) {
      return `${arg.slice(0, arg.indexOf("="))}=…`;
    }
    if (exactNumbers) return arg;
    if (NUMBER.test(arg)) {
      const previous = args[index - 1];
      const flagValue = previous !== undefined && previous.startsWith("-") &&
        !NUMBER.test(previous);
      // `-20` is a count flag; a number after a flag is that flag's value.
      if (arg.startsWith("-") || flagValue) return "<n>";
      return arg;
    }
    const equals = arg.indexOf("=");
    if (equals > 0 && NUMBER.test(arg.slice(equals + 1))) {
      return `${arg.slice(0, equals)}=<n>`;
    }
    return arg;
  });
}

function quote(text: string): string {
  // Placeholders are shown bare so the pattern reads as a pattern.
  if (text === "<n>" || text.endsWith("=<n>") || text.endsWith("=…")) return text;
  return /^[A-Za-z0-9_./:@%+=,-]+$/.test(text) ? text : `'${text}'`;
}

type Part = { key: unknown; text: string };

function redirectParts(command: BashCommandAnalysis): Part[] | undefined {
  const parts: Part[] = [];
  for (const redirect of command.redirects) {
    // Heredoc bodies are not captured, so their content could change unseen.
    if (redirect.heredoc || redirect.targetDynamic) return undefined;
    const target = redirect.target ?? "";
    // `2>&1` and `>&-` only duplicate or close descriptors.
    if (
      (redirect.operator === ">&" || redirect.operator === "<&") &&
      /^(\d+|-)$/.test(target)
    ) {
      parts.push({ key: [redirect.fileDescriptor ?? null, redirect.operator, target], text: "" });
      continue;
    }
    parts.push({
      key: [redirect.fileDescriptor ?? null, redirect.operator, target],
      text: `${redirect.operator} ${target}`,
    });
  }
  return parts;
}

function commandPart(command: BashCommandAnalysis, remote: boolean): Part | undefined {
  if (command.dynamic || command.effectiveCommand.unresolvedTransparentDispatch) {
    return undefined;
  }
  const name = command.effectiveCommand.name;
  if (!name || NESTED_SHELLS.has(name)) return undefined;
  const args = command.effectiveCommand.args;
  const redirects = redirectParts(command);
  if (!redirects) return undefined;
  const redirectText = redirects.map((r) => r.text).filter(Boolean).join(" ");
  const redirectKeys = redirects.map((r) => r.key);

  const inner = unwrapTimeout(name, args);
  const prefixLength = args.length - inner.args.length - 1;
  const prefix = name === "timeout" && inner.name !== name
    ? args.slice(0, prefixLength).map((arg) => (NUMBER.test(arg) ? "<n>" : arg))
    : undefined;
  const innerName = prefix ? inner.name! : name;
  const innerArgs = prefix ? inner.args : args;
  const lead = prefix ? ["timeout", ...prefix] : [];

  if (innerName === "ssh") {
    if (remote) return undefined; // nested remote shells are not followed
    const ssh = parseSshArgs(innerArgs);
    if (!ssh.host || ssh.remoteSource.trim() === "") return undefined;
    const remoteSignature = signatureForSource(ssh.remoteSource, true);
    if (!remoteSignature) return undefined;
    const options = normalizeArgs("ssh", ssh.options);
    const target = innerArgs[ssh.options.length]!;
    return {
      key: ["ssh", lead, options, ssh.host, remoteSignature.key, redirectKeys],
      text: [...lead, "ssh", ...options.map(quote), target, `'${remoteSignature.description}'`, redirectText]
        .filter(Boolean).join(" "),
    };
  }
  const normalized = normalizeArgs(innerName, innerArgs);
  return {
    key: [innerName, lead, normalized, redirectKeys],
    text: [...lead, innerName, ...normalized.map(quote), redirectText].filter(Boolean).join(" "),
  };
}

function signatureForAnalysis(
  analysis: BashAnalysis,
  remote: boolean,
): ApprovalSignature | undefined {
  if (analysis.errors.length > 0 || !analysis.allowStructureSafe) return undefined;
  if (analysis.commands.length === 0) return undefined;
  const keys: unknown[] = [];
  const texts: string[] = [];
  let previousEnd: number | undefined;
  for (const command of analysis.commands) {
    const part = commandPart(command, remote);
    if (!part) return undefined;
    if (previousEnd !== undefined) {
      const separator = analysis.source.slice(previousEnd, command.pos).trim();
      keys.push(separator);
      texts.push(separator);
    }
    keys.push(part.key);
    texts.push(part.text);
    previousEnd = command.end;
  }
  return {
    key: JSON.stringify(keys),
    description: texts.join(" ").replace(/\s+/g, " ").trim(),
  };
}

function signatureForSource(source: string, remote: boolean): ApprovalSignature | undefined {
  if (source.trim() === "") return undefined;
  return signatureForAnalysis(analyzeBash(source), remote);
}

/**
 * The session-approval pattern for a serialized classifier action, or
 * undefined when the action is not a `bash` call the parser can pin down.
 */
export function approvalSignature(action: string): ApprovalSignature | undefined {
  let parsed: { toolName?: unknown; input?: { command?: unknown } };
  try {
    parsed = JSON.parse(action);
  } catch {
    return undefined;
  }
  const command = parsed?.input?.command;
  if (parsed?.toolName !== "bash" || typeof command !== "string") return undefined;
  const signature = signatureForSource(command, false);
  return signature && { key: `bash:${signature.key}`, description: signature.description };
}
