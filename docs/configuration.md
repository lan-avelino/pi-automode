# Configuration

The extension follows the documented Claude Code configuration model where Pi supports it.

It reads `autoMode` only from Pi-owned configuration sources:

- `~/.pi/agent/extensions/pi-automode/config.json`
- `.pi/automode.local.json` for trusted projects
- `PI_AUTOMODE_SETTINGS_JSON`

At startup, pi-automode moves a legacy `~/.pi/agent/automode.json` file to the new global path. If both files exist, it uses the new file and reports the conflict. If migration fails, it uses the legacy file for that session and reports the error.

It does not read project configuration until Pi trusts the project. For an untrusted project, it ignores `.pi/automode.local.json` and `.pi/automode.json`. `/automode config` reports each ignored file that exists.

Shared project `.pi/automode.json` cannot weaken auto mode. For a trusted project, it can add `permissions.deny` and `permissions.ask` rules.

The shared file cannot set `autoMode` or add `permissions.allow` rules. If the file contains `permissions.allow`, `/automode config` reports a diagnostic.

To disable pi-automode for the current project, create or edit `.pi/automode.local.json`:

```json
{
  "autoMode": {
    "enabled": false
  }
}
```

This file is project-local. Pi reads it only after project trust. Do not commit this file. Shared project `.pi/automode.json` cannot disable auto mode.

Set a global default classifier model in `~/.pi/agent/extensions/pi-automode/config.json`. For a trusted project, override it in `.pi/automode.local.json`.

`classifierReasoningLevel` requests `low`, `medium`, `high`, `xhigh`, or `max` reasoning for both classifier stages. If the key is absent, pi-automode sends no reasoning preference. The server then selects the level.

Pi AI clamps an unsupported value to the nearest level that the selected model supports. A model without reasoning support resolves to `off`. `low` matches the reasoning effort of Codex Auto Review.

Higher levels can use all 512 or 1200 stage tokens before they produce visible output. In this case, the classifier fails closed. If truncation occurs before the required `0` or `1` digit, increase `fastClassifierMaxTokens`. The default is 512, and the minimum is 16.

`classifierTimeoutMs` limits each classifier request in milliseconds. The default is 20000, and the minimum is 1000. The fast and detailed stages have separate budgets.

If a request stalls or exceeds its budget, pi-automode aborts it. Then auto mode fails closed and blocks the action.

## Jev classifier backend

`classifierBackend` selects the classifier stage: `"llm"` (default) or `"jev"`. The Jev backend replaces only the classifier stage and leaves every deterministic layer unchanged. Any Jev error fails closed.

The following keys apply only when `classifierBackend` is `"jev"`:

| Key | Default | Meaning |
| --- | --- | --- |
| `jevModel` | `"~typesafe/jev-latest"` | Jev model id sent to the decisions endpoint |
| `jevBaseUrl` | `"https://openrouter.ai/api/v1"` | Chat-compatible base URL; pi-automode derives `/api/alpha/decisions` |
| `jevApiKeyEnv` | `"OPENROUTER_API_KEY"` | Environment variable consulted after the Pi registry and before stored auth. On a custom `jevBaseUrl`, the default variable is withheld and a custom variable must be named |
| `jevTimeoutMs` | `12000` | Per-request timeout, integer from 1000 through 2147483647 |
| `jevHardDenyThreshold` | `0.5` | `hard_deny` probability at or above which the action is blocked |
| `jevSoftDenyThreshold` | `0.5` | Highest authorization-aware probability (`soft_deny_uncovered`, `intent_mismatch`) at or above which the action is blocked. The benign ceiling moves with the classifier transcript; see [Jev classifier backend](jev-classifier-backend.md) for the measurements behind this value |
| `jevScopeEscapeThreshold` | `0.5` | `scope_escape` probability at or above which the action is blocked. Gated separately from the other soft-side questions |

`scope_escape` gates at its own, higher threshold. It asks whether the action reaches outside the trusted repository, working tree, or trusted environment. It has no LLM-classifier counterpart, and it never overrides `hard_deny`. Because it is a supporting signal, it must not decide the verdict alone: an action that `soft_deny_uncovered` and `intent_mismatch` both clear is not blocked by `scope_escape` unless it reaches `jevScopeEscapeThreshold`.

`classifierBackend` is a scalar with normal precedence: global, then project-local, then `PI_AUTOMODE_SETTINGS_JSON`. Shared project `.pi/automode.json` cannot set it. `classifierReasoningLevel` and `fastClassifierMaxTokens` are ignored when `classifierBackend` is `"jev"`.

Jev key resolution is the Pi registry (`/login openrouter`), then `jevApiKeyEnv`, then stored `auth.json`. The registry and stored credentials are only used when `jevBaseUrl` targets OpenRouter. A custom base URL must name its own key variable in `jevApiKeyEnv`; the default `OPENROUTER_API_KEY` is withheld from custom hosts so the OpenRouter key is never sent to a third party. A response that omits any requested question id fails closed.

Jev sends the same bounded context the LLM classifier sees: the token-bounded transcript, the per-file-bounded project instructions, and the full redacted rule lists. Pi-automode does not truncate the current action and does not re-bound the transcript or the rule lists for Jev; a payload the endpoint rejects fails closed.

The transcript keeps only the most recent tool calls (12) and bounds each tool-call input to a budget whose string cap is `budget / 4` characters (375 with the default `1500`). Tool inputs are the agent's own actions, not the user's authorization. Measured against the live endpoint, the inflation tracks the security vocabulary in the input text rather than its length or recency, and the user's authorization lives in the user entries, which are budgeted separately and are unaffected by any tool-transcript budget. `maxToolTranscriptTokens` does not bind at its `4000` default because the retained tool calls are shorter than that.

Jev cannot report the LLM classifier's `allow` or `explicit_intent` tiers, so its allow tier is always `none`. Only the optional `classifier` I/O log records that a Jev allow overrode a soft-deny rule, through the score summary.

`/automode backend <llm|jev>` writes `classifierBackend` to the global config. When the Jev backend is active, `/automode model` writes `jevModel` and does not require the model to be present in the Pi registry; the Pi model picker is LLM-only, so pass the Jev model id explicitly. `/automode jev` reports the effective endpoint, credential source, and thresholds. `/automode jev test` sends one clearly safe and one clearly dangerous probe to the live endpoint and reports both verdicts, which validates that `noul` answers are danger-side-up.

`allowInsideWorkingDirectory` adds a deterministic allow tier for the file tools. The default value is `false`. The file tools are `read`, `write`, `edit`, `grep`, `find`, and `ls`.

The value `allowInsideWorkingDirectory: true` allows access to paths inside the working directory without classifier review. Pi-automode sends access to outside paths to the classifier. This rule also applies to read calls.

This tier takes precedence over `classifyReadOnlyTools`. If both configuration fields are enabled, pi-automode still allows in-tree file access locally. `classifyReadOnlyTools: true` does not change this behavior.

Protected in-tree targets do not use this allow tier. Writes and edits to `.git/hooks`, `.pi` controls, shell profiles, and configuration files still reach the classifier.

`deniedPaths` is a list of path glob patterns. The default list is `[]`. A matching pattern blocks a file-tool call before classifier review or an allow tier.

Patterns support `~`, `$HOME`, and `${HOME}` expansion. The `*` wildcard matches all characters, including `/`. Thus, `**/id_rsa` matches a private key at any depth.

Each pattern can contain at most 4,096 UTF-16 code units. Pi-automode matches the typed path and its symlink-resolved form. It also resolves the fixed path prefix of each pattern. Thus, a symlink alias cannot bypass a denied target.

If a recursive `grep` or `find` scope can contain a denied path, pi-automode blocks the call. A broad pattern such as `*.env` blocks these tools for every directory scope.

A matching path blocks the call without classifier review or an override. The list applies only to file tools. The classifier governs `bash` path access. Both keys use the normal scalar and array precedence.

`allowInsideWorkingDirectory` uses scalar precedence: global, then project-local, then `PI_AUTOMODE_SETTINGS_JSON`. `deniedPaths` entries accumulate across these configuration sources.

Shared project `.pi/automode.json` cannot set either field. Omitting either field at a higher-precedence source does not clear a lower-source value.

Example:

```json
{
  "autoMode": {
    "classifierBackend": "llm",
    "classifierModel": "provider/model-id",
    "classifierReasoningLevel": "low",
    "classifyReadOnlyTools": false,
    "fastClassifierMaxTokens": 512,
    "classifierTimeoutMs": 20000,
    "allowInsideWorkingDirectory": false,
    "deniedPaths": [],
    "maxUserTranscriptTokens": 4000,
    "maxToolTranscriptTokens": 4000,
    "environment": [
      "$defaults",
      "Source control: github.example.com/acme-corp and all repos under it",
      "Trusted internal domains: *.corp.example.com, git.example.com",
      "Trusted cloud buckets: s3://acme-dev-artifacts, gs://acme-ci-cache",
      "Key internal services: staging deploy API at deploy.corp.example.com"
    ],
    "allow": ["$defaults"],
    "protectedPaths": ["$defaults"],
    "soft_deny": ["$defaults"],
    "hard_deny": [
      "$defaults",
      "Never send repository contents to third-party code-review APIs"
    ]
  },
  "permissions": {
    "deny": ["bash(rm -rf *)"],
    "ask": ["bash(git push *)"],
    "allow": ["bash(git status*)", "example-extension-tool"]
  }
}
```

`maxUserTranscriptTokens` and `maxToolTranscriptTokens` are approximate budgets for each category. Both default to 4000 and accept integers of at least 32.

Pi-automode does not support the former `maxTranscriptLines` field. Evidence selection now uses token budgets instead of line counts.

## Ask-user tools and explicit authorization

Classifier evidence includes normal user messages and assistant tool-call inputs. It excludes assistant prose and all tool results. This exclusion includes answers from ask-user tools such as `@vanillagreen/pi-questions`.

Selecting "Yes" in that tool helps the agent select its next action. Pi-automode does not treat the result as authorization to override a soft deny.

Send the authorization as a normal chat message. Then the agent can retry the action. Tool results remain excluded because they can contain untrusted or prompt-injected content.

## `$defaults`

See [Defaults and rule-list behavior](defaults.md) for built-in `environment`, `allow`, `protectedPaths`, `soft_deny`, and `hard_deny` entries. The document also explains replacement behavior after omission of `$defaults`.

## Observability logging

Auto mode can write a JSONL observability log for decisions and classifier usage. Persisted sessions use a sidecar next to the Pi session file. In-memory sessions use a global application directory. Logging is off by default.

```json
{
  "autoMode": {
    "log": {
      "enabled": true,
      "classifierIo": false
    }
  }
}
```

With logging enabled, persisted-session sidecars also contain ccusage-compatible entries for every classifier response. When `classifierIo` is off, `ccusage pi` still reports a separate `-pi-automode` session. In-memory logs use the same entry shape but live outside the normal Pi session tree.

See [Observability logging](observability-logging.md) for the log file location, entry schema, and the `classifierIo` privacy tradeoff. Run `/automode config` to see the resolved log file path.

## Permission patterns

Permission patterns use Pi tool names. Examples include `bash(...)`, `write(...)`, `edit(...)`, and `read(...)`. The parser accepts capitalized names such as `Bash(...)`. The documented form is lowercase because Pi tool names are lowercase.

`permissions.allow` is a deterministic allow tier. The default list is `[]`. A matching rule skips classifier review.

Use this tier for a narrow command such as `bash(git status*)`. You can also use it for a side-effect-free extension or MCP tool.

The matcher understands primary arguments for `bash`, the file tools, and `grep`. For file tools, it uses the resolved `input.path`. For `grep`, it uses `input.pattern`.

For `bash`, pi-automode parses `input.command` with `unbash`. Deny and ask rules inspect each executable command in the Bash syntax tree. This includes pipelines, logical chains, compound commands, substitutions, and literal scripts passed to `bash -c`, `sh -c`, or `eval`. The analysis also follows these literal shell scripts through transparent `command`, `exec`, and `env` dispatch.

The matcher normalizes whitespace between Bash tokens. It preserves whitespace and quoting inside each token. Thus, `bash(git push*)` matches `git  push origin main`. Quoted operators do not create extra commands.

A Bash allow decision requires coverage for each executable command. A multi-command pattern must match the same AST structure and operators. This structure check also applies to one command inside a group, wrapper, control structure, or background statement. Separate single-command patterns only cover top-level foreground chains and plain pipelines. Other supported structure requires one matching structural pattern. A multi-command pattern must match the same number of commands in the same order. Each pattern command must match its corresponding input command. One wildcard cannot hide an additional command or a different operator.

A redirect requires explicit coverage in the allow pattern. The redirect operator, file descriptor, variable name, and target pattern must match. Here-documents and dynamic redirect targets continue to the classifier. Parser errors, dynamic command names, and dynamic wrapper scripts cannot use `permissions.allow`.

Control nodes with unrepresented semantic values cannot use `permissions.allow`. This includes loops, functions, coprocesses, case statements, test commands, and arithmetic commands. These scripts continue to the classifier.

Pi-automode does not execute shell expansions. It cannot resolve aliases, variables, generated scripts, or dynamic `eval` input. These calls continue to the classifier unless a deterministic rule blocks them.

For other tools, the matcher uses the serialized input object. Use a bare tool name for an MCP or extension tool. For example, `example-extension-tool` matches every call to that tool.

The providing extension or MCP server defines the Pi tool name. Pi-automode does not need a predefined list.

A match skips only the classifier call. It cannot skip `permissions.deny`, deterministic hard-deny checks, `deniedPaths`, or protected-path controls. An accepted `permissions.ask` rule also takes precedence. After confirmation, the call continues through deterministic checks and then reaches the classifier. It cannot use `permissions.allow`, the inside-working-directory tier, or the read-only fast path.

Pi-automode reads `permissions.allow` only from global configuration, trusted `.pi/automode.local.json`, and `PI_AUTOMODE_SETTINGS_JSON`. Shared `.pi/automode.json` cannot add allow rules.

A pattern can contain at most 4,096 UTF-16 code units. Bash analysis accepts at most 1,048,576 UTF-16 code units. A longer Bash input is blocked before parsing.

For other allow matching, an input can contain at most 1,048,576 UTF-16 code units. A longer input returns no match. Deny and ask patterns match the same oversized input so that they fail closed.

`write` and `edit` calls whose resolved target is a protected path are never covered by `permissions.allow`. This includes protected targets reached through symlink aliases.

See [Permission recipes](permission-recipes.md) for narrow examples of Bash permissions, directory changes, command chains, redirects, and classifier guidance.

## Custom models (like OpenRouter's presets)

Pi-automode can only select models that Pi exposes through its model registry. Add unlisted models to `~/.pi/agent/models.json`.

For example, register an OpenRouter preset in the built-in `openrouter` provider:

```json
{
  "providers": {
    "openrouter": {
      "models": [
        {
          "id": "@preset/nvidia-nemotron-3-nano-30b-a3b-fast",
          "name": "NVIDIA: Nemotron 3 Nano 30B A3B Fast (Preset)",
          "reasoning": true,
          "input": ["text"],
          "contextWindow": 262144,
          "maxTokens": 235929,
          "cost": {
            "input": 0.05,
            "output": 0.2,
            "cacheRead": 0.03,
            "cacheWrite": 0
          }
        }
      ]
    }
  }
}
```

Restart Pi (or run `/reload`), then select the model with `/automode model openrouter/@preset/nvidia-nemotron-3-nano-30b-a3b-fast`.
