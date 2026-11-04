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
  "cut",
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
  "nl",
  "nproc",
  "ps",
  "pwd",
  "rg",
  "sort",
  "stat",
  "tail",
  "tr",
  "true",
  "uname",
  "uniq",
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

// --- SQL -------------------------------------------------------------------

const SQL_CLIENTS = new Set(["psql", "mysql", "mariadb", "sqlite3", "sqlplus", "sqlcmd"]);
/** Clients whose read-only SQL can make the whole call read-only. sqlite3 is not one. */
const VERIFIABLE_SQL_CLIENTS = new Set(["psql", "mysql", "mariadb", "sqlplus", "sqlcmd"]);
/** Statements that start this way only read, unless a write word appears. */
const SQL_READ_STARTS = new Set(["SELECT", "WITH", "SHOW", "EXPLAIN", "TABLE", "VALUES"]);
/**
 * Words that make a statement write, execute, or change session state. Checked
 * anywhere in the statement, so `WITH … DELETE`, `SELECT … INTO`, `FOR UPDATE`,
 * and `EXPLAIN ANALYZE` are all unverified. Conservative: a column named like
 * one of these also makes the SQL unverified.
 */
const SQL_WRITE_WORDS =
  /\b(INSERT|UPDATE|DELETE|MERGE|UPSERT|REPLACE|DROP|TRUNCATE|ALTER|CREATE|GRANT|REVOKE|COPY|CALL|DO|VACUUM|REINDEX|CLUSTER|REFRESH|LOCK|ANALYZE|INTO|SET|RESET|COMMENT|IMPORT|LOAD|ATTACH|DETACH|PRAGMA|NOTIFY|PREPARE|EXECUTE|EXEC|KILL|SHUTDOWN|FLUSH|OUTFILE|DUMPFILE|NEXTVAL|WAITFOR)\b/i;
/** Functions with side effects or that read server files. */
const SQL_SIDE_EFFECT_FUNCTIONS =
  /\b(pg_terminate_backend|pg_cancel_backend|pg_reload_conf|pg_rotate_logfile|pg_switch_wal|pg_create_\w+|pg_drop_\w+|pg_advisory\w*|pg_sleep\w*|pg_read_file|pg_read_binary_file|pg_ls_dir|pg_stat_file|lo_import|lo_export|lo_unlink|set_config|nextval|setval|dblink\w*|load_file|sleep)\s*\(/i;
/**
 * Built-in functions and type names a read may call. Any other `name(` call,
 * and every qualified `schema.name(` or `package.name(` call, could be a
 * user-defined function that writes, so it leaves the SQL unverified.
 */
const SQL_READ_FUNCTIONS = new Set([
  // aggregates and window functions
  "count", "sum", "avg", "min", "max", "row_number", "rank", "dense_rank", "lag", "lead",
  "first_value", "last_value", "listagg", "string_agg", "array_agg", "json_agg", "jsonb_agg", "group_concat",
  // null handling and comparison
  "coalesce", "nullif", "nvl", "nvl2", "decode", "greatest", "least", "isnull", "iif",
  // strings
  "upper", "lower", "initcap", "length", "len", "char_length", "substr", "substring", "instr", "position",
  "strpos", "replace", "trim", "ltrim", "rtrim", "lpad", "rpad", "concat", "left", "right", "chr", "char",
  "ascii", "regexp_replace", "regexp_substr", "regexp_like", "regexp_count", "format",
  // numbers
  "round", "trunc", "floor", "ceil", "ceiling", "abs", "mod", "power", "sqrt", "sign",
  // conversion and dates
  "cast", "convert", "to_char", "to_date", "to_number", "to_timestamp", "date_trunc", "date_part", "extract",
  "now", "getdate", "sysdatetime", "dateadd", "datediff", "datepart", "age", "generate_series",
  // json
  "to_json", "to_jsonb", "json_build_object", "jsonb_build_object", "row_to_json",
  // catalog reads
  "object_id", "object_name", "schema_name", "db_name", "type_name", "col_length", "format_type",
  "obj_description", "col_description", "pg_get_viewdef", "pg_get_constraintdef", "pg_get_indexdef",
  "pg_get_triggerdef", "pg_get_functiondef", "pg_size_pretty", "pg_total_relation_size", "pg_relation_size",
  "pg_table_size", "current_setting", "version", "current_database", "current_schema",
  // type names with a size, as in `cast(x AS numeric(10, 2))`
  "numeric", "decimal", "number", "varchar", "varchar2", "nvarchar", "nchar", "timestamp", "float",
]);
/** Keywords that a parenthesis may follow without being a function call. */
const SQL_KEYWORDS_BEFORE_PAREN = new Set([
  "as", "in", "exists", "any", "all", "some", "over", "values", "from", "join", "where", "and", "or", "not",
  "on", "select", "when", "then", "else", "by", "using", "having", "within", "filter", "lateral", "between",
  "like", "is", "case", "distinct", "union", "intersect", "except", "minus", "with",
]);

/** True when every `name(` in the SQL is a known built-in or a keyword. */
function sqlCallsOnlyBuiltins(text: string): boolean {
  // A quoted name (`"f"(`, `[f](`, `` `f`( ``) is a call this check cannot name.
  // String cleanup has already reduced `"f"` to `""`.
  if (/["\]`]\s*\(/.test(text)) return false;
  for (const match of text.matchAll(/([A-Za-z_][\w$#]*(?:\s*\.\s*[A-Za-z_][\w$#]*)*)\s*\(/g)) {
    const name = match[1]!;
    if (name.includes(".")) return false;
    const lower = name.toLowerCase();
    if (!SQL_READ_FUNCTIONS.has(lower) && !SQL_KEYWORDS_BEFORE_PAREN.has(lower)) return false;
  }
  return true;
}

/**
 * SQL*Plus commands allowed at the start of a line, as [full name, shortest
 * abbreviation]. They only format output or describe objects. Every other
 * command, and any line that is neither one of these nor the start of a
 * SELECT or WITH statement, leaves the script unverified.
 */
const SQLPLUS_DISPLAY_COMMANDS: [string, string][] = [
  ["SET", "SET"], ["COLUMN", "COL"], ["PROMPT", "PRO"], ["TTITLE", "TTI"], ["BTITLE", "BTI"],
  ["BREAK", "BRE"], ["COMPUTE", "COMP"], ["CLEAR", "CL"], ["REMARK", "REM"], ["WHENEVER", "WHENEVER"],
  ["EXIT", "EXIT"], ["QUIT", "QUIT"], ["SHOW", "SHO"], ["DESCRIBE", "DESC"],
];
/**
 * SQL*Plus system variables a `SET` line may change, as [full name, shortest
 * abbreviation]. Variables that change how lines are split or run (CMDSEP,
 * SQLTERMINATOR, SQLBLANKLINES, BLOCKTERMINATOR, SQLPREFIX, ESCAPE, MARKUP,
 * ...) and SQL `SET ROLE`/`SET TRANSACTION` are not in the list.
 */
const SQLPLUS_SET_VARIABLES: [string, string][] = [
  ["PAGESIZE", "PAGES"], ["LINESIZE", "LIN"], ["LONG", "LONG"], ["LONGCHUNKSIZE", "LONGC"],
  ["TRIMSPOOL", "TRIMS"], ["TRIMOUT", "TRIM"], ["HEADING", "HEA"], ["FEEDBACK", "FEED"], ["ECHO", "ECHO"],
  ["VERIFY", "VER"], ["TAB", "TAB"], ["WRAP", "WRA"], ["NUMWIDTH", "NUMW"], ["COLSEP", "COLSEP"],
  ["NULL", "NULL"], ["TIMING", "TIMI"], ["TERMOUT", "TERM"], ["UNDERLINE", "UND"], ["NEWPAGE", "NEWP"],
  ["EMBEDDED", "EMB"], ["DEFINE", "DEF"],
];
/**
 * True when psql would substitute a variable: a run of colons of odd length
 * (`::` pairs are casts) followed by a name character, a quote, or `{`. Names
 * may start with a digit, so `tags[1:2]` counts.
 */
function psqlInterpolates(text: string): boolean {
  for (const match of text.matchAll(/:+/g)) {
    const after = text[match.index! + match[0].length] ?? "";
    if (match[0].length % 2 === 1 && /^[A-Za-z0-9_'"{\u0080-\uffff]$/.test(after)) return true;
  }
  return false;
}

/** mysql client commands, which the client runs when a line starts with one. */
const MYSQL_CLIENT_COMMANDS = new Set([
  "clear", "connect", "delimiter", "edit", "ego", "exit", "go", "help", "nopager", "notee", "nowarning", "pager",
  "print", "prompt", "quit", "rehash", "source", "status", "system", "tee", "use", "charset", "warnings",
  "resetconnection", "query_attributes", "ssl_session_data_print",
]);
/** T-SQL keywords that write, run code, or change server state. T-SQL needs no `;` between statements. */
const TSQL_WRITE_WORDS =
  /\b(RESTORE|BACKUP|DENY|DISABLE|ENABLE|DBCC|RECONFIGURE|CHECKPOINT|BEGIN|COMMIT|ROLLBACK|SAVE|USE|BULK|RAISERROR|THROW|DECLARE|GOTO|WHILE|IF|RETURN|SETUSER|REVERT|OPENROWSET|OPENQUERY|OPENDATASOURCE|OPENXML|SEND|RECEIVE)\b/i;

/** The full command name when `word` is it or an allowed abbreviation of it. */
function sqlplusAbbreviation(word: string, table: [string, string][]): string | undefined {
  const upper = word.toUpperCase();
  return table.find(([full, shortest]) => upper.length >= shortest.length && full.startsWith(upper))?.[0];
}

/** True when a SQL*Plus `SET` line only changes allowed display variables. */
function sqlplusSetIsSafe(line: string): boolean {
  return line.trim().split(/\s+/).slice(1).every((token) =>
    /^(ON|OFF|NONE|\d+|'')$/i.test(token) || sqlplusAbbreviation(token, SQLPLUS_SET_VARIABLES) !== undefined
  );
}

/**
 * Replace string literals, quoted identifiers, and comments with placeholders,
 * scanning left to right as the client does. Returns undefined when the text
 * cannot be read reliably: an unterminated literal or comment, a backslash in
 * a quoted literal (MySQL and PostgreSQL E'' strings use it as an escape), a
 * nested block comment (PostgreSQL and SQL Server nest them), a MySQL block
 * comment not followed by whitespace (versioned, MariaDB, and hint comments
 * run), Oracle `q'...'` literals, any comment in sqlplus (it finds statement
 * ends on the raw line), or, for the line-oriented sqlplus and sqlcmd, a
 * literal or comment that spans a line. MySQL `#` comments are recognized.
 */
function stripSqlLiterals(script: string, client: string): string | undefined {
  if (/\/\*!/.test(script)) return undefined;
  if (client === "sqlplus" && /(^|[^\w$#])[nN]?[qQ]'/.test(script)) return undefined;
  const sqlplus = client === "sqlplus";
  const lineOriented = sqlplus || client === "sqlcmd";
  const mysql = client === "mysql" || client === "mariadb";
  let out = "";
  let index = 0;
  while (index < script.length) {
    const char = script[index]!;
    const next = script[index + 1];
    // The mysql server reads `--` plus whitespace or a control character as a
    // comment, but the client, which splits statements and runs backslash
    // commands, only `--` plus whitespace. Where they disagree, fail closed.
    const third = script[index + 2] ?? "";
    if (mysql && char === "-" && next === "-" && /^[\x00-\x08\x0e-\x1f\x7f]$/.test(third)) return undefined;
    const lineComment = (char === "-" && next === "-" && (!mysql || /^[ \t\n\v\f\r]?$/.test(third))) ||
      (mysql && char === "#");
    // SQL*Plus finds statement ends and commands on the raw line, comments and all.
    if (sqlplus && (lineComment || (char === "/" && next === "*"))) return undefined;
    if (lineComment) {
      const end = script.indexOf("\n", index);
      out += " ";
      index = end < 0 ? script.length : end;
      continue;
    }
    if (char === "/" && next === "*") {
      // MySQL and MariaDB run hint and versioned comments (`/*!`, `/*M!`, `/*+`).
      if (mysql && !/^[\s*]$/.test(script[index + 2] ?? "")) return undefined;
      const end = script.indexOf("*/", index + 2);
      if (end < 0) return undefined;
      const body = script.slice(index + 2, end);
      // PostgreSQL and SQL Server nest block comments; the first `*/` may not end
      // this one. Include the `*` of that `*/`, so an overlapping `/*/` counts.
      if (script.slice(index + 2, end + 1).includes("/*")) return undefined;
      if (lineOriented && body.includes("\n")) return undefined;
      out += " ";
      index = end + 2;
      continue;
    }
    const close = char === "'" || char === '"' || char === "`"
      ? char
      : char === "[" && client === "sqlcmd" ? "]" : undefined;
    if (close === undefined) {
      out += char;
      index += 1;
      continue;
    }
    let search = index + 1;
    for (;;) {
      const end = script.indexOf(close, search);
      if (end < 0) return undefined;
      // A doubled closing character is an escaped one.
      if (script[end + 1] === close) {
        search = end + 2;
        continue;
      }
      const body = script.slice(index + 1, end);
      if ((char === "'" || char === '"') && body.includes("\\")) return undefined;
      if (lineOriented && body.includes("\n")) return undefined;
      out += char === "'" ? "''" : '""';
      index = end + 1;
      break;
    }
  }
  return out;
}
/** psql meta-commands that only describe or format output. */
const PSQL_READ_META = new Set([
  "\\d", "\\dt", "\\dt+", "\\d+", "\\di", "\\dv", "\\dn", "\\du", "\\df", "\\l", "\\l+",
  "\\echo", "\\x", "\\pset", "\\timing", "\\conninfo", "\\q", "\\t", "\\a", "\\encoding",
]);
/** sqlite3 dot-commands that only describe or format output. */
const SQLITE_READ_DOT = new Set([".tables", ".schema", ".indexes", ".headers", ".mode", ".width"]);

type SqlText = { text?: string; unknown?: string };

/**
 * The statement kinds in a SQL script and whether all of them only read.
 * String literals, quoted identifiers, and comments are removed first, so a
 * write word in data does not count. Dollar-quoted bodies are not parsed and
 * make the script unverified.
 */
function classifySql(script: string, client = "psql"): { statements: string[]; readOnly: boolean } {
  const statements: string[] = [];
  let readOnly = true;
  const kinds = (kind: string) => {
    if (!statements.includes(kind)) statements.push(kind);
  };
  if (/\$[A-Za-z_]*\$/.test(script)) readOnly = false;
  const sqlplus = client === "sqlplus";
  const sqlcmd = client === "sqlcmd";
  // Substitution variables (`&name`, `$(name)`) change the SQL after this
  // check, inside string literals too.
  if (sqlplus && /&/.test(script)) readOnly = false;
  if (sqlcmd && /\$\(/.test(script)) readOnly = false;
  const cleaned = stripSqlLiterals(script, client);
  if (cleaned === undefined) return { statements: ["(unreadable)"], readOnly: false };
  const sqlLines: string[] = [];
  if (sqlplus) {
    // SQL*Plus reads a script line by line. A line that starts a statement
    // must be SELECT or WITH; the statement continues until a line ending in
    // `;`, a `/` line, a lone `.`, or a blank line. Outside a statement only
    // the display commands are allowed. `/` reruns the buffer, which holds a
    // statement this check has already read.
    let inStatement = false;
    for (const line of cleaned.split("\n")) {
      const trimmed = line.trim();
      // SQLPREFIX (`#`) runs a SQL*Plus command even in the middle of a statement.
      if (trimmed.startsWith("#")) {
        kinds("#");
        readOnly = false;
        continue;
      }
      if (inStatement) {
        if (trimmed === "" || trimmed === "." || trimmed === "/") {
          sqlLines.push(";");
          inStatement = false;
          continue;
        }
        sqlLines.push(line);
        if (trimmed.endsWith(";")) inStatement = false;
        continue;
      }
      if (trimmed === "" || trimmed === "/") continue;
      const word = /^([A-Za-z]+)(?![\w$#.])/.exec(trimmed)?.[1];
      const upper = word?.toUpperCase();
      if (upper === "SELECT" || upper === "WITH") {
        sqlLines.push(line);
        inStatement = !trimmed.endsWith(";");
        continue;
      }
      const command = word === undefined ? undefined : sqlplusAbbreviation(word, SQLPLUS_DISPLAY_COMMANDS);
      kinds(upper ?? trimmed.split(/\s+/)[0]!);
      if (command === undefined || (command === "SET" && !sqlplusSetIsSafe(trimmed))) readOnly = false;
    }
  } else {
    for (const line of cleaned.split("\n")) {
      const trimmed = line.trim();
      if (sqlcmd) {
        if (/^go(\s+\d+)?$/i.test(trimmed)) {
          sqlLines.push(";");
          continue;
        }
        // `:r`, `:out`, `:!!`, `!!` and other sqlcmd commands read files, write files, or run shell commands.
        if (trimmed.startsWith(":") || trimmed.startsWith("!!") || /^(ED|EXIT|QUIT|RESET)(?![\w$#@])/i.test(trimmed)) {
          kinds(trimmed.split(/[\s(]+/)[0]!);
          readOnly = false;
          continue;
        }
        sqlLines.push(line);
        continue;
      }
      if (client === "psql" && trimmed.startsWith("\\")) {
        const meta = trimmed.split(/\s+/)[0]!;
        kinds(meta);
        if (!PSQL_READ_META.has(meta)) readOnly = false;
        continue;
      }
      // mysql client commands such as `system`, `pager`, `source`, and `tee` run at the start of any line.
      const mysqlCommand = /^([A-Za-z_]+)/.exec(trimmed)?.[1]?.toLowerCase();
      if ((client === "mysql" || client === "mariadb") && mysqlCommand && MYSQL_CLIENT_COMMANDS.has(mysqlCommand)) {
        kinds(mysqlCommand.toUpperCase());
        readOnly = false;
        continue;
      }
      if (client === "sqlite3" && trimmed.startsWith(".")) {
        const dot = trimmed.split(/\s+/)[0]!;
        kinds(dot);
        if (!SQLITE_READ_DOT.has(dot)) readOnly = false;
        continue;
      }
      // psql and mysql run a backslash command anywhere outside literals (`SELECT 1 \g file`).
      if (line.includes("\\")) {
        kinds(line.slice(line.indexOf("\\")).split(/\s+/)[0]!);
        readOnly = false;
      }
      sqlLines.push(line);
    }
  }
  for (const statement of sqlLines.join("\n").split(";")) {
    const text = statement.trim();
    if (text === "") continue;
    const first = text.split(/[\s(]+/)[0]!.toUpperCase();
    kinds(first);
    // SQL Server's row-count message switch changes no data.
    if (sqlcmd && /^SET\s+NOCOUNT\s+(ON|OFF)$/i.test(text)) continue;
    if (
      !SQL_READ_STARTS.has(first) ||
      // Oracle has no read-only EXPLAIN, SHOW, TABLE, or VALUES statement; EXPLAIN PLAN writes PLAN_TABLE.
      (sqlplus && first !== "SELECT" && first !== "WITH") ||
      SQL_WRITE_WORDS.test(text) ||
      (sqlcmd && TSQL_WRITE_WORDS.test(text)) ||
      // psql substitutes `:name`, `:'name'`, and `:"name"` variables, which `-v` can set to any SQL.
      (client === "psql" && psqlInterpolates(text)) ||
      /\bNEXT\s+VALUE\s+FOR\b/i.test(text) ||
      SQL_SIDE_EFFECT_FUNCTIONS.test(text) ||
      !sqlCallsOnlyBuiltins(text)
    ) {
      readOnly = false;
    }
  }
  if (statements.length === 0) readOnly = false;
  return { statements, readOnly };
}

/** SQL passed to a client on its command line. */
function sqlFromClientArgs(client: string, args: string[]): SqlText[] {
  const texts: SqlText[] = [];
  const valueOf = (index: number, long: string) => {
    const arg = args[index]!;
    return arg.startsWith(`${long}=`) ? arg.slice(long.length + 1) : args[index + 1];
  };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]!;
    if (client === "psql" && (arg === "-c" || arg === "--command" || arg.startsWith("--command="))) {
      texts.push({ text: valueOf(index, "--command") ?? "" });
    } else if (
      client === "psql" &&
      (arg.startsWith("-v") || arg === "--set" || arg.startsWith("--set=") || arg === "--variable" ||
        arg.startsWith("--variable="))
    ) {
      // psql substitutes variables set here into the SQL.
      texts.push({ unknown: "(variables)" });
    } else if (client === "psql" && (arg === "-f" || arg === "--file" || arg.startsWith("--file="))) {
      texts.push({ unknown: "(file)" });
    } else if (
      (client === "mysql" || client === "mariadb") &&
      (arg === "-e" || arg === "--execute" || arg.startsWith("--execute="))
    ) {
      texts.push({ text: valueOf(index, "--execute") ?? "" });
    } else if (client === "sqlplus" && arg.startsWith("@")) {
      // `sqlplus LOGON @script` runs a script file.
      texts.push({ unknown: "(file)" });
    } else if (client === "sqlcmd" && (arg === "-Q" || arg === "-q")) {
      texts.push({ text: args[index + 1] ?? "" });
    } else if (client === "sqlcmd" && arg === "-i") {
      texts.push({ unknown: "(file)" });
    }
  }
  if (client === "sqlite3") {
    const positional = args.filter((arg) => !arg.startsWith("-"));
    if (positional.length > 1) texts.push({ text: positional.slice(1).join(" ") });
  }
  return texts;
}

/** SQL fed on stdin by a heredoc or here-string. */
function sqlFromRedirects(command: BashCommandAnalysis): SqlText[] {
  return command.redirects.flatMap((redirect): SqlText[] => {
    if (redirect.heredoc) {
      const body = redirect.heredocContent ?? "";
      // An unquoted heredoc expands $(...) and backticks before the client runs.
      if (!redirect.heredocQuoted && /\$\(|`|\$\{?[A-Za-z_]/.test(body)) {
        return [{ unknown: "(expanded heredoc)" }];
      }
      return [{ text: body }];
    }
    if (redirect.operator === "<<<") {
      return redirect.targetDynamic ? [{ unknown: "(expanded here-string)" }] : [{ text: redirect.target ?? "" }];
    }
    if (redirect.operator === "<") return [{ unknown: "(file)" }];
    return [];
  });
}

/** Commands that run another command given as their arguments. */
const COMMAND_WRAPPERS = new Set(["sudo", "doas", "docker", "podman", "kubectl", "env", "nice", "nohup", "time"]);

/** The database client a command runs, directly or behind a wrapper such as sudo or docker exec. */
function sqlClient(command: BashCommandAnalysis): { client: string; args: string[] } | undefined {
  const name = command.effectiveCommand.name;
  const args = command.effectiveCommand.args;
  if (name && SQL_CLIENTS.has(name)) return { client: name, args };
  // `which psql` names a client without running it.
  if (!name || !COMMAND_WRAPPERS.has(name)) return undefined;
  const index = args.findIndex((arg) => SQL_CLIENTS.has(arg.split("/").pop() ?? ""));
  if (index < 0) return undefined;
  return { client: args[index]!.split("/").pop()!, args: args.slice(index + 1) };
}

/** Client options that write local files. */
const SQL_CLIENT_WRITE_OPTIONS = /^(-o|--output|-L|--log-file|--tee|-f|--file)(=|$)/;

/**
 * Skip `[sudo|doas [-n] [-u U] [-g G]] [docker|podman exec OPTS CONTAINER |
 * kubectl exec OPTS POD [--]]` and return the index of the database client, or
 * -1 when any word falls outside that exact shape.
 */
function sqlClientIndex(words: string[]): number {
  let index = 0;
  const take = (flags: Set<string>, valueFlags: Set<string>): boolean => {
    while (index < words.length && words[index]!.startsWith("-")) {
      const word = words[index]!;
      if (word === "--") return true;
      const bare = word.split("=")[0]!;
      if (flags.has(word)) index += 1;
      else if (valueFlags.has(bare)) index += word.includes("=") ? 1 : 2;
      else return false;
    }
    return true;
  };
  if (words[index] === "sudo" || words[index] === "doas") {
    index += 1;
    if (!take(new Set(["-n"]), new Set(["-u", "-g"]))) return -1;
  }
  const tool = words[index];
  if (tool === "docker" || tool === "podman") {
    if (words[index + 1] !== "exec") return -1;
    index += 2;
    if (
      !take(
        new Set(["-i", "-t", "-it", "-ti", "--interactive", "--tty"]),
        new Set(["-u", "--user", "-e", "--env", "-w", "--workdir"]),
      )
    ) return -1;
    index += 1; // container
  } else if (tool === "kubectl") {
    if (words[index + 1] !== "exec") return -1;
    index += 2;
    if (
      !take(
        new Set(["-i", "-t", "-it", "-ti", "--stdin", "--tty"]),
        new Set(["-n", "--namespace", "-c", "--container", "--context"]),
      )
    ) return -1;
    index += 1; // pod
    if (words[index] === "--") index += 1;
  }
  const client = words[index]?.split("/").pop();
  return client !== undefined && VERIFIABLE_SQL_CLIENTS.has(client) ? index : -1;
}

/**
 * True when a command is exactly a database client call, possibly behind the
 * wrappers `sqlClientIndex` accepts, with no file-writing client options and
 * with SQL that `classifySql` verifies as read-only. sqlite3 is never claimed:
 * opening a missing database file creates it.
 */
function sqlCallIsReadOnly(command: BashCommandAnalysis, stdin: SqlText[]): boolean {
  if (command.dynamic) return false;
  const name = command.effectiveCommand.name;
  if (!name) return false;
  const words = [name, ...command.effectiveCommand.args];
  const index = sqlClientIndex(words);
  if (index < 0) return false;
  const client = words[index]!.split("/").pop()!;
  const clientArgs = words.slice(index + 1);
  if (clientArgs.some((arg) => SQL_CLIENT_WRITE_OPTIONS.test(arg))) return false;
  const texts = [
    ...sqlFromClientArgs(client, clientArgs),
    ...sqlFromRedirects(command),
    ...stdin,
  ];
  if (texts.length === 0) return false;
  return texts.every((text) => text.unknown === undefined && classifySql(text.text ?? "", client).readOnly);
}

function sqlFact(client: string, texts: SqlText[], dynamic: boolean): string {
  const statements: string[] = [];
  let readOnly = !dynamic && texts.length > 0;
  for (const text of texts) {
    if (text.unknown !== undefined) {
      statements.push(text.unknown);
      readOnly = false;
      continue;
    }
    const result = classifySql(text.text ?? "", client);
    for (const statement of result.statements) {
      if (!statements.includes(statement)) statements.push(statement);
    }
    readOnly &&= result.readOnly;
  }
  return `sql: client=${client} statements=${statements.join(", ") || "(none)"} read_only=${
    readOnly ? "true" : "unverified"
  }`;
}

/** One `sql:` fact per database client call, local or behind ssh. */
function sqlFacts(commands: BashCommandAnalysis[]): string[] {
  const facts: string[] = [];
  for (const command of commands) {
    const unwrapped = unwrapTimeout(command.effectiveCommand.name, command.effectiveCommand.args);
    if (unwrapped.name === "ssh") {
      const { remoteSource } = parseSshArgs(unwrapped.args);
      if (remoteSource.trim() === "") continue;
      // A local heredoc on ssh is the remote command's stdin.
      const stdin = sqlFromRedirects(command);
      for (const remote of analyzeBash(remoteSource).commands) {
        const found = sqlClient(remote);
        if (!found) continue;
        facts.push(sqlFact(
          found.client,
          [...sqlFromClientArgs(found.client, found.args), ...sqlFromRedirects(remote), ...stdin],
          command.dynamic || remote.dynamic,
        ));
      }
      continue;
    }
    const found = sqlClient(command);
    if (!found) continue;
    facts.push(sqlFact(
      found.client,
      [...sqlFromClientArgs(found.client, found.args), ...sqlFromRedirects(command)],
      command.dynamic,
    ));
  }
  return facts;
}

type RemoteShell = {
  host?: string;
  commands: string[];
  readOnly: boolean;
};

function hasUnsafeArgument(name: string, args: string[]): boolean {
  const unsafe = UNSAFE_ARGUMENTS[name];
  return unsafe ? args.some(unsafe) : false;
}

export function isWriteRedirect(
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
export function unwrapTimeout(name: string | undefined, args: string[]): {
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
export type SshInvocation = {
  /** The option words before the host, as written. */
  options: string[];
  /** The target host, lowercased, without `user@`. */
  host?: string;
  /** The remote command, joined the way ssh joins it. */
  remoteSource: string;
  /** False when any option is outside the safe set. */
  optionsSafe: boolean;
};

/** Split `ssh [options] HOST COMMAND...` arguments. */
export function parseSshArgs(args: string[]): SshInvocation {
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
  const host = args[index]?.split("@").pop()?.toLowerCase();
  return {
    options: args.slice(0, index),
    ...(host ? { host } : {}),
    remoteSource: args.slice(index + 1).join(" "),
    optionsSafe,
  };
}

/**
 * `stdin` is SQL fed to the ssh command itself (a local heredoc), which the
 * remote command reads.
 */
function analyzeSsh(args: string[], stdin: SqlText[] = []): RemoteShell {
  const { host, remoteSource, optionsSafe } = parseSshArgs(args);
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
    remote.commands.every((command) => commandIsReadOnly(command, false, stdin));
  return { host, commands, readOnly };
}

/** A sed line address: a number or `$`, optionally a range. */
const SED_ADDRESS = String.raw`(?:\d+|\$)(?:,(?:\d+|\$))?`;
/** `ADDRp`, or `s` with any delimiter and only the g, p, i, I, and number flags. */
const SED_SAFE_COMMAND = new RegExp(
  String.raw`^\s*(?:(?:${SED_ADDRESS})?p|(?:${SED_ADDRESS})?s(.)(?:(?!\1)[^\\]|\\.)*\1(?:(?!\1)[^\\]|\\.)*\1[gpiI0-9]*)\s*$`,
);

/**
 * True when sed only prints: no in-place edit or script file, and every command
 * is a substitution or a print. The `w`, `W`, `e`, and `r` commands and flags
 * write files or run programs, so they never match.
 */
function sedIsReadOnly(args: string[]): boolean {
  const scripts: string[] = [];
  let sawScript = false;
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i]!;
    if (arg === "-n" || arg === "-E" || arg === "-r" || arg === "--quiet" || arg === "--silent") continue;
    if (arg === "-e") {
      const script = args[i + 1];
      if (script === undefined) return false;
      scripts.push(script);
      sawScript = true;
      i += 1;
      continue;
    }
    if (arg.startsWith("-")) return false;
    if (!sawScript) {
      scripts.push(arg);
      sawScript = true;
    }
  }
  return scripts.length > 0 &&
    scripts.every((script) => script.split(/[;\n]/).every((command) => SED_SAFE_COMMAND.test(command)));
}

/** git subcommands that only read the repository. */
const GIT_READ_SUBCOMMANDS = new Set([
  "blame", "branch", "cat-file", "describe", "diff", "log", "ls-files", "merge-base",
  "rev-parse", "shortlog", "show", "status",
]);
/** `git branch` flags that only list; anything else may create, rename, or delete. */
const GIT_BRANCH_LIST_FLAGS = new Set(["-a", "-r", "-v", "-vv", "--all", "--list", "--remotes", "--show-current", "--verbose"]);

/**
 * True for `git [-C DIR] SUBCOMMAND ...` with a read-only subcommand. Other
 * global options are refused: `-c` can set a pager or alias that runs a
 * command, and `--git-dir` reaches another repository. Options that write a
 * file or run a program are refused too.
 */
function gitIsReadOnly(args: string[]): boolean {
  let rest = args;
  if (rest[0] === "-C") {
    if (rest.length < 2) return false;
    rest = rest.slice(2);
  }
  const [subcommand, ...options] = rest;
  if (!subcommand || !GIT_READ_SUBCOMMANDS.has(subcommand)) return false;
  if (options.some((arg) => /^--(output|ext-diff|exec|textconv|open-files-in-pager)\b/.test(arg) || arg === "-O")) {
    return false;
  }
  if (subcommand === "branch") return options.every((arg) => GIT_BRANCH_LIST_FLAGS.has(arg));
  return true;
}

/** Modules a verified python script may import. */
const PYTHON_IMPORTS = new Set(["json", "os", "re", "sys", "textwrap", "urllib.request"]);
/** Module functions a verified python script may call. */
const PYTHON_MODULE_CALLS = new Set([
  "json.dumps", "json.load", "json.loads", "os.environ.get", "os.getenv",
  "re.compile", "re.findall", "re.match", "re.search", "re.sub", "sys.exit",
  "textwrap.indent", "textwrap.shorten", "urllib.request.Request", "urllib.request.urlopen",
]);
/** Builtins a verified python script may call. `open`, `exec`, and `eval` are not here. */
const PYTHON_BUILTINS = new Set([
  "all", "any", "bool", "dict", "enumerate", "filter", "float", "int", "isinstance", "len",
  "list", "map", "max", "min", "print", "range", "repr", "reversed", "round", "set", "sorted",
  "str", "sum", "tuple", "zip",
]);
/** Methods of strings, lists, dicts, and regex matches, which only return values. */
const PYTHON_METHODS = new Set([
  "count", "decode", "encode", "endswith", "find", "findall", "format", "get", "group", "items",
  "join", "keys", "lower", "lstrip", "match", "replace", "rstrip", "search", "split",
  "splitlines", "startswith", "strip", "upper", "values",
]);
/** Keywords that may precede a parenthesis without being a call. */
const PYTHON_KEYWORDS = new Set([
  "and", "elif", "else", "for", "if", "in", "is", "not", "or", "return", "while", "with",
]);
const PYTHON_INTERPRETER = /^python(3(\.\d+)?)?$/;

/** The top-level arguments of the call whose `(` is at `open`, or undefined if unbalanced. */
function pythonCallArgs(source: string, open: number): string[] | undefined {
  const args: string[] = [];
  let depth = 0;
  let quote: string | undefined;
  let start = open + 1;
  for (let i = open; i < source.length; i += 1) {
    const char = source[i]!;
    if (quote) {
      if (char === "\\") i += 1;
      else if (char === quote) quote = undefined;
      continue;
    }
    if (char === "'" || char === '"') quote = char;
    else if ("([{".includes(char)) depth += 1;
    else if (")]}".includes(char)) {
      depth -= 1;
      if (depth === 0) {
        args.push(source.slice(start, i).trim());
        return args.filter((arg) => arg !== "");
      }
    } else if (char === "," && depth === 1) {
      args.push(source.slice(start, i).trim());
      start = i + 1;
    }
  }
  return undefined;
}

/**
 * True when a python script can only read: it imports and calls nothing off
 * the allowlists, and every HTTP call is a `urllib` GET with no body. The scan
 * covers string literals too, so an f-string expression is checked like code.
 */
function pythonScriptReadOnly(script: string): boolean {
  // Dunder access, chained calls, `file=`, and decorators reach code the call scan cannot name.
  if (/__|[)\]]\s*\(|\bfile\s*=|^\s*@|\bdata\s*=|\bmethod\s*=/m.test(script)) return false;
  const importStatements = script.match(/^[ \t]*import[ \t]+[^\n]+$/gm) ?? [];
  if ((script.match(/\bimport\b/g) ?? []).length !== importStatements.length) return false;
  for (const statement of importStatements) {
    for (const part of statement.replace(/^\s*import\s+/, "").split(",")) {
      const name = part.trim().split(/\s+as\s+/)[0] ?? "";
      if (!PYTHON_IMPORTS.has(name)) return false;
    }
  }
  for (const match of script.matchAll(/(\.?[A-Za-z_][\w.]*)\s*\(/g)) {
    // A leading dot is a method on an expression, such as `(text or '').splitlines()`.
    const name = match[1]!.startsWith(".") ? `(value)${match[1]}` : match[1]!;
    const segments = name.split(".");
    const allowed = segments.length === 1
      ? PYTHON_BUILTINS.has(name) || PYTHON_KEYWORDS.has(name)
      : PYTHON_MODULE_CALLS.has(name) ||
        (!PYTHON_IMPORTS.has(segments[0]!) && segments[0] !== "urllib" &&
          PYTHON_METHODS.has(segments[segments.length - 1]!));
    if (!allowed) return false;
    // A second positional argument is a request body; only headers and a timeout may follow.
    const keywords = name === "urllib.request.Request"
      ? ["headers"]
      : name === "urllib.request.urlopen"
      ? ["timeout"]
      : undefined;
    if (keywords) {
      const args = pythonCallArgs(script, match.index! + match[0].length - 1);
      if (!args || args.length === 0) return false;
      for (const arg of args.slice(1)) {
        const keyword = /^(\w+)\s*=/.exec(arg)?.[1];
        if (!keyword || !keywords.includes(keyword)) return false;
      }
    }
  }
  return true;
}

/** The script a `python3 -` call reads from a quoted heredoc, or undefined for any other form. */
function pythonStdinScript(command: BashCommandAnalysis): string | undefined {
  const { name, args } = unwrapTimeout(command.effectiveCommand.name, command.effectiveCommand.args);
  if (!name || !PYTHON_INTERPRETER.test(name)) return undefined;
  if (!(args.length === 0 || (args.length === 1 && args[0] === "-"))) return undefined;
  const heredocs = command.redirects.filter((redirect) => redirect.heredoc);
  if (heredocs.length !== 1 || command.redirects.length !== 1) return undefined;
  // An unquoted heredoc lets the shell rewrite the script before python sees it.
  if (!heredocs[0]!.heredocQuoted) return undefined;
  return heredocs[0]!.heredocContent ?? "";
}

function pythonHttpFacts(commands: BashCommandAnalysis[]): string[] {
  return commands.flatMap((command) => {
    const script = pythonStdinScript(command);
    if (script === undefined || !/\burlopen\s*\(/.test(script)) return [];
    const readOnly = !command.dynamic && pythonScriptReadOnly(script);
    const hosts = [...new Set([...script.matchAll(/https?:\/\/([A-Za-z0-9.-]+)/g)].map((m) => m[1]!))];
    return [
      `python_http: requests=${readOnly ? "GET only" : "unverified"} hosts=${
        hosts.join(",") || "(unknown)"
      } read_only=${readOnly ? "true" : "unverified"}`,
    ];
  });
}

export function commandIsReadOnly(
  command: BashCommandAnalysis,
  allowRemoteShell: boolean,
  stdin: SqlText[] = [],
): boolean {
  const script = pythonStdinScript(command);
  if (script !== undefined) return !command.dynamic && pythonScriptReadOnly(script);
  if (command.dynamic || command.effectiveCommand.unresolvedTransparentDispatch) {
    return false;
  }
  const { name, args } = unwrapTimeout(
    command.effectiveCommand.name,
    command.effectiveCommand.args,
  );
  if (!name) return false;
  if (name === "ssh") {
    return allowRemoteShell && analyzeSsh(args, sqlFromRedirects(command)).readOnly;
  }
  if (sqlCallIsReadOnly(command, stdin)) return true;
  if (name === "curl") return curlIsReadOnly(args);
  if (name === "git") return gitIsReadOnly(args);
  if (name === "sed") return sedIsReadOnly(args);
  return READ_ONLY_COMMANDS.has(name) && !hasUnsafeArgument(name, args);
}

/** Words that name a secret, as a search term, key, or file. */
const CREDENTIAL_TERMS =
  /master[_-]?key|api[_-]?key|secret|passw|passphrase|credential|private[_-]?key|\btoken\b|_token\b|\bauth\.json\b|\.env\b|id_rsa|id_ed25519|\.pem\b|\.netrc\b/i;

/**
 * True when a serialized action names a credential. Environment references
 * (`$VAR`, `${VAR}`, `os.environ['VAR']`, `os.getenv('VAR')`) and auth header
 * names only pass a secret along, so they are removed first. Used to keep
 * reads that go looking for a secret on the normal intent threshold.
 */
export function mentionsCredentials(action: string): boolean {
  let text: string;
  try {
    const parsed = JSON.parse(action) as ActionShape;
    text = typeof parsed?.input?.command === "string" ? parsed.input.command : action;
  } catch {
    text = action;
  }
  const stripped = text
    .replace(/\$\{?[A-Za-z_][A-Za-z0-9_]*\}?/g, "")
    .replace(/os\.environ(\.get)?\s*[[(]\s*['"][^'"]*['"]\s*[\])]/g, "")
    .replace(/os\.getenv\s*\(\s*['"][^'"]*['"]/g, "")
    .replace(/['"]?\b(PRIVATE-TOKEN|JOB-TOKEN|Authorization|X-[A-Za-z-]*Token)\b['"]?\s*:\s*(Bearer\b)?/gi, "");
  return CREDENTIAL_TERMS.test(stripped);
}

/**
 * Describe a serialized classifier action as `key: value` lines, or return ""
 * when the action is not a parseable `bash` call. See the module comment for
 * what `read_only` means.
 */
export function describeActionFacts(
  action: string,
  trustedHosts: string[],
  extraLines: string[] = [],
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
    const remote = analyzeSsh(unwrapped.args, sqlFromRedirects(bashCommand));
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
  lines.push(...sqlFacts(analysis.commands));
  lines.push(...pythonHttpFacts(analysis.commands));
  lines.push(...extraLines);
  const readOnly = writes.length === 0 &&
    analysis.commands.length > 0 &&
    analysis.commands.every((c) => commandIsReadOnly(c, true));
  lines.push(`read_only: ${readOnly ? "true" : "unverified"}`);
  return lines.map(escapeLineBreaks).join("\n");
}

/**
 * Escape control characters and Unicode line separators. Fact values come from
 * command text, and a newline in a path or host would otherwise start a forged
 * line such as `read_only: true`.
 */
function escapeLineBreaks(line: string): string {
  return line.replace(/[\u0000-\u001f\u007f\u0085\u2028\u2029]/g, (char) => {
    if (char === "\n") return "\\n";
    if (char === "\r") return "\\r";
    if (char === "\t") return "\\t";
    return `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`;
  });
}
