/**
 * Make untrusted text safe to *display*.
 *
 * Every finding WARDEN emits quotes something the other side chose: a tool name,
 * a server id, a catalog name, the `reason` string out of a signed threat feed.
 * Those strings are then printed to a terminal by the host CLI, rendered in a
 * dashboard, and stored in receipts. Interpolating them raw makes the firewall
 * itself the delivery vehicle for a terminal-control payload:
 *
 *     tool name: <ESC>[2K<ESC>[1A + "overwritten  ~/.ssh"
 *     finding:   Tool "<ESC>[2K<ESC>[1Aoverwritten  ~/.ssh": Server references ...
 *
 * Printed to a TTY that erases the current line and moves the cursor up, so the
 * BLOCK line WARDEN had just written is overwritten by text the attacker chose.
 * The same trick with zero-width and bidi characters makes a name read as
 * something it is not.
 *
 * So control characters and invisible characters are replaced with a VISIBLE
 * escape rather than stripped. Stripping would hide the very thing worth seeing:
 * a name with an embedded U+202E should look suspicious in the report, not clean.
 * Length is capped, because a finding message is a line of output, not somewhere
 * a hostile server gets to paste a megabyte.
 *
 * This is display hygiene, not a security boundary. `WardenFinding.tool` keeps
 * the RAW advertised name, because that is the key a host uses to filter its own
 * tool list and a sanitized key would match nothing.
 */

/** Zero-width and bidi controls: invisible, therefore always escaped. */
const INVISIBLE = "\\u200B-\\u200F\\u202A-\\u202E\\u2060\\u2066-\\u2069\\uFEFF";

/** C0 controls, DEL, and C1 - the terminal-control range. */
const CONTROL = "\\u0000-\\u001F\\u007F-\\u009F";

const UNSAFE = new RegExp(`[${CONTROL}${INVISIBLE}]`, "g");

/** Default cap for an interpolated fragment: long enough to be useful in a log line. */
export const DEFAULT_DISPLAY_MAX = 200;

/**
 * Render `value` as a single-line, control-character-free fragment, escaping what
 * cannot be shown and truncating past `max`.
 *
 * Exported so a host can apply it to the raw names it gets back in
 * `allowedTools` / `blockedTools`, which are deliberately not sanitized.
 */
export function displaySafe(value: unknown, max: number = DEFAULT_DISPLAY_MAX): string {
  const text = typeof value === "string" ? value : String(value ?? "");
  const escaped = text.replace(UNSAFE, (ch) => {
    const code = ch.codePointAt(0) ?? 0;
    return `\\u${code.toString(16).toUpperCase().padStart(4, "0")}`;
  });
  if (escaped.length <= max) return escaped;
  // Report the real length: "this name is 4 MB long" is itself worth knowing.
  return `${escaped.slice(0, max)}... [truncated, ${text.length} chars]`;
}
