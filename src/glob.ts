/**
 * `*`-glob matching, without a regular expression.
 *
 * WARDEN matches two kinds of glob against attacker-controlled text: threat-feed
 * patterns (a signed publisher chooses the pattern, a hostile server chooses the
 * haystack) and `policy.sensitiveToolPatterns` (the operator chooses the pattern,
 * the server chooses the tool name). Both used to compile `*` into `.*` and run a
 * regex, which is a denial of service:
 *
 *     pattern  "*a*a*a*a*a*a*a*a*a*a*a*a*a*a*zzz"   (32 characters)
 *     haystack "aaaa..."                            (220 characters)
 *     -> 112 SECONDS inside one RegExp.test
 *
 * The engine has to try every way of distributing the wildcards over the haystack
 * before it can conclude "no match" - exponential in the number of `*`. That
 * mattered more than an ordinary performance bug: the threat feed's whole trust
 * story is that a compromised publisher can only ever ADD protection, never
 * remove it, and a record that hangs `vet()` forever removes all of it. The same
 * shape let a hostile server freeze the agent inspecting it, by advertising a
 * long enough tool name against an operator's own `*a*b*c*` pattern.
 *
 * The two-pointer algorithm below is the standard wildcard matcher: it walks the
 * haystack once and remembers only the most recent `*` to fall back to, so the
 * work is bounded by `pattern.length x value.length` with no backtracking tree to
 * explode. The same 32/220 case returns in microseconds.
 *
 * Semantics, matching what the regex did: `*` matches any run of zero or more
 * UTF-16 code units (including newlines - the old regex needed the `s` flag for
 * that), every other character is literal, and the match is anchored at both
 * ends. Case folding is the caller's job: both sides arrive already lowercased.
 */
export function wildcardMatch(pattern: string, value: string): boolean {
  const STAR = 0x2a;
  let p = 0;
  let v = 0;
  let star = -1;
  let resume = 0;

  while (v < value.length) {
    if (p < pattern.length && pattern.charCodeAt(p) === value.charCodeAt(v)) {
      p++;
      v++;
    } else if (p < pattern.length && pattern.charCodeAt(p) === STAR) {
      // Remember this wildcard and let it match nothing for now.
      star = p++;
      resume = v;
    } else if (star >= 0) {
      // Backtrack: hand one more character to the last wildcard. There is only
      // ever one fallback point, which is what keeps this linear-bounded.
      p = star + 1;
      v = ++resume;
    } else {
      return false;
    }
  }

  // Trailing wildcards may still match the empty remainder.
  while (p < pattern.length && pattern.charCodeAt(p) === STAR) p++;
  return p === pattern.length;
}

/**
 * How many wildcards a pattern may carry.
 *
 * The matcher above is not exponential, but `*`-heavy patterns still cost
 * `pattern x value` per match and buy nothing: a real threat pattern names a
 * command, a path or a keyword. A record with more than this many wildcards is
 * refused rather than run - refusing an *addition* to the deny-list is the safe
 * direction, and it is reported loudly.
 */
export const MAX_GLOB_WILDCARDS = 12;

/** Count `*` in a pattern, for the record validator. */
export function countWildcards(pattern: string): number {
  let n = 0;
  for (let i = 0; i < pattern.length; i++) {
    if (pattern.charCodeAt(i) === 0x2a) n++;
  }
  return n;
}

/**
 * Largest gap an INTERIOR `*` in a threat pattern may span.
 *
 * A field survey of 1 108 public MCP servers (see docs/mcp-survey.md) found every
 * multi-segment built-in firing on unrelated words that merely happened to appear
 * in the same paragraph: `*drain*wallet*` matched an anti-drainer scanner because
 * it says "drainer" in one clause and "wallet" in another, and `*seed*phrase*`
 * matched "for a **seed** topic, returns suggested search **phrases**". A real
 * threat pattern names something whose parts sit next to each other; 24 characters
 * is roughly "a few words apart" and comfortably covers "wallet seed or recovery
 * phrase".
 */
export const THREAT_MAX_GAP = 24;

/**
 * Threat-pattern matching: `wildcardMatch` plus two constraints that only make
 * sense for a deny-list.
 *
 * 1. **Interior gaps are bounded** to {@link THREAT_MAX_GAP}. Leading and trailing
 *    `*` stay unbounded — `*id_rsa*` must still find `id_rsa` anywhere.
 * 2. **A segment that starts with a word character must start at a word boundary.**
 *    `*sweep*funds*` matched an ENS floor-sweeping tool because `funds` sits inside
 *    "re**funds**". Only the START is anchored: a pattern author writing `*drain*`
 *    means "drainer" too, so anchoring the end as well would break ordinary
 *    stemming.
 *
 * Kept separate from {@link wildcardMatch} on purpose. That function is also what
 * `policy.sensitiveToolPatterns` runs on, where the operator wrote the pattern
 * against their own tool names and plain glob semantics are what they expect.
 *
 * Completeness matters here in a way it does not for a display filter: a missed
 * match is a deny-list entry that silently stopped working. So this explores every
 * reachable position per segment (deduplicated, so the work stays bounded by
 * `segments x value.length`) rather than taking the leftmost occurrence greedily,
 * which would report "no match" for a pattern that does match further along.
 */
export function threatMatch(pattern: string, value: string): boolean {
  if (!pattern.includes("*")) return value.includes(pattern);

  const parts = pattern.split("*");
  const openStart = parts[0] === "";
  const openEnd = parts[parts.length - 1] === "";
  const segments = parts.filter((s) => s !== "");
  if (segments.length === 0) return true;

  // Reachable end positions after matching the segments consumed so far.
  let ends: number[] = [0];
  for (let i = 0; i < segments.length; i++) {
    const seg = segments[i]!;
    // The first segment is anchored at 0 unless the pattern opened with `*`.
    const unbounded = i === 0 ? openStart : false;
    const next = new Set<number>();
    for (const from of ends) {
      const limit = unbounded ? value.length : Math.min(value.length, from + THREAT_MAX_GAP + seg.length);
      let at = from;
      for (;;) {
        const found = value.indexOf(seg, at);
        if (found < 0 || found + seg.length > limit) break;
        if (i === 0 && !openStart && found !== 0) break;
        if (startsOnBoundary(seg, value, found)) next.add(found + seg.length);
        at = found + 1;
      }
    }
    if (next.size === 0) return false;
    ends = [...next];
  }
  return openEnd || ends.some((e) => e === value.length);
}

/**
 * Is `seg` at `at` starting on a word boundary?
 *
 * Only asked when the segment's own first character is a word character — a
 * pattern starting with `~`, `.` or `/` has no boundary to respect.
 */
function startsOnBoundary(seg: string, value: string, at: number): boolean {
  if (!isWordChar(seg.charCodeAt(0))) return true;
  if (at === 0) return true;
  return !isWordChar(value.charCodeAt(at - 1));
}

/**
 * Letters and digits only — `_` and `-` are BOUNDARIES here, not word characters.
 *
 * Tool schemas are written in snake_case and kebab-case, so a field named
 * `seed_phrase` must still satisfy `*seed*phrase*`; treating `_` as a word
 * character silently switched that built-in off. "re**funds**" is still rejected,
 * because there the preceding character is a letter.
 */
function isWordChar(c: number): boolean {
  return (
    (c >= 0x30 && c <= 0x39) || // 0-9
    (c >= 0x41 && c <= 0x5a) || // A-Z
    (c >= 0x61 && c <= 0x7a) // a-z
  );
}
