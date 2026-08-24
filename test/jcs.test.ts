/**
 * RFC 8785 (JCS) canonicalization, as profiled by AWR/2 `awr/SPEC.md` §4.
 *
 * The positive cases are transcriptions of the AWR conformance vectors in
 * `awr/vectors/canonicalization/` (inlined, because this package ships standalone
 * and must not depend on a sibling directory), and the negative cases carry the reason code
 * the vector set records for them. Non-ASCII and control characters are written as
 * escapes throughout: the point of several vectors is which exact code units are
 * present, which a literal in a source file cannot show a reviewer.
 */
import { describe, it, expect } from "vitest";
import { canonicalize, parseJsonStrict, CanonicalizationError } from "../src/jcs.js";

/** The reason code carried by a refusal, for terse assertions. */
function codeOf(fn: () => unknown): string {
  try {
    fn();
  } catch (err) {
    return err instanceof CanonicalizationError ? err.code : `not-a-CanonicalizationError: ${(err as Error).name}`;
  }
  return "no-error";
}

const E_ACUTE = "\u00e9"; // U+00E9, precomposed e-acute
const E_COMBINING = "e\u0301"; // e + U+0301 combining acute: same glyph, different code units
const EMOJI = "\u{1f600}"; // U+1F600, surrogate pair D83D DE00
const BMP_MAX = "\uffff"; // the highest BMP code unit

describe("JCS canonicalize — positive vectors", () => {
  it("sorts property names by UTF-16 code unit (key-order-ascii)", () => {
    expect(
      canonicalize({ [E_ACUTE]: "e-acute", Z: 1, a: 2, A: 3, z: 4, "10": 5, "2": 6, "": "empty name", _: 7, "~": 8 }),
    ).toBe(`{"":"empty name","10":5,"2":6,"A":3,"Z":1,"_":7,"a":2,"z":4,"~":8,${JSON.stringify(E_ACUTE)}:"e-acute"}`);
  });

  it("orders astral keys by their surrogate pair, not their code point (key-order-non-bmp)", () => {
    // U+1F600's first code unit (D83D) sorts BELOW U+FFFF, while its code point
    // sorts above it. Sorting by code point would swap these two members.
    expect(canonicalize({ [BMP_MAX]: 3, [EMOJI]: 2, a: 1 })).toBe(
      `{"a":1,${JSON.stringify(EMOJI)}:2,${JSON.stringify(BMP_MAX)}:3}`,
    );
  });

  it("sorts nested objects and preserves array order (nesting-mixed)", () => {
    expect(canonicalize({ outer: { z: 1, a: [{ b: 1, a: 2 }] } })).toBe('{"outer":{"a":[{"a":2,"b":1}],"z":1}}');
  });

  it("uses two-char escapes and lowercase \\u00xx for the remaining C0 controls (escapes-all-forms)", () => {
    expect(canonicalize({ twoChar: "\b\t\n\f\r\"\\" })).toBe('{"twoChar":"\\b\\t\\n\\f\\r\\"\\\\"}');
    expect(canonicalize({ c0: "\u0000\u0001\u001f" })).toBe('{"c0":"\\u0000\\u0001\\u001f"}');
    // DEL and NBSP must NOT be escaped: RFC 8785 escapes C0 controls only.
    expect(canonicalize({ keep: "\u007f\u00a0 /'<>&" })).not.toContain("\\u");
  });

  it("applies no Unicode normalization (no-nfc-normalization)", () => {
    // NFC would collide these two property names into one member.
    expect(canonicalize({ [E_ACUTE]: 1, [E_COMBINING]: 2 })).toBe(
      `{${JSON.stringify(E_COMBINING)}:2,${JSON.stringify(E_ACUTE)}:1}`,
    );
  });

  it("renders integers to the safe bound and normalises -0 (numbers-integer-bounds)", () => {
    expect(canonicalize({ maxSafe: 9007199254740991, minSafe: -9007199254740991, zero: -0, one: 1 })).toBe(
      '{"maxSafe":9007199254740991,"minSafe":-9007199254740991,"one":1,"zero":0}',
    );
  });

  it("keeps empty containers and literals (empty-containers, literals-and-strings)", () => {
    expect(canonicalize({ o: {}, a: [], nested: [{}, [], [[]]], s: "", n: null })).toBe(
      '{"a":[],"n":null,"nested":[{},[],[[]]],"o":{},"s":""}',
    );
    expect(canonicalize([true, false, null, "true"])).toBe('[true,false,null,"true"]');
  });

  it("is insertion-order independent — the property the signed feed depends on", () => {
    const a = { records: [{ pattern: "*x*", severity: "high" }], timestamp: 1 };
    const b = { timestamp: 1, records: [{ severity: "high", pattern: "*x*" }] };
    expect(canonicalize(a)).toBe(canonicalize(b));
    // ...whereas the byte string the previous implementation signed did depend on it.
    expect(JSON.stringify(a)).not.toBe(JSON.stringify(b));
  });
});

describe("JCS canonicalize — refusals", () => {
  it("refuses a non-integer number (AWR-CANON-001)", () => {
    expect(codeOf(() => canonicalize({ latencyMs: 2340.5 }))).toBe("AWR-CANON-001");
    expect(codeOf(() => canonicalize({ n: Number.NaN }))).toBe("AWR-CANON-001");
    expect(codeOf(() => canonicalize({ n: Number.POSITIVE_INFINITY }))).toBe("AWR-CANON-001");
  });

  it("refuses an integer outside ±(2^53−1) (AWR-CANON-002)", () => {
    expect(codeOf(() => canonicalize({ big: 9007199254740992 }))).toBe("AWR-CANON-002");
  });

  it("refuses a lone surrogate instead of substituting one (AWR-CANON-003)", () => {
    expect(codeOf(() => canonicalize({ text: "lone-\ud800-surrogate" }))).toBe("AWR-CANON-003");
    expect(codeOf(() => canonicalize({ "\udc00": 1 }))).toBe("AWR-CANON-003");
    expect(canonicalize({ ok: EMOJI })).toBe(`{"ok":${JSON.stringify(EMOJI)}}`);
  });

  it("refuses values JSON cannot represent (AWR-CANON-005)", () => {
    // JSON.stringify drops an undefined member silently, which changes the signed
    // bytes without changing the document.
    expect(codeOf(() => canonicalize({ timestamp: undefined }))).toBe("AWR-CANON-005");
    expect(codeOf(() => canonicalize({ when: new Date(0) }))).toBe("AWR-CANON-005");
    expect(codeOf(() => canonicalize({ m: new Map() }))).toBe("AWR-CANON-005");
    const cycle: Record<string, unknown> = {};
    cycle.self = cycle;
    expect(codeOf(() => canonicalize(cycle))).toBe("AWR-CANON-005");
  });
});

describe("parseJsonStrict", () => {
  it("accepts a well-formed document and returns the parsed value", () => {
    expect(parseJsonStrict('{"a":[1,2],"b":"x"}')).toEqual({ a: [1, 2], b: "x" });
  });

  it("rejects duplicate property names that last-wins would have hidden (AWR-CANON-004)", () => {
    expect(codeOf(() => parseJsonStrict('{"a":1,"b":{"x":1,"x":2},"c":3}'))).toBe("AWR-CANON-004");
    // Escaped and literal spellings of one name are one name.
    expect(codeOf(() => parseJsonStrict('{"a":1,"\\u0061":2}'))).toBe("AWR-CANON-004");
    // The same name in sibling objects is not a duplicate.
    expect(parseJsonStrict('{"a":[{"x":1},{"x":2}]}')).toEqual({ a: [{ x: 1 }, { x: 2 }] });
    // A string in a value position is not a property name.
    expect(parseJsonStrict('{"a":["x","x"],"b":"x"}')).toEqual({ a: ["x", "x"], b: "x" });
  });

  it("rejects non-integer number literals lexically (AWR-CANON-001)", () => {
    // 2340.0 and 1e2 parse to integers in JavaScript; a publisher whose language
    // keeps them as floats signed different bytes for the same document.
    expect(codeOf(() => parseJsonStrict('{"a":2340.0}'))).toBe("AWR-CANON-001");
    expect(codeOf(() => parseJsonStrict('{"a":1e2}'))).toBe("AWR-CANON-001");
    expect(codeOf(() => parseJsonStrict('{"a":-0.5}'))).toBe("AWR-CANON-001");
  });

  it("rejects an out-of-range integer literal without losing precision (AWR-CANON-002)", () => {
    expect(codeOf(() => parseJsonStrict('{"big":9007199254740993}'))).toBe("AWR-CANON-002");
    expect(codeOf(() => parseJsonStrict('{"big":-12345678901234567890}'))).toBe("AWR-CANON-002");
  });

  it("rejects malformed JSON (AWR-CANON-005)", () => {
    expect(codeOf(() => parseJsonStrict('{"a":1,"b":[1,2,],}'))).toBe("AWR-CANON-005");
    expect(codeOf(() => parseJsonStrict("not json"))).toBe("AWR-CANON-005");
  });

  it("does not mistake a colon inside a string for a member separator", () => {
    expect(parseJsonStrict('{"a":"b\\":x","c":1}')).toEqual({ a: 'b":x', c: 1 });
    expect(codeOf(() => parseJsonStrict('{"a":"x:1","a":2}'))).toBe("AWR-CANON-004");
  });
});
