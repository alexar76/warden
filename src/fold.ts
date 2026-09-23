/**
 * Unicode folding before the rule table reads a tool definition.
 *
 * A rule written as `ignore previous instructions` must not be defeated by the
 * same words spelled so that a regex no longer sees them while a model still
 * does. Three spellings do that, and none of them depends on the language:
 *
 *   1. Compatibility forms. `ｉｇｎｏｒｅ ｐｒｅｖｉｏｕｓ` (fullwidth), ligatures,
 *      mathematical alphanumerics, circled letters. NFKC maps each to the plain
 *      letter a reader sees.
 *   2. Invisible characters inside a word. `ig​nore`, a soft hyphen, a
 *      variation selector. They are dropped here so they cannot split a rule word.
 *      The high-signal ones (zero-width, bidi, word-joiner, BOM, the tag block and
 *      the variation-selector supplement) are ALSO reported, because the
 *      hidden-character rule runs on the raw text; the purely cosmetic ones (a
 *      soft hyphen, an Indic/Arabic joiner control) are neutralised here and not
 *      separately flagged.
 *   3. Look-alike letters from another script inside a Latin word: `іgnоre` with a
 *      Cyrillic і and о. A token that mixes Latin with Cyrillic or Greek letters has
 *      its look-alikes mapped to Latin. A token written wholly in one script is left
 *      alone, so Russian and Greek text still reads as Russian and Greek.
 *
 * Unicode TAG characters (U+E0020–U+E007E) are the exception to "dropped": each is
 * an invisible copy of an ASCII character, and a whole instruction can be written in
 * them. They are DECODED to that ASCII here, so the instruction they carry meets the
 * same rules as visible text.
 *
 * The fold is part of the published ruleset (FOLD_ID is in its digest): the same
 * regexes over folded and unfolded text are different scans.
 */

/** Identity of this fold, carried in the ruleset preimage. Bump on any change below. */
export const FOLD_ID = "nfkc+tags-decoded+invisible-stripped+mixed-script-confusables/1";

/**
 * Characters with no visible form in running text. Dropped by the fold; the
 * hidden-character rule reports them from the raw text.
 */
const INVISIBLE_RE = new RegExp(
  "[\\u00AD\\u034F\\u061C\\u115F\\u1160\\u17B4\\u17B5\\u180B-\\u180F\\u200B-\\u200F\\u202A-\\u202E" +
    "\\u2060-\\u2064\\u2066-\\u206F\\u3164\\uFE00-\\uFE0F\\uFEFF\\uFFA0\\u{E0000}-\\u{E001F}" +
    "\\u{E007F}\\u{E0100}-\\u{E01EF}]",
  "gu",
);

/** U+E0020–U+E007E: invisible ASCII. Decoded, not dropped. */
const TAG_RE = /[\u{E0020}-\u{E007E}]/gu;

/**
 * Cyrillic and Greek letters that render like a Latin letter. Used only inside a
 * token that already contains Latin letters.
 */
const CONFUSABLE: Record<string, string> = {
  // Cyrillic lower case
  "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p",
  "с": "c", "т": "t", "у": "y", "х": "x", "і": "i", "ї": "i", "ј": "j", "ѕ": "s", "ԁ": "d",
  "ԛ": "q", "ԝ": "w", "ӏ": "l", "һ": "h", "ɡ": "g",
  // Cyrillic upper case
  "А": "A", "В": "B", "Е": "E", "Ё": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P",
  "С": "C", "Т": "T", "У": "Y", "Х": "X", "І": "I", "Ї": "I", "Ј": "J", "Ѕ": "S", "Һ": "H",
  "Ԛ": "Q", "Ԝ": "W", "Ӏ": "I",
  // Greek
  "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u",
  "χ": "x", "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
  "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
};

const TOKEN_RE = /[\p{L}\p{M}]+/gu;
const LATIN_RE = /[A-Za-z]/;
const CONFUSABLE_RE = new RegExp(`[${Object.keys(CONFUSABLE).join("")}]`, "gu");

/**
 * Fold `text` for matching. Never shown to anyone: findings quote the folded span,
 * and the raw text is what the hidden-character rules and the reader see.
 */
export function foldForScan(text: string): string {
  if (!text) return text;
  let out = text.normalize("NFKC");
  out = out.replace(TAG_RE, (ch) => String.fromCharCode((ch.codePointAt(0) ?? 0xe0020) - 0xe0000));
  out = out.replace(INVISIBLE_RE, "");
  CONFUSABLE_RE.lastIndex = 0;
  if (!CONFUSABLE_RE.test(out)) return out;
  return out.replace(TOKEN_RE, (tok) => {
    // Map a token that mixes Latin with look-alikes (`pаypаl`), OR one written
    // WHOLLY in look-alike letters (`ЅУЅТЕМ`, `рrіvаtе` where every letter is in
    // the table). A token with non-Latin letters that are NOT all confusables —
    // ordinary Russian or Greek — is left alone, so those languages read normally.
    // The scanner also matches the un-mapped raw text, so this only ever ADDS a
    // reading; it never hides the original.
    const marks = tok.replace(/\p{M}/gu, "");
    if (!LATIN_RE.test(tok) && !allConfusable(marks)) return tok;
    return tok.replace(CONFUSABLE_RE, (ch) => CONFUSABLE[ch] ?? ch);
  });
}

/** Every letter of the token is one of the Latin look-alikes in the table. */
function allConfusable(letters: string): boolean {
  if (!letters) return false;
  for (const ch of letters) {
    if (!(ch in CONFUSABLE) && !/[A-Za-z]/.test(ch)) return false;
  }
  return /[^A-Za-z]/.test(letters); // at least one non-Latin look-alike, else nothing to map
}
