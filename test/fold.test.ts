import { describe, it, expect } from "vitest";
import { foldForScan, FOLD_ID } from "../src/fold.js";

/**
 * The fold is what makes the rule table language-independent against obfuscation:
 * it normalises the text a rule reads so the same instruction cannot be spelled
 * in a way a regex misses while a model still understands it. These cases are all
 * benign words — the point is the transformation, not any particular phrase.
 */
describe("foldForScan", () => {
  it("has a stable identity", () => {
    expect(FOLD_ID).toBe("nfkc+tags-decoded+invisible-stripped+mixed-script-confusables/1");
  });

  it("maps compatibility (fullwidth, ligature) forms to plain letters via NFKC", () => {
    expect(foldForScan("Ｒｕｎ ｃｏｎｆｉｇ")).toBe("Run config"); // fullwidth
    expect(foldForScan("ﬁle")).toBe("file"); // ﬁ ligature
    expect(foldForScan("ⅾⅾ")).toBe("dd"); // roman-numeral small d
  });

  it("strips invisible characters sitting inside a word", () => {
    expect(foldForScan("co​nfig")).toBe("config"); // zero-width space
    expect(foldForScan("con­fig")).toBe("config"); // soft hyphen
    expect(foldForScan("a﻿b")).toBe("ab"); // BOM in the middle
  });

  it("decodes the invisible Unicode-tag block to the ASCII it hides", () => {
    // U+E0068 U+E0069 is an invisible "hi".
    expect(foldForScan("\u{E0068}\u{E0069}")).toBe("hi");
  });

  it("maps look-alike letters to Latin only inside a Latin word", () => {
    // Cyrillic а/р mixed into a Latin word.
    expect(foldForScan("pаypаl")).toBe("paypal");
    // A word written wholly in Cyrillic is left as Cyrillic — Russian stays Russian.
    expect(foldForScan("привет")).toBe("привет");
    // Greek text left alone too.
    expect(foldForScan("καλήμέρα")).toBe("καλήμέρα");
  });

  it("leaves ordinary text unchanged", () => {
    const plain = "Returns the weather for a city. See docs at example.org.";
    expect(foldForScan(plain)).toBe(plain);
    expect(foldForScan("")).toBe("");
  });
});
