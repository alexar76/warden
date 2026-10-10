/** Bounded, non-executing readings of encoded text. No language vocabulary. */
const MAX_TOKEN = 8192;
const MAX_DECODED = 65536;
const MAX_PASSES = 4;
const ENTITIES: Record<string, string> = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", colon: ':', sol: '/',
  bsol: '\\', tab: '\t', newline: '\n', nbsp: ' ',
};
const utf8 = new TextDecoder('utf-8', { fatal: true });

function point(raw: string, radix: number, fallback: string): string {
  const n = Number.parseInt(raw, radix);
  return n > 0 && n <= 0x10ffff && !(n >= 0xd800 && n <= 0xdfff) ? String.fromCodePoint(n) : fallback;
}

/**
 * Preserve the original as a separate scanner pass. Decoding changes a reading,
 * never the tool, its pin, or what gets executed. Invalid encodings remain literal.
 * Replacement cannot grow the input; per-token and aggregate budgets bound work.
 */
export function decodeForScan(text: string): string {
  let out = text;
  let budget = MAX_DECODED;
  for (let pass = 0; pass < MAX_PASSES; pass++) {
    const before = out;
    const replace = (whole: string, decoded: string): string => {
      if (whole.length > MAX_TOKEN || whole.length > budget || decoded.length > whole.length) return whole;
      budget -= whole.length;
      return decoded;
    };
    out = out.replace(/&#(?:x([0-9a-f]{1,6})|([0-9]{1,7}));|&(amp|lt|gt|quot|apos|colon|sol|bsol|Tab|NewLine|nbsp);/gi,
      (whole, hex: string | undefined, decimal: string | undefined, named: string | undefined) =>
        replace(whole, named ? ENTITIES[named.toLowerCase()] ?? whole : point(hex ?? decimal!, hex ? 16 : 10, whole)));
    out = out.replace(/(?<!\\)\\{1,8}(?:u\{([0-9a-f]{1,6})\}|u([0-9a-f]{4})|x([0-9a-f]{2}))/gi,
      (whole, brace: string | undefined, unit: string | undefined, hex: string | undefined) =>
        replace(whole, brace ? point(brace, 16, whole) : String.fromCharCode(Number.parseInt(unit ?? hex!, 16))));
    out = out.replace(/(?:%[0-9a-f]{2})+/gi, whole => {
      if (whole.length > MAX_TOKEN || whole.length > budget) return whole;
      try { return replace(whole, decodeURIComponent(whole)); } catch { return whole; }
    });
    out = out.replace(/(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_-]{24,}={0,2}(?![A-Za-z0-9+/_=-])/g, whole => {
      if (whole.length > MAX_TOKEN || whole.length > budget || whole.replace(/=+$/, '').length % 4 === 1) return whole;
      try {
        const buffer = Buffer.from(whole, 'base64url');
        if (buffer.toString('base64url') !== whole.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')) return whole;
        const decoded = utf8.decode(buffer);
        if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(decoded) || !/\p{L}[\s\S]*\p{L}/u.test(decoded)) return whole;
        return replace(whole, decoded);
      } catch { return whole; }
    });
    if (out === before || budget <= 0) break;
  }
  return out;
}
