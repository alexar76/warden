/** Occurrence-local SSH references: a public file, or a local authentication option. */
export function benignSshReference(text: string, start: number, end: number): string | null {
  if (end - start > 256) return null;
  let left = start, right = end;
  const boundary = /[\s"'`\\,;:!?()[\]]/;
  const floor = Math.max(0, start - 256), ceiling = Math.min(text.length, end + 256);
  while (left > floor && !boundary.test(text[left - 1]!)) left--;
  while (right < ceiling && !boundary.test(text[right]!)) right++;
  if ((left > 0 && !boundary.test(text[left - 1]!)) || (right < text.length && !boundary.test(text[right]!)) || right - left > 256) return null;
  // A Windows path continues at a backslash. A JSON-escaped closing quote is
  // the sole delimiter exception; `.pub\\..\\private` is never a public file.
  if (text[right] === '\\' && text[right + 1] !== '"') return null;
  // Sentence punctuation is not part of the path; an internal dot or slash is.
  const token = text.slice(left, right).replace(/([^\.])\.$/, '$1');
  if (token.includes('/../') || token.includes('/./') || /\.pub\//i.test(token)) return null;
  if (/(?:^|\/)[^/]+\.pub$/i.test(token) || /(?:^|\/)\.ssh\/(?:authorized_keys|known_hosts)$/i.test(token)) {
    return 'this exact path names public SSH material';
  }
  if (!/^~\/\.ssh\/[^/]+$/.test(token)) return null;
  const before = text.slice(Math.max(0, left - 180), left);
  const sshOption = /\bssh(?:\s+(?:-[A-Za-z]+(?:\s+[^\s;"'`]+)?)){0,4}\s+-i\s+$/i.test(before);
  const describedSshOption = /\bssh\s+command\s+(?:uses?|includes?)\s+[`"']?-i\s+$/i.test(before);
  const describedPlaceholder = /^~\/\.ssh\/<[A-Za-z_][A-Za-z0-9_]*>$/.test(token) &&
    /\b(?:the\s+)?command\s+(?:uses?|includes?)\s+[`"']?-i\s+$/i.test(before) &&
    !/\b(?:base64|curl|openssl|cat|encode)\s+command\s+(?:uses?|includes?)\s+[`"']?-i\s+$/i.test(before);
  const describedOption = describedSshOption || describedPlaceholder;
  if (!sshOption && !describedOption) return null;
  if (!describedPlaceholder) {
    // A literal private filename is exempt only in a complete connection
    // command or a pure authentication reference. Additional prose (in any
    // language) is not proof that the file is used only for authentication.
    const tail = text.slice(right);
    if (tail.length > 512) return null;
    const connectionTail = /^(?:\s+(?:-p\s+\d{1,5}|-o\s+IdentitiesOnly=(?:yes|no)|-l\s+[A-Za-z0-9_.-]+))*\s+(?:[A-Za-z0-9_.-]+@)?(?:\[[a-f0-9:]+\]|[A-Za-z0-9][A-Za-z0-9.-]*)[`"']?\.?\s*$/i;
    const authenticationTail = /^[`"']?\s*(?:(?:when|for)\s+authenticating|(?:to|for)\s+authenticat(?:e|ion))?\.?\s*$/i;
    if (!(sshOption && connectionTail.test(tail)) && !(describedSshOption && authenticationTail.test(tail))) return null;
  }
  // A connection example cannot excuse reading/transmitting that same identity.
  const after = text.slice(end, Math.min(text.length, right + 160));
  if (/\b(?:contents?|bytes|material|values?)\b/i.test(after) || /\b(?:read|cat|paste|send|upload|attach|append|insert|share|transmit|encode|dump|reveal|export|include|copy|return|put|provide|pass|supply|print|log)\b[^.!?\n";]{0,50}\b(?:key|contents?|it|bytes|material|values?)\b/i.test(after)) return null;
  return 'the path is the local identity argument of an SSH connection command';
}

/** Remove only individually proven references, never an entire tool or field. */
export function withoutBenignSshReferences(text: string): string {
  return text.replace(/~\/\.ssh[^\s"'`\\,;:!?()[\]]*|\bid_rsa[^\s"'`\\,;:!?()[\]]*/gi, (token, offset: number) =>
    benignSshReference(text, offset, offset + token.length) ? ' '.repeat(token.length) : token);
}

/** Feed text per JSON string/key: prose from another field cannot prove local custody. */
export function sshToolText(value: unknown): string {
  const parts: string[] = [], stack: unknown[] = [value], seen = new WeakSet<object>();
  while (stack.length) {
    const item = stack.pop();
    if (typeof item === 'string') { parts.push(withoutBenignSshReferences(item).toLowerCase()); continue; }
    if (!item || typeof item !== 'object' || seen.has(item)) continue;
    seen.add(item);
    if (Array.isArray(item)) { for (const child of item) stack.push(child); }
    else for (const [key, child] of Object.entries(item)) stack.push(key, child);
  }
  return parts.join('\n');
}
