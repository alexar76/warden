import type { Readable } from 'node:stream';

export const WRAP_FRAME_BYTES = 32 * 1024 * 1024;
export type FrameMode = 'unknown' | 'ndjson' | 'lsp';

/** Incremental, bounded framing. Raw JSON bodies are retained for transparent forwarding. */
export class WrapFrames {
  mode: FrameMode;
  private buf: Buffer = Buffer.alloc(0);
  constructor(mode: FrameMode = 'unknown') { this.mode = mode; }
  push(chunk: Buffer): string[] {
    this.buf = Buffer.concat([this.buf, chunk]);
    if (this.mode === 'unknown') {
      const prefix = this.buf.subarray(0, 8193).toString('ascii').trimStart().toLowerCase();
      if (!prefix || 'content-length:'.startsWith(prefix)) {
        if (this.buf.length > 8192) throw new Error('MCP header too large');
        return [];
      }
      this.mode = prefix.startsWith('content-length:') ? 'lsp' : 'ndjson';
    }
    const bodies: string[] = [];
    while (this.buf.length) {
      let start = 0, end: number, consumed: number;
      if (this.mode === 'lsp') {
        const header = this.buf.indexOf('\r\n\r\n');
        if (header < 0) {
          if (this.buf.length > 8192) throw new Error('MCP header too large');
          break;
        }
        if (header > 8192) throw new Error('MCP header too large');
        const lengths = [...this.buf.subarray(0, header).toString('ascii').matchAll(/^Content-Length:\s*(\d+)\s*$/gim)];
        const length = lengths.length === 1 ? Number(lengths[0]![1]) : NaN;
        if (!Number.isSafeInteger(length) || length < 0 || length > WRAP_FRAME_BYTES) throw new Error('Invalid or oversized MCP frame');
        start = header + 4; end = start + length; consumed = end;
        if (this.buf.length < end) break;
      } else {
        end = this.buf.indexOf(10); consumed = end + 1;
        if (end < 0) {
          if (this.buf.length > WRAP_FRAME_BYTES) throw new Error('MCP frame too large');
          break;
        }
        if (end > WRAP_FRAME_BYTES) throw new Error('MCP frame too large');
      }
      const body = this.buf.subarray(start, end).toString('utf8');
      this.buf = this.buf.subarray(consumed);
      if (body.trim()) bodies.push(body);
    }
    return bodies;
  }
  end(): string[] {
    if (!this.buf.length) return [];
    if (this.mode === 'lsp') throw new Error('Incomplete MCP frame');
    return this.push(Buffer.from('\n'));
  }
}

export function readFrames(stream: Readable, frames: WrapFrames, onBody: (body: string) => void, onError: (e: unknown) => void, onEnd: () => void): void {
  stream.on('data', chunk => {
    try { for (const body of frames.push(Buffer.from(chunk))) onBody(body); }
    catch (e) { onError(e); }
  });
  stream.on('end', () => {
    try { for (const body of frames.end()) onBody(body); }
    catch (e) { onError(e); }
    onEnd();
  });
  stream.on('error', onError);
}
