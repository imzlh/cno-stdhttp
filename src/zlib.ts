/**
 * Shared zlib utilities for HTTP Content-Encoding support.
 * Used by both client (decompress) and server (compress).
 */

const zlib = import.meta.use("zlib");

type Uint8Array = globalThis.Uint8Array<ArrayBuffer>;

// Zip-bomb guard: cumulative decompressed output per stream may not exceed this.
export const MAX_DECOMPRESS_BYTES = 256 * 1024 * 1024;

/** Parse Accept-Encoding header into ordered list of supported algorithms. */
export function parseAcceptEncoding(header: string | null | undefined): ('gzip' | 'deflate')[] {
    if (!header) return [];
    const result: ('gzip' | 'deflate')[] = [];
    const parts = header.toLowerCase().split(',').map(s => s.trim());
    for (const part of parts) {
        const tokens = part.split(';').map(s => s.trim());
        const algo = tokens[0];
        if (algo === undefined) continue;
        let q = 1;
        for (const token of tokens.slice(1)) {
            const [name, value] = token.split('=').map(s => s.trim());
            if (name === 'q' && value !== undefined) {
                const parsed = Number(value);
                if (Number.isFinite(parsed)) q = parsed;
            }
        }
        if (q <= 0) continue;
        if (algo === 'gzip' && !result.includes('gzip')) result.push('gzip');
        else if (algo === 'deflate' && !result.includes('deflate')) result.push('deflate');
    }
    return result;
}

/** Pick best encoding from Accept-Encoding list. gzip preferred. */
export function pickEncoding(supported: ('gzip' | 'deflate')[]): 'gzip' | 'deflate' | null {
    if (supported.includes('gzip')) return 'gzip';
    if (supported.includes('deflate')) return 'deflate';
    return null;
}

/** Check if Content-Type is worth compressing. */
export function shouldCompress(contentType: string | null): boolean {
    if (!contentType) return false;
    const ct = contentType.toLowerCase().split(';')[0]?.trim() ?? '';
    return ct.startsWith('text/') || ct === 'application/json' || ct === 'application/javascript' ||
           ct === 'application/xml' || ct === 'application/xhtml+xml' || ct === 'application/rss+xml' ||
           ct === 'application/atom+xml' || ct === 'application/svg+xml' || ct === 'application/wasm' ||
           ct.endsWith('+json') || ct.endsWith('+xml');
}

/** Create a one-shot decompressor. Output capped to guard against zip bombs. */
export function createDecompressor(encoding: string, maxOutput = MAX_DECOMPRESS_BYTES): ((data: Uint8Array) => Uint8Array) | null {
    const enc = encoding.toLowerCase().trim();
    if (enc === 'gzip') return bombGuard(zlib.gunzip, maxOutput);
    if (enc === 'deflate') {
        // One shared budget across both attempts: separate counters would charge the
        // failed inflate's output twice and let the raw path decode a second full
        // maxOutput on top of it.
        const budget = { total: 0 };
        const inflate = bombGuard(zlib.inflate, maxOutput, budget);
        const inflateRaw = bombGuard(zlib.inflateRaw, maxOutput, budget);
        return (data) => {
            const before = budget.total;
            try { return inflate(data); }
            catch {
                // Roll back the failed attempt's charge; it produced nothing usable.
                budget.total = before;
                return inflateRaw(data);
            }
        };
    }
    return null;
}

// Wraps a one-shot decompressor, throwing once cumulative output exceeds maxOutput (zip-bomb guard).
function bombGuard(
    fn: (d: Uint8Array) => ArrayBuffer,
    maxOutput: number,
    budget: { total: number } = { total: 0 },
): (data: Uint8Array) => Uint8Array {
    return (data) => {
        const out = new Uint8Array(fn(data));
        budget.total += out.length;
        if (budget.total > maxOutput) throw new Error(`decompressed output exceeds ${maxOutput} bytes`);
        return out;
    };
}

/** Streaming decompressor for incremental decompression. */
export class StreamingDecompressor {
    private _stream: ReturnType<typeof zlib.createGunzip> | null;
    private _encoding: string;
    private _deflateRawFallback = false;
    private _produced = false;
    private _finished = false;
    private _total = 0;
    private _maxOutput: number;
    constructor(encoding: string, maxOutput = MAX_DECOMPRESS_BYTES) {
        this._encoding = encoding.toLowerCase().trim();
        this._maxOutput = maxOutput;
        if (this._encoding === 'gzip') this._stream = zlib.createGunzip();
        else if (this._encoding === 'deflate') this._stream = zlib.createInflate();
        else this._stream = null;
    }
    decompress(chunk: Uint8Array): Uint8Array {
        if (!this._stream || chunk.length === 0) return chunk;
        try {
            const out = new Uint8Array(this._stream.inflate(chunk));
            this._produced = true;
            this._total += out.length;
            if (this._total > this._maxOutput) throw new Error(`decompressed output exceeds ${this._maxOutput} bytes`);
            return out;
        } catch (err) {
            // Raw-deflate retry is only sound on the first chunk. Restarting mid-stream
            // would decode this chunk against a fresh window and emit garbage.
            if (this._encoding === 'deflate' && !this._deflateRawFallback && !this._produced) {
                this._deflateRawFallback = true;
                this._stream = zlib.createInflateRaw();
                const out = new Uint8Array(this._stream.inflate(chunk));
                this._produced = true;
                this._total += out.length;
                if (this._total > this._maxOutput) throw new Error(`decompressed output exceeds ${this._maxOutput} bytes`);
                return out;
            }
            throw err;
        }
    }
    get encoding(): string { return this._encoding; }
    get isActive(): boolean { return this._stream !== null; }

    /**
     * End of compressed input: validate the stream trailer. A body cut short mid-stream
     * inflates to a short-but-plausible result, so without this a truncated (or
     * deliberately clipped) response body is indistinguishable from a complete one.
     * Throws when the stream is incomplete or corrupt; safe to call more than once.
     */
    finish(): Uint8Array {
        const stream = this._stream;
        if (!stream || this._finished) return new Uint8Array(0);
        this._finished = true;
        // circu.js marks an inflater finished as soon as inflate() sees the trailer,
        // so a following finish() is a duplicate and throws. Test the state instead
        // of matching the thrown message: the message is not part of any contract and
        // a reworded throw would silently turn this back into a hard error.
        if (stream.finished) return new Uint8Array(0);
        const out = new Uint8Array(stream.finish());
        this._total += out.length;
        if (this._total > this._maxOutput) throw new Error(`decompressed output exceeds ${this._maxOutput} bytes`);
        return out;
    }
}

/** Create a one-shot compressor. */
export function createCompressor(encoding: string, level = zlib.DEFAULT_COMPRESSION): ((data: Uint8Array) => Uint8Array) | null {
    const enc = encoding.toLowerCase().trim();
    if (enc === 'gzip') return (data) => new Uint8Array(zlib.gzip(data, level));
    if (enc === 'deflate') return (data) => new Uint8Array(zlib.deflate(data, level));
    return null;
}

/** Streaming compressor — produces a single continuous gzip/deflate stream across multiple chunks. */
export class StreamingCompressor {
    private _stream: ReturnType<typeof zlib.createGzip> | null;
    constructor(encoding: string, level = zlib.DEFAULT_COMPRESSION) {
        const enc = encoding.toLowerCase().trim();
        if (enc === 'gzip') this._stream = zlib.createGzip(level);
        else if (enc === 'deflate') this._stream = zlib.createDeflate(level);
        else this._stream = null;
    }
    compress(chunk: Uint8Array): Uint8Array {
        if (!this._stream || chunk.length === 0) return chunk;
        return new Uint8Array(this._stream.deflate(chunk));
    }
    finish(): Uint8Array {
        if (!this._stream) return new Uint8Array(0);
        return new Uint8Array(this._stream.finish());
    }
    get isActive(): boolean { return this._stream !== null; }
}
