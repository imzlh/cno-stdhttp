/**
 * Shared zlib utilities for HTTP Content-Encoding support.
 * Used by both client (decompress) and server (compress).
 */

const zlib = import.meta.use("zlib");

type Uint8Array = globalThis.Uint8Array<ArrayBuffer>;

/** Parse Accept-Encoding header into ordered list of supported algorithms. */
export function parseAcceptEncoding(header: string | null | undefined): ('gzip' | 'deflate')[] {
    if (!header) return [];
    const result: ('gzip' | 'deflate')[] = [];
    const parts = header.toLowerCase().split(',').map(s => s.trim());
    for (const part of parts) {
        const algo = part.split(';')[0]!.trim();
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
    const ct = contentType.toLowerCase().split(';')[0]!.trim();
    return ct.startsWith('text/') || ct === 'application/json' || ct === 'application/javascript' ||
           ct === 'application/xml' || ct === 'application/xhtml+xml' || ct === 'application/rss+xml' ||
           ct === 'application/atom+xml' || ct === 'application/svg+xml' || ct === 'application/wasm' ||
           ct.endsWith('+json') || ct.endsWith('+xml');
}

/** Create a one-shot decompressor. */
export function createDecompressor(encoding: string): ((data: Uint8Array) => Uint8Array) | null {
    const enc = encoding.toLowerCase().trim();
    if (enc === 'gzip') return (data) => new Uint8Array(zlib.gunzip(data));
    if (enc === 'deflate') return (data) => {
        try { return new Uint8Array(zlib.inflate(data)); }
        catch { return new Uint8Array(zlib.inflateRaw(data)); }
    };
    return null;
}

/** Streaming decompressor for incremental decompression. */
export class StreamingDecompressor {
    private _stream: ReturnType<typeof zlib.createGunzip> | null;
    private _encoding: string;
    private _deflateRawFallback = false;
    constructor(encoding: string) {
        this._encoding = encoding.toLowerCase().trim();
        if (this._encoding === 'gzip') this._stream = zlib.createGunzip();
        else if (this._encoding === 'deflate') this._stream = zlib.createInflate();
        else this._stream = null;
    }
    decompress(chunk: Uint8Array): Uint8Array {
        if (!this._stream || chunk.length === 0) return chunk;
        try {
            return new Uint8Array(this._stream.inflate(chunk));
        } catch (err) {
            if (this._encoding === 'deflate' && !this._deflateRawFallback) {
                this._deflateRawFallback = true;
                this._stream = zlib.createInflateRaw();
                return new Uint8Array(this._stream.inflate(chunk));
            }
            throw err;
        }
    }
    get encoding(): string { return this._encoding; }
    get isActive(): boolean { return this._stream !== null; }
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
