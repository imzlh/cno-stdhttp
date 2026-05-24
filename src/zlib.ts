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
    private _decompressFn: ((data: Uint8Array) => Uint8Array) | null;
    private _encoding: string;
    constructor(encoding: string) {
        this._encoding = encoding.toLowerCase().trim();
        this._decompressFn = createDecompressor(encoding);
    }
    decompress(chunk: Uint8Array): Uint8Array {
        if (!this._decompressFn || chunk.length === 0) return chunk;
        return this._decompressFn(chunk);
    }
    get encoding(): string { return this._encoding; }
    get isActive(): boolean { return this._decompressFn !== null; }
}

/** Create a one-shot compressor. */
export function createCompressor(encoding: string, level = zlib.DEFAULT_COMPRESSION): ((data: Uint8Array) => Uint8Array) | null {
    const enc = encoding.toLowerCase().trim();
    if (enc === 'gzip') return (data) => new Uint8Array(zlib.gzip(data, level));
    if (enc === 'deflate') return (data) => new Uint8Array(zlib.deflate(data, level));
    return null;
}
