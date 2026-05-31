/**
 * CJS HTTP client -- H1 and H2 unity
 * @copyright iz
 */

import { connectionManager } from "./connection";
import { HttpRequestBuilder, HttpResponseParser } from "./h1";
import { HttpVersion } from "./protocol";
import { dbg } from "./debug";

const engine = import.meta.use("engine");

export type ProgressCallback = (now: number, total: number) => void;

export interface FetchOptions {
    method?: string;
    headers?: Record<string, string>;
    body?: Uint8Array | null;
}

function parseUrl(url: string): { protocol: 'http:' | 'https:'; hostname: string; port: number; path: string } {
    const match = url.match(/^(https?):\/\/([^/:]+)(?::(\d+))?(\/.*)?$/);
    if (!match) throw new Error(`Invalid URL: ${url}`);
    return {
        protocol: `${match[1]}:` as 'http:' | 'https:',
        hostname: match[2]!,
        port: match[3] ? parseInt(match[3]) : (match[1] === 'https' ? 443 : 80),
        path: match[4] ?? '/',
    };
}

function buildHeaders(hostname: string, httpVersion: HttpVersion, opts?: FetchOptions): Array<[string, string]> {
    const h: Array<[string, string]> = [
        ['host', hostname],
        ['connection', httpVersion === HttpVersion.HTTP10 ? 'close' : 'keep-alive'],
    ];
    if (opts?.headers) {
        for (const [k, v] of Object.entries(opts.headers)) h.push([k.toLowerCase(), v]);
    }
    if (!h.find(([n]) => n === 'user-agent')) h.push(['user-agent', 'cnojs/http']);
    if (!h.find(([n]) => n === 'accept')) h.push(['accept', '*/*']);
    return h;
}

function mergeChunks(chunks: Uint8Array[]): Uint8Array {
    const total = chunks.reduce((s, c) => s + c.length, 0);
    const result = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) { result.set(c, off); off += c.length; }
    return result;
}

function shouldKeepAlive(parser: HttpResponseParser): boolean {
    if (parser.isHttp10) {
        return parser.getHeaders().some(([n, v]) => n === 'connection' && v.toLowerCase() === 'keep-alive');
    }
    return !parser.getHeaders().some(([n, v]) => n === 'connection' && v.toLowerCase() === 'close');
}

type Uint8Array = globalThis.Uint8Array<ArrayBuffer>;

const connConfig = (parsed: ReturnType<typeof parseUrl>) => ({
    hostname: parsed.hostname,
    port: parsed.port,
    protocol: parsed.protocol,
});

/* ------------------------------------------------------------------ */
/* Sync fetch                                                          */
/* ------------------------------------------------------------------ */

export function fetchBytes(url: string, onProgress?: ProgressCallback, httpVersionOrOpts?: HttpVersion | FetchOptions): Uint8Array {
    const opts: FetchOptions | undefined = typeof httpVersionOrOpts === 'object' ? httpVersionOrOpts : undefined;
    const httpVersion: HttpVersion = typeof httpVersionOrOpts === 'string' ? httpVersionOrOpts : HttpVersion.HTTP11;
    const parsed = parseUrl(url);
    const cfg = connConfig(parsed);
    dbg('http.fetch', () => `→ ${opts?.method ?? 'GET'} ${url}`);
    const conn = connectionManager.acquire(cfg);

    const headers = buildHeaders(parsed.hostname, httpVersion, opts);
    const builder = new HttpRequestBuilder({
        method: opts?.method ?? 'GET', path: parsed.path, host: parsed.hostname,
        httpVersion, headers, body: opts?.body ?? null,
    });
    const requestBytes = builder.build();
    conn.write(requestBytes);

    const parser = new HttpResponseParser();
    const chunks: Uint8Array[] = [];
    let contentLength = 0;
    let loaded = 0;
    let parseError: Error | null = null;

    parser.onHeadersComplete = (status, hdrs) => {
        const cl = hdrs.find(([n]) => n === 'content-length');
        if (cl) contentLength = parseInt(cl[1]!, 10);
        dbg('http.fetch', () => `← ${status} (content-length: ${contentLength || 'unknown'}) ${url}`);
    };
    parser.onData = (chunk) => { chunks.push(chunk); loaded += chunk.length; onProgress?.(loaded, contentLength); };
    parser.onError = (e) => { parseError = e; };

    while (!parser.isCompleted && !parseError) {
        const d = conn.read(128 * 1024, true);
        if (!d) break;
        parser.feed(d);
    }

    if (parseError) {
        dbg('http.fetch', () => `parse error: ${parseError} ${url}`);
        conn.close(); throw parseError;
    }
    if (!parser.isCompleted) {
        conn.close();
        throw new Error(`Response not completed: ${url}`);
    }

    const status = parser.getStatusCode();
    const reusable = shouldKeepAlive(parser);
    if (status >= 300 && status < 400) {
        const location = parser.getHeaders().find(([n]) => n === 'location')?.[1];
        if (location) {
            if (reusable) connectionManager.release(cfg, conn);
            else conn.close();
            const nextUrl = location.startsWith('/') ? `${parsed.protocol}//${parsed.hostname}:${parsed.port}${location}` : location;
            dbg('http.fetch', () => `redirect ${status} → ${nextUrl}`);
            return fetchBytes(nextUrl, onProgress, httpVersionOrOpts);
        }
    }

    if (reusable) connectionManager.release(cfg, conn);
    else conn.close();
    if (status < 200 || status >= 300) {
        const body = mergeChunks(chunks);
        dbg('http.fetch', () => `error headers: ${JSON.stringify(parser.getHeaders())}`);
        dbg('http.fetch', () => `error response: ${status} ${url}`);
        throw new Error(`HTTP ${status} ${url}`);
    }

    dbg('http.fetch', () => `done: ${loaded} bytes from ${url}`);
    return mergeChunks(chunks);
}

export function fetchSync(url: string, onProgress?: ProgressCallback, httpVersionOrOpts?: HttpVersion | FetchOptions): { status: number; headers: Array<[string, string]>; body: Uint8Array } {
    const opts: FetchOptions | undefined = typeof httpVersionOrOpts === 'object' ? httpVersionOrOpts : undefined;
    const httpVersion: HttpVersion = typeof httpVersionOrOpts === 'string' ? httpVersionOrOpts : HttpVersion.HTTP11;
    const parsed = parseUrl(url);
    const cfg = connConfig(parsed);
    const conn = connectionManager.acquire(cfg);

    const headers = buildHeaders(parsed.hostname, httpVersion, opts);
    const builder = new HttpRequestBuilder({
        method: opts?.method ?? 'GET', path: parsed.path, host: parsed.hostname,
        httpVersion, headers, body: opts?.body ?? null,
    });
    const requestBytes = builder.build();
    conn.write(requestBytes);

    const parser = new HttpResponseParser();
    const chunks: Uint8Array[] = [];
    let contentLength = 0;
    let loaded = 0;
    let parseError: Error | null = null;

    parser.onHeadersComplete = (status, hdrs) => {
        void status;
        const cl = hdrs.find(([n]) => n === 'content-length');
        if (cl) contentLength = parseInt(cl[1]!, 10);
    };
    parser.onData = (chunk) => { chunks.push(chunk); loaded += chunk.length; onProgress?.(loaded, contentLength); };
    parser.onError = (e) => { parseError = e; };

    while (!parser.isCompleted && !parseError) {
        const d = conn.read(128 * 1024, true);
        if (!d) break;
        parser.feed(d);
    }

    if (parseError) { conn.close(); throw parseError; }
    if (!parser.isCompleted) {
        conn.close();
        throw new Error(`Response not completed: ${url}`);
    }

    const status = parser.getStatusCode();
    const respHeaders = parser.getHeaders();
    const reusable = shouldKeepAlive(parser);

    if (status >= 300 && status < 400) {
        const location = respHeaders.find(([n]) => n === 'location')?.[1];
        if (location) {
            if (reusable) connectionManager.release(cfg, conn);
            else conn.close();
            const nextUrl = location.startsWith('/') ? `${parsed.protocol}//${parsed.hostname}:${parsed.port}${location}` : location;
            return fetchSync(nextUrl, onProgress, httpVersionOrOpts);
        }
    }

    if (reusable) connectionManager.release(cfg, conn);
    else conn.close();

    const body = mergeChunks(chunks);
    if (status < 200 || status >= 300) {
        dbg('http.fetch', () => `error headers: ${JSON.stringify(respHeaders)}`);
    }

    return { status, headers: respHeaders, body };
}

export function fetchText(url: string, httpVersion?: HttpVersion): string {
    const bytes = fetchBytes(url, undefined, httpVersion);
    return engine.decodeString(bytes);
}

/* ------------------------------------------------------------------ */
/* Async fetch                                                         */
/* ------------------------------------------------------------------ */

export async function fetchBytesAsync(url: string, onProgress?: ProgressCallback, httpVersionOrOpts?: HttpVersion | FetchOptions): Promise<Uint8Array> {
    const opts: FetchOptions | undefined = typeof httpVersionOrOpts === 'object' ? httpVersionOrOpts : undefined;
    const httpVersion: HttpVersion = typeof httpVersionOrOpts === 'string' ? httpVersionOrOpts : HttpVersion.HTTP11;
    const parsed = parseUrl(url);
    const cfg = connConfig(parsed);
    dbg('http.fetch', () => `→ ${opts?.method ?? 'GET'} ${url} (async)`);
    const conn = await connectionManager.acquireAsync(cfg);

    const headers = buildHeaders(parsed.hostname, httpVersion, opts);
    const builder = new HttpRequestBuilder({
        method: opts?.method ?? 'GET', path: parsed.path, host: parsed.hostname,
        httpVersion, headers, body: opts?.body ?? null,
    });
    const requestBytes = builder.build();
    await conn.writeAsync(requestBytes);

    const parser = new HttpResponseParser();
    const chunks: Uint8Array[] = [];
    let contentLength = 0;
    let loaded = 0;
    let parseError: Error | null = null;

    parser.onHeadersComplete = (status, hdrs) => {
        const cl = hdrs.find(([n]) => n === 'content-length');
        if (cl) contentLength = parseInt(cl[1]!, 10);
        dbg('http.fetch', () => `← ${status} (content-length: ${contentLength || 'unknown'}) ${url}`);
    };
    parser.onData = (chunk) => { chunks.push(chunk); loaded += chunk.length; onProgress?.(loaded, contentLength); };
    parser.onError = (e) => { parseError = e; };

    while (!parser.isCompleted && !parseError) {
        const d = await conn.readAsync(128 * 1024, true);
        if (!d) break;
        parser.feed(d);
    }

    if (parseError) {
        dbg('http.fetch', () => `parse error: ${parseError} ${url}`);
        conn.close(); throw parseError;
    }
    if (!parser.isCompleted) {
        conn.close();
        throw new Error(`Response not completed: ${url}`);
    }

    const status = parser.getStatusCode();
    const reusable = shouldKeepAlive(parser);
    if (status >= 300 && status < 400) {
        const location = parser.getHeaders().find(([n]) => n === 'location')?.[1];
        if (location) {
            if (reusable) connectionManager.release(cfg, conn);
            else conn.close();
            const nextUrl = location.startsWith('/') ? `${parsed.protocol}//${parsed.hostname}:${parsed.port}${location}` : location;
            dbg('http.fetch', () => `redirect ${status} → ${nextUrl}`);
            return fetchBytesAsync(nextUrl, onProgress, httpVersionOrOpts);
        }
    }

    if (reusable) connectionManager.release(cfg, conn);
    else conn.close();
    if (status < 200 || status >= 300) {
        const body = mergeChunks(chunks);
        dbg('http.fetch', () => `error headers: ${JSON.stringify(parser.getHeaders())}`);
        dbg('http.fetch', () => `error response: ${status} ${url}`);
        throw new Error(`HTTP ${status} ${url}`);
    }

    dbg('http.fetch', () => `done: ${loaded} bytes from ${url}`);
    return mergeChunks(chunks);
}

export async function fetchAsync(url: string, onProgress?: ProgressCallback, opts?: FetchOptions): Promise<{ body: Uint8Array }> {
    const bytes = await fetchBytesAsync(url, onProgress, opts);
    return { body: bytes };
}

export async function fetchTextAsync(url: string, httpVersion?: HttpVersion): Promise<string> {
    const bytes = await fetchBytesAsync(url, undefined, httpVersion);
    return engine.decodeString(bytes);
}
