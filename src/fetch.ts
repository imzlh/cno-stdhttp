/**
 * Simple HTTP client — built on h1.ts low-level primitives.
 *
 * This is a minimal fetch implementation for CTS compatibility.
 * For full Fetch API (Request/Response/Headers), use CNO's secondary wrapping layer.
 */

import { connectionManager } from "./connection";
import { HttpRequestBuilder, HttpResponseParser } from "./h1";
import { HttpVersion } from "./protocol";

const engine = import.meta.use("engine");

export type ProgressCallback = (now: number, total: number) => void;

const MAX_REDIRECTS = 8;

function parseUrl(url: string): { protocol: string; hostname: string; port: number; path: string } {
    const match = url.match(/^(https?):\/\/([^/:]+)(?::(\d+))?(\/.*)?$/);
    if (!match) throw new Error(`Invalid URL: ${url}`);
    return {
        protocol: match[1]!,
        hostname: match[2]!,
        port: match[3] ? parseInt(match[3]) : (match[1] === 'https' ? 443 : 80),
        path: match[4] ?? '/',
    };
}

/** Simple asynchronous fetch returning raw bytes. */
export async function fetchBytes(url: string, onProgress?: ProgressCallback, httpVersion: HttpVersion = HttpVersion.HTTP11): Promise<Uint8Array> {
    const parsed = parseUrl(url);
    const conn = await connectionManager.acquire({
        hostname: parsed.hostname,
        port: parsed.port,
        protocol: parsed.protocol as 'http:' | 'https:',
    });

    const headers: Array<[string, string]> = [
        ['host', parsed.hostname],
        ['user-agent', 'cnojs/http'],
        ['accept', '*/*'],
        ['connection', httpVersion === HttpVersion.HTTP10 ? 'close' : 'keep-alive'],
    ];

    const builder = new HttpRequestBuilder({
        method: 'GET', path: parsed.path, host: parsed.hostname,
        httpVersion, headers,
    });

    await conn.write(builder.build());

    const parser = new HttpResponseParser();
    const chunks: Uint8Array[] = [];
    let contentLength = 0;
    let loaded = 0;

    parser.onHeadersComplete = (status, hdrs) => {
        void status;
        const cl = hdrs.find(([n]) => n === 'content-length');
        if (cl) contentLength = parseInt(cl[1]!, 10);
    };
    parser.onData = (chunk) => { chunks.push(chunk); loaded += chunk.length; onProgress?.(loaded, contentLength); };

    while (!parser.isCompleted) {
        const d = await conn.read(128 * 1024);
        if (!d) break;
        parser.feed(d);
    }

    connectionManager.release({
        hostname: parsed.hostname,
        port: parsed.port,
        protocol: parsed.protocol as 'http:' | 'https:',
    }, conn);

    // Merge chunks
    const total = chunks.reduce((s, c) => s + c.length, 0);
    const result = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) { result.set(c, off); off += c.length; }
    return result;
}

/** Async fetch. */
export async function fetchAsync(url: string, onProgress?: ProgressCallback, httpVersion: HttpVersion = HttpVersion.HTTP11): Promise<{ body: Uint8Array }> {
    const parsed = parseUrl(url);
    const conn = await connectionManager.acquire({
        hostname: parsed.hostname,
        port: parsed.port,
        protocol: parsed.protocol as 'http:' | 'https:',
    });

    const headers: Array<[string, string]> = [
        ['host', parsed.hostname],
        ['user-agent', 'cnojs/http'],
        ['accept', '*/*'],
        ['connection', httpVersion === HttpVersion.HTTP10 ? 'close' : 'keep-alive'],
    ];

    const builder = new HttpRequestBuilder({
        method: 'GET', path: parsed.path, host: parsed.hostname,
        httpVersion, headers,
    });

    await conn.write(builder.build());

    const parser = new HttpResponseParser();
    const chunks: Uint8Array[] = [];
    let contentLength = 0;
    let loaded = 0;

    parser.onHeadersComplete = (status, hdrs) => {
        void status;
        const cl = hdrs.find(([n]) => n === 'content-length');
        if (cl) contentLength = parseInt(cl[1]!, 10);
    };
    parser.onData = (chunk) => { chunks.push(chunk); loaded += chunk.length; onProgress?.(loaded, contentLength); };

    while (!parser.isCompleted) {
        const d = await conn.read(128 * 1024);
        if (!d) break;
        parser.feed(d);
    }

    connectionManager.release({
        hostname: parsed.hostname,
        port: parsed.port,
        protocol: parsed.protocol as 'http:' | 'https:',
    }, conn);

    const total = chunks.reduce((s, c) => s + c.length, 0);
    const result = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) { result.set(c, off); off += c.length; }
    return { body: result };
}

/** Simple text decode. */
export async function fetchText(url: string, httpVersion?: HttpVersion): Promise<string> {
    const bytes = await fetchBytes(url, undefined, httpVersion);
    return engine.decodeString(bytes as Uint8Array<ArrayBuffer>);
}
