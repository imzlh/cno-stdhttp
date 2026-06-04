/**
 * CNO HTTP fetch helpers backed by the native curl module.
 *
 * This file intentionally preserves the small @cnojs/http/fetch API while
 * delegating ordinary client requests to libcurl. Raw connection primitives in
 * connection.ts/h1.ts are still used by server, SSE, and WebSocket upgrade code.
 */

import { HttpVersion } from "./protocol";
import { dbg } from "./debug";

const curlMod = import.meta.use("curl") as typeof CModuleCURL;
const engine = import.meta.use("engine");

export type ProgressCallback = (now: number, total: number) => void;

export interface FetchOptions {
    method?: string;
    headers?: Record<string, string>;
    body?: Uint8Array | null;
    timeout?: number;
    signal?: AbortSignal;
}

type Uint8Array = globalThis.Uint8Array<ArrayBuffer>;

interface FetchResult {
    status: number;
    headers: Array<[string, string]>;
    body: Uint8Array;
}

let curlPool: CModuleCURL.ConnPool | null = null;

function getCurlPool(): CModuleCURL.ConnPool {
    if (!curlPool) {
        curlPool = new curlMod.ConnPool({
            maxConnections: 64,
            maxConnectionsPerHost: 8,
            pipelining: true,
        });
    }
    return curlPool;
}

function abortError(signal?: AbortSignal): any {
    return signal?.reason ?? new DOMException("The operation was aborted", "AbortError");
}

function throwIfAborted(signal?: AbortSignal): void {
    if (signal?.aborted) throw abortError(signal);
}

function getOptions(httpVersionOrOpts?: HttpVersion | FetchOptions): FetchOptions | undefined {
    return typeof httpVersionOrOpts === "object" ? httpVersionOrOpts : undefined;
}

function getHttpVersion(httpVersionOrOpts?: HttpVersion | FetchOptions): HttpVersion {
    return typeof httpVersionOrOpts === "string" ? httpVersionOrOpts : HttpVersion.HTTP11;
}

function toCurlHttpVersion(version: HttpVersion): "1.0" | "1.1" | "2" | "3" {
    switch (version) {
        case HttpVersion.HTTP10: return "1.0";
        case HttpVersion.HTTP2: return "2";
        case HttpVersion.HTTP3: return "3";
        case HttpVersion.HTTP11:
        default: return "1.1";
    }
}

function hasHeader(headers: Record<string, string>, name: string): boolean {
    const lower = name.toLowerCase();
    for (const key of Object.keys(headers)) {
        if (key.toLowerCase() === lower) return true;
    }
    return false;
}

function buildHeaders(opts?: FetchOptions): Record<string, string> {
    const headers: Record<string, string> = { ...(opts?.headers ?? {}) };
    if (!hasHeader(headers, "user-agent")) headers["User-Agent"] = "cnojs/http";
    if (!hasHeader(headers, "accept")) headers["Accept"] = "*/*";
    return headers;
}

function bodyToCurlValue(body: Uint8Array): ArrayBuffer {
    return body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) as ArrayBuffer;
}

function responseBodyToBytes(body?: ArrayBuffer): Uint8Array {
    if (!body) return new Uint8Array(0);
    return new Uint8Array(body) as Uint8Array;
}

function resolveRedirectUrl(base: string, location: string): string {
    try { return new URL(location, base).href; }
    catch { return location; }
}

function parseHeaders(raw: string): Array<[string, string]> {
    let current: Array<[string, string]> = [];
    let last: [string, string] | null = null;

    for (const line of raw.split(/\r?\n/)) {
        if (!line) continue;
        if (/^HTTP\//i.test(line)) {
            current = [];
            last = null;
            continue;
        }

        if ((line[0] === " " || line[0] === "\t") && last) {
            last[1] += " " + line.trim();
            continue;
        }

        const colon = line.indexOf(":");
        if (colon <= 0) continue;
        const header: [string, string] = [line.slice(0, colon).trim().toLowerCase(), line.slice(colon + 1).trim()];
        current.push(header);
        last = header;
    }

    return current;
}

function configureCurl(
    curl: CModuleCURL.CURL,
    url: string,
    onProgress: ProgressCallback | undefined,
    httpVersionOrOpts: HttpVersion | FetchOptions | undefined,
): void {
    const opts = getOptions(httpVersionOrOpts);
    const httpVersion = getHttpVersion(httpVersionOrOpts);
    const method = (opts?.method ?? "GET").toUpperCase();

    curl.setUrl(url)
        .setMethod(method)
        .setHeaders(buildHeaders(opts))
        .setFollowRedirects(true)
        .setMaxRedirects(20)
        .setHTTPVersion(toCurlHttpVersion(httpVersion))
        .setAcceptEncoding();

    const postRedirectAll = curlMod.constants.CURL_REDIR_POST_ALL;
    if (typeof postRedirectAll === "number") {
        curl.setOptByName("POSTREDIR", postRedirectAll);
    }

    if (typeof opts?.timeout === "number" && Number.isFinite(opts.timeout) && opts.timeout > 0) {
        curl.setTimeout(opts.timeout);
        curl.setConnectTimeout(opts.timeout);
    }

    if (opts?.body !== undefined && opts.body !== null) {
        curl.setBody(bodyToCurlValue(opts.body));
    }

    if (onProgress) {
        curl.onProgress((dltotal, dlnow) => {
            onProgress(Number(dlnow), Number(dltotal));
            return true;
        });
    }
}

function normalizeCurlError(error: any, url: string, signal?: AbortSignal): any {
    if (signal?.aborted) return abortError(signal);
    if (error instanceof Error) return error;
    if (error?.message) return new Error(String(error.message));
    return new Error(`HTTP request failed: ${url}`);
}

function performSync(url: string, onProgress: ProgressCallback | undefined, httpVersionOrOpts: HttpVersion | FetchOptions | undefined): FetchResult {
    const opts = getOptions(httpVersionOrOpts);
    throwIfAborted(opts?.signal);
    const curl = new curlMod.CURL(getCurlPool());
    configureCurl(curl, url, onProgress, httpVersionOrOpts);
    dbg("http.fetch", () => `curl ${opts?.method ?? "GET"} ${url}`);

    try {
        const response = curl.performSync();
        throwIfAborted(opts?.signal);
        return {
            status: response.status,
            headers: parseHeaders(response.headers),
            body: responseBodyToBytes(response.body),
        };
    } catch (error) {
        throw normalizeCurlError(error, url, opts?.signal);
    }
}

async function performAsync(url: string, onProgress: ProgressCallback | undefined, httpVersionOrOpts: HttpVersion | FetchOptions | undefined): Promise<FetchResult> {
    const opts = getOptions(httpVersionOrOpts);
    throwIfAborted(opts?.signal);
    const curl = new curlMod.CURL(getCurlPool());
    configureCurl(curl, url, onProgress, httpVersionOrOpts);
    dbg("http.fetch", () => `curl ${opts?.method ?? "GET"} ${url} (async)`);

    let abortHandler: (() => void) | null = null;
    try {
        if (opts?.signal) {
            abortHandler = () => { try { curl.abort(); } catch {} };
            opts.signal.addEventListener("abort", abortHandler, { once: true });
        }

        const response = await curl.perform();
        throwIfAborted(opts?.signal);
        return {
            status: response.status,
            headers: parseHeaders(response.headers),
            body: responseBodyToBytes(response.body),
        };
    } catch (error) {
        throw normalizeCurlError(error, url, opts?.signal);
    } finally {
        if (opts?.signal && abortHandler) opts.signal.removeEventListener("abort", abortHandler);
    }
}

function assertOk(result: FetchResult, url: string): void {
    if (result.status < 200 || result.status >= 300) {
        dbg("http.fetch", () => `error headers: ${JSON.stringify(result.headers)}`);
        dbg("http.fetch", () => `error response: ${result.status} ${url}`);
        throw new Error(`HTTP ${result.status} ${url}`);
    }
}

export function fetchBytes(url: string, onProgress?: ProgressCallback, httpVersionOrOpts?: HttpVersion | FetchOptions): Uint8Array {
    const result = performSync(url, onProgress, httpVersionOrOpts);
    assertOk(result, url);
    dbg("http.fetch", () => `done: ${result.body.length} bytes from ${url}`);
    return result.body;
}

export function fetchSync(url: string, onProgress?: ProgressCallback, httpVersionOrOpts?: HttpVersion | FetchOptions): { status: number; headers: Array<[string, string]>; body: Uint8Array } {
    return performSync(url, onProgress, httpVersionOrOpts);
}

export function fetchText(url: string, httpVersion?: HttpVersion): string {
    return engine.decodeString(fetchBytes(url, undefined, httpVersion));
}

export async function fetchBytesAsync(url: string, onProgress?: ProgressCallback, httpVersionOrOpts?: HttpVersion | FetchOptions): Promise<Uint8Array> {
    const result = await performAsync(url, onProgress, httpVersionOrOpts);
    assertOk(result, url);
    dbg("http.fetch", () => `done: ${result.body.length} bytes from ${url}`);
    return result.body;
}

export async function fetchAsync(url: string, onProgress?: ProgressCallback, opts?: FetchOptions): Promise<{ body: Uint8Array }> {
    const body = await fetchBytesAsync(url, onProgress, opts);
    return { body };
}

export async function fetchTextAsync(url: string, httpVersion?: HttpVersion): Promise<string> {
    return engine.decodeString(await fetchBytesAsync(url, undefined, httpVersion));
}

export function closeCurlPool(): void {
    const pool = curlPool;
    curlPool = null;
    pool?.close();
}
