/**
 * HTTP/1.x protocol implementation —low-level, no WebAPI dependencies.
 *
 * Handles:
 * - Request building (from raw strings/bytes, no URL/Headers types)
 * - Response parsing (incremental, llhttp-based)
 * - Server-side request parsing + response writing (H1ServerConnection)
 * - Client-side request/response (H1ClientConnection)
 * - Content-Encoding negotiation, keep-alive, chunked transfer encoding
 *
 * NO WebAPI types (URL, Headers, Request, Response, ReadableStream, Blob, etc.).
 * All I/O is via raw bytes and callbacks. CNO's secondary wrapping layer
 * maps WebAPI types onto this low-level API.
 */

const http = import.meta.use("http");
const engine = import.meta.use("engine");
const error = import.meta.use("error");

import { TcpSocket } from "./socket";
import {
    type ProtocolClient, type ProtocolServer, type ProtocolConnection,
    type ProtocolStream, type RawRequest, type RawResponse,
    type ProtocolClientConfig, type ProtocolServerConfig,
    type ProtocolConnectionEvents,
    HttpVersion, ALPN,
} from "./protocol";
import { StreamingDecompressor } from "./zlib";
import {
    encodeResponseHead,
    encodeRequestHead,
    encodeChunkedFrame,
    encodeChunkedTrailer,
    wantsKeepAlive,
    connectionTokens,
} from "./h1-frame";
import { assert } from "../utils/assert";

type Uint8Array = globalThis.Uint8Array<ArrayBuffer>;

/**
 * Hard ceiling on request-body bytes held for a server handler that is not draining
 * them. Mirrors the HTTP/2 cap of the same name in h2.ts so both protocols refuse the
 * same flood. Reaching this means nothing is consuming the body, so the connection is
 * failed rather than grown: a handler that *does* drain never gets near it, because
 * BODY_HIGH_WATER_MARK stops us reading the socket long before.
 */
const MAX_BUFFERED_BODY_BYTES = 16 * 1024 * 1024;

/**
 * Stop reading the socket once this many undelivered body bytes are queued, and resume
 * at BODY_RESUME_MARK. This is the actual flow control: not reading leaves the bytes in
 * the kernel receive buffer, which closes the TCP window and makes the peer wait.
 */
const BODY_HIGH_WATER_MARK = 1024 * 1024;
const BODY_RESUME_MARK = 256 * 1024;

function toByteView(buf: CModuleHTTP.BufferSource): Uint8Array {
    if (buf instanceof ArrayBuffer) return new Uint8Array(buf);
    return new Uint8Array(new globalThis.Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength));
}

function decodeParserBytes(buf: CModuleHTTP.BufferSource, off: number, len: number): string {
    return engine.decodeString(toByteView(buf).slice(off, off + len));
}

// RFC 9112 permits coding lists only when chunked is the final non-empty token.
export function isChunkedEncoding(transferEncoding: string | undefined | null): boolean {
    if (!transferEncoding) return false;
    const codings = transferEncoding.split(',').map(c => c.trim().toLowerCase()).filter(Boolean);
    return codings.length > 0 && codings[codings.length - 1] === 'chunked';
}

// RFC 7230 §3.2.4: header names/values must not contain CR/LF/NUL. Rejects at parse time.
function validateHeader(name: string, value: string): void {
    if (/[\r\n\0]/.test(name) || /[\r\n\0]/.test(value)) {
        throw new Error(`invalid header: ${JSON.stringify(name)}`);
    }
}

// Parses Content-Length with strict validation: single finite non-negative integer.
// Returns -1 on any malformed value (negative, non-numeric, multiple headers).
function parseContentLength(clHeader: string | undefined, reqHeaders: Array<[string, string]>): number {
    if (clHeader === undefined) return -1;
    const count = reqHeaders.filter(([n]) => n === 'content-length').length;
    if (count > 1) return -1;
    const v = clHeader.trim();
    if (!/^\d+$/.test(v)) return -1;
    const n = Number(v);
    if (!Number.isSafeInteger(n) || n < 0) return -1;
    return n;
}

/* ------------------------------------------------------------------ */
/* HTTP/1.x Request Builder (low-level: strings + bytes, no URL/Headers) */
/* ------------------------------------------------------------------ */

export interface H1RequestOptions {
    method?: string;
    path?: string;
    host?: string;
    httpVersion?: string;
    headers?: Array<[string, string]>;
    body?: Uint8Array | null;
    useFullUrl?: string;
}

export class HttpRequestBuilder {
    private method: string = 'GET';
    private path: string = '/';
    private host: string = '';
    private headers: Array<[string, string]> = [];
    private body: Uint8Array | null = null;
    private useFullUrl: string | null = null;
    private httpVersion: string = '1.1';

    static DEFAULT_HEADERS: Array<[string, string]> = [
        ['accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'],
        ['accept-language', 'zh-CN,zh;q=0.9'],
        ['user-agent', 'cnojs/http'],
    ];

    constructor(options?: H1RequestOptions) {
        if (options?.method) this.method = options.method.toUpperCase();
        if (options?.path) this.path = options.path;
        if (options?.host) this.host = options.host;
        if (options?.httpVersion) this.httpVersion = options.httpVersion;
        if (options?.headers) this.headers = [...options.headers];
        if (options?.body !== undefined && options?.body !== null) this.body = options.body;
        if (options?.useFullUrl) this.useFullUrl = options.useFullUrl;
    }

    setHeader(name: string, value: string): void { this.headers.push([name.toLowerCase(), value]); }
    setBody(data: Uint8Array): void { this.body = data; }

    build(): Uint8Array {
        if (!this.host) this.host = 'localhost';
        if (!this.headers.find(([n]) => n === 'host')) this.setHeader('host', this.host);
        if (this.body && !this.headers.find(([n]) => n === 'content-length'))
            this.setHeader('content-length', String(this.body.length));
        for (const [k, v] of HttpRequestBuilder.DEFAULT_HEADERS) {
            if (!this.headers.find(([n]) => n === k)) this.headers.push([k, v]);
        }
        if (!this.headers.find(([n]) => n === 'connection')) {
            this.setHeader(
                'connection',
                wantsKeepAlive(this.httpVersion, null) ? 'keep-alive' : 'close',
            );
        }

        const path = this.useFullUrl ?? this.path;
        const headerBytes = encodeRequestHead(
            this.method,
            path,
            this.httpVersion,
            this.headers.filter(([k, v]) => Boolean(k && v)),
        );
        if (this.body) {
            const combined = new Uint8Array(headerBytes.length + this.body.length);
            combined.set(headerBytes, 0); combined.set(this.body, headerBytes.length);
            return combined;
        }
        return headerBytes;
    }

    getHeaders(): Array<[string, string]> { return this.headers; }
    getBody(): Uint8Array | null { return this.body; }
}

interface PreparedH1Request {
    head: Uint8Array;
    chunked: boolean;
    contentLength: number | null;
    hasBody: boolean;
}

function prepareH1Request(req: RawRequest): PreparedH1Request {
    const headers = req.headers.map(([name, value]) => [name.toLowerCase(), value] as [string, string]);
    const values = (name: string): string[] => headers
        .filter(([header]) => header === name)
        .map(([, value]) => value);
    const contentLengths = values('content-length');
    if (contentLengths.length > 1) throw new Error('invalid Content-Length');
    let contentLength: number | null = null;
    if (contentLengths.length === 1) {
        const value = contentLengths[0]!.trim();
        if (!/^\d+$/.test(value) || !Number.isSafeInteger(Number(value))) {
            throw new Error('invalid Content-Length');
        }
        contentLength = Number(value);
    }

    const transferEncodings = values('transfer-encoding');
    if (transferEncodings.length > 1) throw new Error('invalid Transfer-Encoding');
    let chunked = false;
    if (transferEncodings.length === 1) {
        if (contentLength !== null || !isChunkedEncoding(transferEncodings[0])) {
            throw new Error('unsupported or ambiguous Transfer-Encoding');
        }
        chunked = true;
    }

    const hasBody = req.body !== null;
    if (!hasBody && contentLength !== null && contentLength !== 0) {
        throw new Error('Content-Length requires a request body');
    }
    const httpVersion = req.httpVersion === '1.0' ? '1.0' : '1.1';
    if (hasBody && contentLength === null && !chunked) {
        if (httpVersion === '1.0') {
            throw new Error('HTTP/1.0 streaming request requires Content-Length');
        }
        headers.push(['transfer-encoding', 'chunked']);
        chunked = true;
    }
    if (chunked && httpVersion === '1.0') {
        throw new Error('chunked transfer encoding requires HTTP/1.1');
    }

    const builder = new HttpRequestBuilder({ method: req.method, path: req.url, httpVersion });
    for (const [name, value] of headers) builder.setHeader(name, value);
    return { head: builder.build(), chunked, contentLength, hasBody };
}

class H1ClientRequest {
    private bodyBytes = 0;
    private ended = false;
    private responseRead = false;
    private released = false;

    constructor(
        private readonly conn: H1ClientConnection,
        private readonly framing: PreparedH1Request,
        private readonly releaseSlot: () => void,
    ) {}

    async writeData(chunk: globalThis.Uint8Array): Promise<void> {
        if (this.ended) throw new Error('request body already ended');
        if (!this.framing.hasBody && this.framing.contentLength === null && !this.framing.chunked) {
            throw new Error('request body was not declared');
        }
        const data = toByteView(chunk as CModuleHTTP.BufferSource);
        if (data.byteLength === 0) return;
        this.bodyBytes += data.byteLength;
        if (this.framing.contentLength !== null && this.bodyBytes > this.framing.contentLength) {
            const err = new Error('request body exceeds Content-Length');
            this.abort();
            throw err;
        }
        try {
            await this.conn.writeRequestBytes(this.framing.chunked ? encodeChunkedFrame(data) : data);
        } catch (err) {
            this.abort();
            throw err;
        }
    }

    async end(chunk?: globalThis.Uint8Array): Promise<void> {
        if (this.ended) throw new Error('request body already ended');
        if (chunk !== undefined) await this.writeData(chunk);
        if (this.framing.contentLength !== null && this.bodyBytes !== this.framing.contentLength) {
            const err = new Error('request body does not match Content-Length');
            this.abort();
            throw err;
        }
        try {
            if (this.framing.chunked) await this.conn.writeRequestBytes(encodeChunkedTrailer());
            this.ended = true;
        } catch (err) {
            this.abort();
            throw err;
        }
    }

    async readResponse(): Promise<RawResponse> {
        if (!this.ended) throw new Error('request body has not ended');
        if (this.responseRead) throw new Error('response already read');
        this.responseRead = true;
        try {
            return await this.conn.readResponse();
        } catch (err) {
            this.abort();
            throw err;
        } finally {
            this.release();
        }
    }

    abort(): void {
        this.ended = true;
        this.conn.close();
        this.release();
    }

    /** Mark a connection close as terminal without recursing through `abort()`. */
    connectionClosed(): void {
        this.ended = true;
        this.release();
    }

    get isEnded(): boolean { return this.ended; }

    private release(): void {
        if (this.released) return;
        this.released = true;
        this.releaseSlot();
    }
}

/* ------------------------------------------------------------------ */
/* HTTP/1.x Response Parser (incremental, llhttp-based)               */
/* ------------------------------------------------------------------ */

export class HttpResponseParser {
    private parser: CModuleHTTP.Parser;
    private statusCode: number = 0;
    private statusText: string = '';
    private httpVersion: string = '1.1';
    private headers: Array<[string, string]> = [];
    private currentHeaderField: string = '';
    private currentHeaderValue: string | null = null;
    private bodyChunks: Uint8Array[] = [];
    private completed: boolean = false;
    private headersComplete: boolean = false;
    private interimResponse: boolean = false;
    private interimOnly = false;
    private decompressor: StreamingDecompressor | null = null;

    public onHeadersComplete?: (statusCode: number, headers: Array<[string, string]>) => void;
    public onData?: (chunk: Uint8Array) => void;
    public onComplete?: () => void;
    public onError?: (error: Error) => void;

    constructor() { this.parser = new http.Parser(http.RESPONSE); this.setupCallbacks(); }

    private setupCallbacks(): void {
        this.parser.onMessageBegin = () => {
            this.statusCode = 0; this.statusText = ''; this.headers = [];
            this.currentHeaderField = ''; this.currentHeaderValue = null;
            this.headersComplete = false; this.interimResponse = false;
            this.decompressor = null;
        };
        this.parser.onStatus = (buf, off, len) => {
            this.statusText += decodeParserBytes(buf, off, len);
        };
        this.parser.onHeaderField = (buf, off, len) => {
            if (this.currentHeaderValue !== null) this.commitHeader();
            this.currentHeaderField += decodeParserBytes(buf, off, len);
        };
        this.parser.onHeaderValue = (buf, off, len) => {
            this.currentHeaderValue = (this.currentHeaderValue ?? '') + decodeParserBytes(buf, off, len);
        };
        this.parser.onHeadersComplete = () => {
            this.commitHeader();
            const nextStatus = this.parser.state.status;
            if (this.interimResponse && nextStatus >= 200) {
                this.statusText = '';
                this.headers = [];
                this.currentHeaderField = ''; this.currentHeaderValue = null;
            }
            this.statusCode = nextStatus; this.headersComplete = true;
            this.interimOnly = false;
            if (!this.statusText) this.statusText = strstatus(this.statusCode);
            this.interimResponse = this.statusCode >= 100 && this.statusCode < 200 && this.statusCode !== 101;
            const major = this.parser.state.httpMajor ?? 1;
            const minor = this.parser.state.httpMinor ?? 1;
            this.httpVersion = `${major}.${minor}`;
            if (!this.interimResponse) {
                const ce = this.headers.find(([n]) => n === 'content-encoding');
                if (ce) this.decompressor = new StreamingDecompressor(ce[1]);
                this.onHeadersComplete?.(this.statusCode, this.headers);
            }
        };
        this.parser.onBody = (buf, off, len) => {
            let view = toByteView(buf).slice(off, off + len);
            if (this.decompressor?.isActive) view = this.decompressor.decompress(view);
            if (!this.onData) this.bodyChunks.push(view);
            this.onData?.(view);
        };
        this.parser.onMessageComplete = () => {
            if (this.interimResponse) {
                // 1xx responses are informational; llhttp continues parsing the
                // final response on the same connection/buffer.
                this.statusCode = 0; this.statusText = ''; this.headers = [];
                this.currentHeaderField = ''; this.currentHeaderValue = null;
                this.headersComplete = false; this.interimResponse = false;
                this.decompressor = null;
                this.interimOnly = true;
                return;
            }
            // Trailer validation turns compressed truncation into an error.
            try {
                const tail = this.decompressor?.finish() ?? new Uint8Array(0);
                if (tail.length > 0) {
                    if (!this.onData) this.bodyChunks.push(tail);
                    this.onData?.(tail);
                }
            } catch (err) {
                const e = err instanceof Error ? err : new Error(String(err));
                if (this.onError) { this.onError(e); return; }
                throw e;
            }
            this.completed = true; this.onComplete?.();
            // Preserve bytes belonging to a pipelined or upgraded message.
            this.parser.pause();
        };
    }

    private commitHeader(): void {
        if (this.currentHeaderValue === null) return;
        const name = this.currentHeaderField.toLowerCase();
        const value = this.currentHeaderValue;
        validateHeader(name, value);
        this.headers.push([name, value]);
        this.currentHeaderField = '';
        this.currentHeaderValue = null;
    }

    feed(data: Uint8Array): CModuleHTTP.ParserExecuteResult | undefined {
        try {
            const result = this.parser.execute(data.buffer.slice(data.byteOffset, data.byteLength + data.byteOffset));
            if (result.errno !== 0) {
                if (result.name === 'HPE_PAUSED' || result.name === 'HPE_PAUSED_UPGRADE') return result;
                const e = new Error(`HTTP parse error: ${result.reason}`); if (this.onError) this.onError(e); else throw e;
            }
            // Reset only when an informational response occupied this buffer alone.
            if (this.interimOnly && !this.headersComplete) {
                this.parser.reset(http.RESPONSE);
                this.setupCallbacks();
                this.statusCode = 0; this.statusText = ''; this.headers = [];
                this.currentHeaderField = ''; this.currentHeaderValue = null;
                this.completed = false; this.headersComplete = false;
                this.interimOnly = false;
            }
            return result;
        } catch (err) { if (this.onError) this.onError(err as Error); else throw err; }
    }

    /**
     * Signal EOF. A response with neither Content-Length nor chunked encoding is
     * terminated by the close itself, so llhttp only completes such a message once
     * told the stream ended. Leaves `isCompleted` false when EOF truncated a framed
     * body, so the caller can treat that as the error it is.
     */
    finishOnEof(): void {
        try {
            this.parser.finish();
        } catch { /* llhttp rejected the EOF state; isCompleted stays false */ }
    }

    getStatusCode(): number { assert(this.statusCode, "Response not completed"); return this.statusCode; }
    getHttpVersion(): string { return this.httpVersion; }
    get isHttp10(): boolean { return this.httpVersion === '1.0'; }
    getStatusText(): string { assert(this.statusCode, "Response not completed"); return this.statusText || "Unknown"; }
    getHeaders(): Array<[string, string]> { assert(this.statusCode, "Response not completed"); return this.headers; }
    getBodyChunks(): Uint8Array[] { const t = this.bodyChunks; this.bodyChunks = []; return t; }
    get isCompleted(): boolean { return this.completed; }
    get isHeadersComplete(): boolean { return this.headersComplete; }

    reset(): void {
        this.parser.reset(http.RESPONSE); this.statusCode = 0; this.statusText = '';
        this.httpVersion = '1.1'; this.headers = []; this.bodyChunks = [];
        this.currentHeaderField = ''; this.currentHeaderValue = null;
        this.completed = false; this.headersComplete = false;
        this.interimResponse = false;
        this.interimOnly = false;
        this.decompressor = null; this.onComplete = this.onData = this.onError = this.onHeadersComplete = undefined;
    }
}

/* ------------------------------------------------------------------ */
/* H1 Stream                                                          */
/* ------------------------------------------------------------------ */

class H1Stream implements ProtocolStream {
    readonly id: number | string = 0;
    private conn: H1ServerConnection | H1ClientConnection;
    private isServer: boolean;
    private clientRequest: H1ClientRequest | null = null;
    private clientHeadStarted = false;
    private clientFinished = false;
    constructor(conn: H1ServerConnection | H1ClientConnection, isServer: boolean) { this.conn = conn; this.isServer = isServer; }

    async writeHead(data: RawRequest | RawResponse): Promise<void> {
        if (this.isServer) {
            const res = data as RawResponse;
            await (this.conn as H1ServerConnection).writeHead(res.status, res.statusText, res.headers);
        } else {
            if (this.clientHeadStarted || this.clientFinished) {
                throw new Error('request headers already sent');
            }
            this.clientHeadStarted = true;
            this.clientRequest = await (this.conn as H1ClientConnection).beginRequest(data as RawRequest);
        }
    }
    async writeData(data: Uint8Array): Promise<void> {
        if (this.isServer) await (this.conn as H1ServerConnection).writeData(data);
        else {
            if (!this.clientRequest) throw new Error('request headers have not been sent');
            await this.clientRequest.writeData(data);
        }
    }
    async end(data?: Uint8Array): Promise<void> {
        if (this.isServer) await (this.conn as H1ServerConnection).endResponse(data);
        else {
            if (!this.clientRequest) throw new Error('request headers have not been sent');
            await this.clientRequest.end(data);
        }
    }
    async readMessage(): Promise<RawRequest | RawResponse> {
        if (this.isServer) return (this.conn as H1ServerConnection).readRequest();
        if (!this.clientRequest) throw new Error('request headers have not been sent');
        const response = await this.clientRequest.readResponse();
        this.clientRequest = null;
        this.clientFinished = true;
        return response;
    }
    abort(code?: number): void { this.conn.close(); }
    close(): void { this.conn.close(); }
}

/* ------------------------------------------------------------------ */
/* H1 Server Connection                                               */
/* ------------------------------------------------------------------ */

export class H1ServerConnection implements ProtocolConnection {
    readonly version = HttpVersion.HTTP11;
    readonly secure: boolean;
    readonly socket: TcpSocket;
    /** Idle keep-alive timeout (ms); Node emits Keep-Alive: timeout=<sec> from this. */
    private keepAliveTimeoutMs: number;
    private maxHeadersCount: number;
    /** Byte budget for the whole head (request line + field names + values). */
    private maxHeaderSize: number;
    /** Head bytes seen so far this request; compared against maxHeaderSize incrementally. */
    private headerBytes = 0;
    private parser: CModuleHTTP.Parser;
    private method = ''; private url = ''; private reqHeaders: Array<[string, string]> = [];
    private headerField = ''; private headerValue: string | null = null; private headersOk = false;
    private expectBody = false; private contentLength = 0; private chunked = false;
    private bodyRead = 0;
    private headersSent = false; private responseEnded = false; private chunkedEncoding = false;
    /** The single in-flight response termination, shared by concurrent/reentrant callers. */
    private responseEndPromise: Promise<void> | null = null;
    private responseBodyBytes = 0;
    private responseContentLength: number | null = null;
    /** Response has explicit framing (chunked, content-length, or bodyless status/HEAD). */
    private responseFramed = false;
    /** RFC 9112 §6.3: HEAD / 1xx / 204 / 205 / 304 end at the header block. */
    private bodyless = false;
    /** Header-block fault (oversized headers, bad framing) — answer 400, never run the handler. */
    private requestError: Error | null = null;
    /** Status to answer a rejected header block with (431 for an oversized head). */
    private requestErrorStatus = 400;
    /** Chunked trailer fields; kept out of reqHeaders so they cannot forge request headers. */
    private trailers: Array<[string, string]> = [];
    /** Server loop said this is the last request — response must announce Connection: close. */
    private forceClose = false;
    private requestCount = 0; private keepAlive = true; private requestHttpVersion = '1.1';
    private _closed = false;
    private _upgraded = false;
    /** Subscribers notified exactly once when the H1 transport reaches terminal close. */
    private terminalCloseListeners = new Set<() => void>();
    private upgradeLeftover: Uint8Array | null = null;
    private pendingInput: Uint8Array | null = null;
    private events: ProtocolConnectionEvents = { onstream: null, onError: null, onClose: null, onGoaway: null, onSettings: null };
    private bodyChunk: Uint8Array[] = [];
    /** Undelivered bytes sitting in bodyChunk; drives backpressure and the hard cap. */
    private bufferedBody = 0;
    /** True once the handler has polled req.body() at least once — i.e. a real consumer exists. */
    private bodyPolled = false;
    /** Resolved when the queue drains below BODY_RESUME_MARK, so the read loop can continue. */
    private drainWaiter: PromiseWithResolvers<void> | null = null;
    private pendingPromise: PromiseWithResolvers<Uint8Array | null> | null = null;
    private bodyError: Error | null = null;
    /** Peer/transport fault observed on read — writers must see the same coded error. */
    private transportError: Error | null = null;
    private ended = false;
    /** True while a request handler is parsing, reading, or writing. */
    private requestInProgress = false;

    constructor(socket: TcpSocket, secure: boolean, keepAliveTimeoutMs = 5000, maxHeadersCount: number = 2000, maxHeaderSize: number = 16384) {
        this.socket = socket;
        this.secure = secure;
        this.keepAliveTimeoutMs = keepAliveTimeoutMs;
        this.maxHeadersCount = maxHeadersCount;
        this.maxHeaderSize = maxHeaderSize;
        this.parser = new http.Parser(http.REQUEST);
        this.setupParser();
    }

    isClosed(): boolean { return this._closed; }

    /** Subscribe to terminal H1 transport close. Late subscribers run once immediately. */
    onTerminalClose(listener: () => void): () => void {
        if (this._closed) {
            listener();
            return () => {};
        }
        this.terminalCloseListeners.add(listener);
        return () => this.terminalCloseListeners.delete(listener);
    }

    /** Stop keep-alive reuse; close now only when no request is active. */
    beginDrain(): void {
        this.forceClose = true;
        this.keepAlive = false;
        // Node's server.close() stops HTTP keep-alive reuse but does not own
        // upgraded sockets. Force shutdown still reaches close() directly.
        if (!this._upgraded && !this.requestInProgress) this.close();
    }

    private peerClosedError(): Error {
        return error.Error(error.errno.EOF);
    }

    private markTransportError(err: Error): void {
        if (!this.transportError) this.transportError = err;
    }

    private throwIfTransportDead(): void {
        if (this._closed) throw this.transportError ?? this.peerClosedError();
        if (this.transportError) throw this.transportError;
    }

    private enqueue(u8: Uint8Array) {
        const pending = this.pendingPromise;
        if (pending) {
            this.pendingPromise = null;
            pending.resolve(u8);
            return;
        }
        // Account retained bytes even before a consumer starts reading.
        this.bodyChunk.push(u8);
        this.bufferedBody += u8.byteLength;
    }

    /** Let the read loop continue once the consumer has taken enough out of the queue. */
    private wakeDrain(): void {
        const w = this.drainWaiter;
        if (w && this.bufferedBody <= BODY_RESUME_MARK) {
            this.drainWaiter = null;
            w.resolve();
        }
    }

    /** Release retained body bytes; the body is being failed and nothing will read them. */
    private discardBody(): void {
        this.bodyChunk = [];
        this.bufferedBody = 0;
        const w = this.drainWaiter;
        if (w) { this.drainWaiter = null; w.resolve(); }
    }

    private finishBody(): void {
        this.ended = true;
        const w = this.drainWaiter;
        if (w) { this.drainWaiter = null; w.resolve(); }
        const pending = this.pendingPromise;
        if (pending) {
            this.pendingPromise = null;
            pending.resolve(null);
        }
    }

    private failBody(err: Error): void {
        this.markTransportError(err);
        // A peer close before declared body completion is truncation, not clean EOF.
        if (TcpSocket.isDisconnectError(err) && !this.bodyIncomplete()) {
            this.discardBody();
            this.finishBody();
            return;
        }
        if (TcpSocket.isDisconnectError(err)) {
            // Reject only an existing body waiter, avoiding unhandled rejections.
            err = Object.assign(
                new Error('request body truncated: peer closed before the declared body length'),
                { code: 'ECONNRESET' },
            );
        }
        this.bodyError = err;
        this.ended = true;
        this.discardBody();
        const pending = this.pendingPromise;
        if (pending) {
            this.pendingPromise = null;
            pending.reject(err);
        }
    }

    /**
     * Did the body stop short of what the framing promised? Only meaningful while the
     * message is unfinished — onMessageComplete calls finishBody(), not failBody().
     */
    private bodyIncomplete(): boolean {
        if (!this.expectBody) return false;
        // Chunked declares its end with a 0-chunk; not having seen one means short.
        if (this.chunked) return true;
        return this.bodyRead < this.contentLength;
    }

    /** Bad header block: stop parsing here so the handler never sees the request. */
    private rejectHeaders(err: Error, status = 400): void {
        if (!this.requestError) { this.requestError = err; this.requestErrorStatus = status; }
        this.parser.pause();
    }

    /**
     * Charge `n` bytes of head (request line, field name, or value) against the
     * budget. Without this a peer can stream an endless header block: llhttp has
     * no size limit of its own and maxHeadersCount is only checked at
     * onHeadersComplete, which such a peer never reaches — so reqHeaders/url grow
     * until the process dies. Node caps the same total at http.maxHeaderSize
     * (16384) and answers 431.
     */
    private chargeHeaderBytes(n: number): boolean {
        if (this.maxHeaderSize <= 0) return true;
        this.headerBytes += n;
        if (this.headerBytes <= this.maxHeaderSize) return true;
        this.rejectHeaders(
            new Error(`request head exceeds ${this.maxHeaderSize} bytes`),
            431,
        );
        return false;
    }

    /** Minimal close-delimited error response for a rejected header block. */
    private async rejectRequest(status: number, statusText: string): Promise<void> {
        this.keepAlive = false;
        this.responseFramed = true;
        try {
            await this.socket.write(encodeResponseHead(this.requestHttpVersion, status, statusText, [
                ['Content-Length', '0'],
                ['Connection', 'close'],
            ]));
        } catch { /* peer already gone */ }
        this.headersSent = true;
        this.responseEnded = true;
    }

    private setupParser(): void {
        this.parser.onUrl = (buf, off, len) => {
            // The request target counts toward the head budget (Node: a 30k URL is
            // HPE_HEADER_OVERFLOW), and is what an attacker grows when sending no headers.
            if (!this.chargeHeaderBytes(len)) return;
            this.url += decodeParserBytes(buf, off, len);
        };
        this.parser.onHeaderField = (buf, off, len) => {
            if (!this.chargeHeaderBytes(len)) return;
            if (this.headerValue !== null) this.commitRequestHeader();
            this.headerField += decodeParserBytes(buf, off, len);
        };
        this.parser.onHeaderValue = (buf, off, len) => {
            if (!this.chargeHeaderBytes(len)) return;
            this.headerValue = (this.headerValue ?? '') + decodeParserBytes(buf, off, len);
        };
        this.parser.onHeadersComplete = () => {
            this.commitRequestHeader();
            this.method = HTTP_METHODS[this.parser.state.method] ?? 'UNKNOWN'; this.headersOk = true;
            if (this.maxHeadersCount > 0 && this.reqHeaders.length > this.maxHeadersCount) {
                this.rejectHeaders(new Error(`request exceeds max headers (${this.maxHeadersCount})`));
                return;
            }
            const connH = this.reqHeaders.find(([n]) => n === 'connection')?.[1];
            const ver = `${this.parser.state.httpMajor}.${this.parser.state.httpMinor}`;
            this.requestHttpVersion = ver;
            this.keepAlive = wantsKeepAlive(ver, connH) && !this.forceClose;
            // Response compression is application-owned, including Content-Length.
            const cl = this.reqHeaders.find(([n]) => n === 'content-length')?.[1];
            const te = this.reqHeaders.find(([n]) => n === 'transfer-encoding')?.[1];
            // Reject ambiguous or unsupported transfer codings before a handler runs.
            if (te !== undefined && (!isChunkedEncoding(te) || cl !== undefined)) {
                this.rejectHeaders(new Error('unsupported or ambiguous Transfer-Encoding'));
                return;
            }
            if (isChunkedEncoding(te)) {
                this.chunked = true; this.expectBody = true;
            } else if (cl) {
                const len = parseContentLength(cl, this.reqHeaders);
                if (len < 0) { this.rejectHeaders(new Error('invalid Content-Length')); return; }
                this.contentLength = len; this.expectBody = len > 0;
            }
        };
        this.parser.onBody = (buf, off, len) => {
            // Already failed: nothing will read these bytes, so retaining them only
            // re-grows a queue we just discarded (same reasoning as h2.acceptData).
            if (this.bodyError || this._closed) return;
            // Copy retained chunks so accounting matches actual retained memory.
            const u8 = toByteView(buf).slice(off, off + len);
            // Counts what the framing actually delivered, so a peer that vanishes short of
            // Content-Length can be told apart from one that finished (see bodyIncomplete).
            this.bodyRead += len;
            this.enqueue(u8);
            if (this.bufferedBody > MAX_BUFFERED_BODY_BYTES) {
                // Unconsumed bodies are capped independently of stream backpressure.
                this.discardBody();
                this.bodyError = Object.assign(
                    new Error(`request body exceeds ${MAX_BUFFERED_BODY_BYTES} buffered bytes`),
                    { code: 'ERR_HTTP_REQUEST_BODY_TOO_LARGE' },
                );
                this.ended = true;
                this.keepAlive = false;
                const pending = this.pendingPromise;
                if (pending) { this.pendingPromise = null; pending.reject(this.bodyError); }
                this.parser.pause();
            }
        }
        this.parser.onMessageComplete = () => {
            /* llhttp does not emit onHeadersComplete for the trailer block. The
             * final trailer therefore has no following field callback to flush
             * it, so commit any pending pair before completing the message. */
            this.commitRequestHeader();
            this.finishBody();
            this.parser.pause();
        };
    }

    private commitRequestHeader(): void {
        if (this.headerValue === null) return;
        const name = this.headerField.toLowerCase();
        const value = this.headerValue;
        validateHeader(name, value);
        // Fields after the header block are chunked trailers — never request headers.
        if (this.headersOk) this.trailers.push([name, value]);
        else this.reqHeaders.push([name, value]);
        this.headerField = '';
        this.headerValue = null;
    }

    async handleRequest(handler: (req: RawRequest, res: RawResponse) => void | Promise<void>, onHeaders?: () => void): Promise<boolean> {
        this.requestInProgress = false;
        this.method = ''; this.url = ''; this.reqHeaders = []; this.headerField = ''; this.headerValue = null; this.headersOk = false;
        this.expectBody = false; this.contentLength = 0; this.chunked = false; this.bodyRead = 0;
        this.headersSent = false; this.responseEnded = false; this.responseFramed = false;
        this.responseEndPromise = null;
        this.responseBodyBytes = 0; this.responseContentLength = null;
        this.chunkedEncoding = false;
        this.requestHttpVersion = '1.1';
        this.bodyless = false; this.requestError = null; this.requestErrorStatus = 400; this.trailers = [];
        this.headerBytes = 0;
        this.bodyChunk = [];
        this.bufferedBody = 0;
        this.bodyPolled = false;
        this.drainWaiter = null;
        this.pendingPromise = null;
        this.bodyError = null;
        this.transportError = null;
        this.ended = false;

        const req: RawRequest = {
            method: '', url: '', httpVersion: this.requestHttpVersion,
            headers: this.reqHeaders, body: null
        };
        Reflect.set(req as object, '__cnoTcp', this.socket.socket);
        const res: RawResponse = {
            status: 200, statusText: 'OK', headers: [], body: null
        };
        let handlePromise: Promise<void> | undefined;
        let handlerStarted = false;

        while (!this.ended) {
            // Pause socket reads only after a consumer establishes backpressure.
            if (this.bodyPolled && this.bufferedBody >= BODY_HIGH_WATER_MARK && !this.ended) {
                if (!this.drainWaiter) this.drainWaiter = Promise.withResolvers<void>();
                await this.drainWaiter.promise;
                if (this.ended) break;
            }
            let data = this.pendingInput;
            this.pendingInput = null;
            if (data === null) {
                try {
                    data = await this.socket.read();
                } catch (err) {
                    // UV peer-gone on read — same coded path as clean EOF.
                    const e = err instanceof Error ? err : new Error(String(err));
                    if (!this.headersOk) {
                        this.markTransportError(e);
                        if (TcpSocket.isDisconnectError(e)) {
                            this.requestInProgress = false;
                            return false;
                        }
                        this.requestInProgress = false;
                        throw e;
                    }
                    this.failBody(e);
                    break;
                }
            }
            if (data === null) {
                // Clean TCP EOF: n===0 → null. Always structured IOError, never bare message.
                if (!this.headersOk) {
                    this.requestInProgress = false;
                    return false;
                }
                this.failBody(this.peerClosedError());
                break;
            }
            if (data.length === 0) continue;
            // Incoming bytes make a draining keep-alive connection active.
            this.requestInProgress = true;

            const r = this.parser.execute(data.buffer.slice(data.byteOffset, data.byteLength + data.byteOffset));

            // Rejected request framing must never reach the handler.
            if (this.requestError && !handlerStarted) {
                this.finishBody();
                const status = this.requestErrorStatus;
                await this.rejectRequest(status, status === 431 ? 'Request Header Fields Too Large' : 'Bad Request');
                this.requestInProgress = false;
                return false;
            }
            // Trailer faults must reject an already-running handler's body wait.
            if (this.requestError && handlerStarted && !this.ended) {
                this.failBody(this.requestError);
                this.keepAlive = false;
            }

            // Start the handler before processing the parser's completion pause.
            if (this.headersOk && !handlerStarted) {
                handlerStarted = true;
                onHeaders?.();
                req.method = this.method;
                req.url = this.url;
                req.httpVersion = this.requestHttpVersion;
                if (this.expectBody) {
                    req.body = () => {
                        // A poll proves a consumer exists, which is what licenses the read
                        // loop to block on backpressure instead of buffering without limit.
                        this.bodyPolled = true;
                        if (this.bodyChunk.length) {
                            const chunk = this.bodyChunk.shift();
                            if (chunk !== undefined) {
                                this.bufferedBody -= chunk.byteLength;
                                if (this.bufferedBody < 0) this.bufferedBody = 0;
                                this.wakeDrain();
                                return Promise.resolve(chunk);
                            }
                        }
                        if (this.bodyError) return Promise.reject(this.bodyError);
                        if (this.ended) return Promise.resolve(null);
                        const pending = Promise.withResolvers<Uint8Array | null>();
                        this.pendingPromise = pending;
                        return pending.promise;
                    };
                }
                handlePromise = Promise.resolve(handler(req, res));
            }

            if (r.errno !== 0) {
                const consumed = Number(r.bytesConsumed ?? data.byteLength);
                if (Number.isFinite(consumed) && consumed >= 0 && consumed < data.byteLength) {
                    this.pendingInput = data.subarray(consumed);
                }
                if (r.name === 'HPE_PAUSED') {
                    // Preserve coalesced bytes following an upgrade handshake.
                    if (this.parser.state.upgrade) {
                        this.upgradeLeftover = this.pendingInput;
                        this.pendingInput = null;
                        this.keepAlive = false;
                    }
                    break;
                }
                if (r.name === 'HPE_PAUSED_UPGRADE') {
                    this.upgradeLeftover = this.pendingInput;
                    this.pendingInput = null;
                    this.keepAlive = false;
                    break;
                }
                const parseError = new Error(`Parse error: ${r.reason}`);
                this.failBody(parseError);
                // The handler is already running and awaiting the body we just failed;
                // nothing awaits its promise after we throw, so absorb that rejection here.
                if (handlePromise) handlePromise.catch(() => { /* reported via body error */ });
                // Malformed framing before any handler ran: answer 400 so the peer sees a
                // status, not a bare FIN (llhttp rejects bad CL/TE before onHeadersComplete).
                else await this.rejectRequest(400, 'Bad Request');
                this.requestInProgress = false;
                throw parseError;
            }
        }

        this.parser.reset(http.REQUEST); this.requestCount++;
        try {
            await handlePromise;
        } finally {
            this.requestInProgress = false;
        }
        // Peer/transport fault ends the connection — do not wait for another request.
        if (this.transportError || this._closed) return false;
        return this._upgraded ? false : this.keepAlive;
    }

    async writeHead(status: number, statusText: string, headers: Array<[string, string]>): Promise<void> {
        this.throwIfTransportDead();
        const informational = status >= 100 && status < 200 && status !== 101;
        if (this.headersSent && !informational) throw new Error("Headers already sent");
        if (this.responseEnded) throw new Error("Response already ended");
        // Never mutate a handler-owned reusable header list.
        headers = headers.map(([n, v]) => [n, v] as [string, string]);
        // 1xx responses are interim header blocks. They must not mark the final
        // response as sent or change its framing/body policy (103 -> 200 is valid).
        if (informational) {
            try {
                await this.socket.write(encodeResponseHead('1.1', status, statusText, headers));
            } catch (err) {
                const e = err instanceof Error ? err : new Error(String(err));
                this.markTransportError(e);
                throw e;
            }
            return;
        }
        const headerValue = (name: string): string | undefined =>
            headers.find(([n]) => n.toLowerCase() === name)?.[1];
        const hasHeader = (name: string): boolean =>
            headers.some(([n]) => n.toLowerCase() === name);
        const isBodyForbiddenStatus = (status >= 100 && status < 200)
            || status === 204 || status === 205 || status === 304;
        // RFC 9112 §6.3: a HEAD response also ends at the header block. Headers stay as the
        // handler set them (HEAD must mirror GET), but no body byte may ever be written.
        this.bodyless = isBodyForbiddenStatus || this.method === 'HEAD';
        if (isBodyForbiddenStatus) {
            // Bodyless responses retain representation Content-Length metadata.
            headers = headers.filter(([n]) => {
                const key = n.toLowerCase();
                return key !== 'content-encoding' && key !== 'transfer-encoding';
            });
            this.chunkedEncoding = false;
        }
        const contentLengths = headers.filter(([n]) => n.toLowerCase() === 'content-length');
        if (contentLengths.length > 1) throw new Error('invalid Content-Length');
        if (contentLengths.length === 1) {
            const value = contentLengths[0]![1].trim();
            if (!/^\d+$/.test(value) || !Number.isSafeInteger(Number(value))) {
                throw new Error('invalid Content-Length');
            }
            this.responseContentLength = Number(value);
        }
        const te = headerValue('transfer-encoding');
        if (te && contentLengths.length > 0 && !isBodyForbiddenStatus) {
            throw new Error('Content-Length cannot be combined with Transfer-Encoding');
        }
        if (te !== undefined && !isChunkedEncoding(te)) throw new Error('unsupported Transfer-Encoding');
        if (isChunkedEncoding(te)) this.chunkedEncoding = true;
        // A handler-supplied Connection: close disables reuse.
        if (connectionTokens(headerValue('connection')).includes('close')) this.keepAlive = false;
        // No framing given by the handler: chunked on 1.1, close-delimited otherwise (Node parity).
        const needsFraming = !isBodyForbiddenStatus && this.method !== 'HEAD'
            && !this.chunkedEncoding && !hasHeader('content-length');
        const isUpgradeResponse = status === 101 && hasHeader('upgrade');
        if (needsFraming) {
            if (this.requestHttpVersion === '1.0' || hasHeader('transfer-encoding')) this.keepAlive = false;
            else this.chunkedEncoding = true;
        }
        this.responseFramed = !needsFraming || this.chunkedEncoding;
        if (this.bodyless) this.responseContentLength = null;
        if (this.forceClose) this.keepAlive = false;
        let outHeaders = headers.slice();
        if (needsFraming && this.chunkedEncoding) outHeaders.push(['transfer-encoding', 'chunked']);
        if (!hasHeader('connection')) {
            outHeaders.push(['Connection', this.keepAlive ? 'keep-alive' : 'close']);
        } else if (!this.keepAlive && !isUpgradeResponse) {
            // Never advertise keep-alive when this response disables reuse.
            outHeaders = outHeaders.filter(([n]) => n.toLowerCase() !== 'connection');
            outHeaders.push(['Connection', 'close']);
        }
        // Node adds Keep-Alive: timeout=<sec> when the connection stays open.
        if (this.keepAlive && !hasHeader('keep-alive') && this.keepAliveTimeoutMs > 0) {
            const sec = Math.max(1, Math.floor(this.keepAliveTimeoutMs / 1000));
            outHeaders.push(['Keep-Alive', `timeout=${sec}`]);
        }
        try {
            // Node advertises HTTP/1.1 in response status lines even when the
            // request was HTTP/1.0; requestHttpVersion still controls framing.
            await this.socket.write(encodeResponseHead('1.1', status, statusText, outHeaders));
        } catch (err) {
            const e = err instanceof Error ? err : new Error(String(err));
            this.markTransportError(e);
            throw e;
        }
        this.headersSent = true;
    }

    async writeData(chunk: Uint8Array | string): Promise<void> {
        this.throwIfTransportDead();
        if (this.responseEnded) throw new Error("Response already ended");
        if (!this.headersSent) { if (this.requestHttpVersion === "1.0") { this.keepAlive = false; await this.writeHead(200, "OK", []); } else { this.chunkedEncoding = true; await this.writeHead(200, "OK", [['transfer-encoding', 'chunked']]); } }
        // Bodyless response: the peer stopped reading at the header block, so any byte
        // written here would be parsed as the head of the next response (Node drops too).
        if (this.bodyless) return;
        let data = typeof chunk === "string" ? engine.encodeString(chunk) : chunk;
        // Empty chunked writes are no-ops; zero-length frames terminate the body.
        if (data.byteLength === 0) return;
        if (this.responseContentLength !== null && this.responseBodyBytes + data.byteLength > this.responseContentLength) {
            const err = new Error('response body exceeds Content-Length');
            this.markTransportError(err);
            throw err;
        }
        // Reserve body bytes before awaiting so concurrent writes share the cap.
        this.responseBodyBytes += data.byteLength;
        try {
            if (this.chunkedEncoding) await this.socket.write(encodeChunkedFrame(data));
            else await this.socket.write(data);
        } catch (err) {
            const e = err instanceof Error ? err : new Error(String(err));
            this.markTransportError(e);
            throw e;
        }
    }

    async endResponse(chunk?: Uint8Array | string): Promise<void> {
        if (this.responseEnded) return;
        if (this.responseEndPromise) return this.responseEndPromise;
        const ending = this.finishResponse(chunk);
        this.responseEndPromise = ending;
        return ending;
    }

    private async finishResponse(chunk?: Uint8Array | string): Promise<void> {
        this.throwIfTransportDead();
        if (chunk !== undefined) await this.writeData(chunk);
        else if (!this.headersSent) await this.writeHead(200, "OK", [['content-length', '0']]);
        try {
            // Bodyless responses end at the header block; no chunk terminator follows.
            if (this.bodyless) this.chunkedEncoding = false;
            else {
                if (this.chunkedEncoding) {
                    await this.socket.write(encodeChunkedTrailer());
                    this.chunkedEncoding = false;
                }
                // Trailer and close-delimited framing remain mutually exclusive.
                else if (!this.responseFramed) {
                    // Unframed body (1.0 / handler-supplied TE): EOF is the only terminator.
                    this.keepAlive = false;
                }
                if (this.responseContentLength !== null && this.responseBodyBytes !== this.responseContentLength) {
                    throw new Error('response body does not match Content-Length');
                }
            }
        } catch (err) {
            const e = err instanceof Error ? err : new Error(String(err));
            this.markTransportError(e);
            throw e;
        }
        this.responseEnded = true;
    }

    receive(_d: Uint8Array): void { }
    wantWrite(): boolean { return false; }
    flush(): Uint8Array | null { return null; }
    createStream(): ProtocolStream { return new H1Stream(this, true); }
    on(events: Partial<ProtocolConnectionEvents>): void { Object.assign(this.events, events); }
    goaway(): void { this.close(); }
    close(): void {
        if (this._closed) return;
        this._closed = true;
        this.requestInProgress = false;
        // Pending body/waiters: local close looks like peer EOF to upper layers.
        if (!this.ended) this.failBody(this.transportError ?? this.peerClosedError());
        this.socket.close();
        this.events.onClose?.();
        const listeners = [...this.terminalCloseListeners];
        this.terminalCloseListeners.clear();
        for (const listener of listeners) listener();
    }
    destroy(): void { this.close(); }
    /** Last request on this connection: the response must carry Connection: close. */
    disableKeepAlive(): void { this.forceClose = true; this.keepAlive = false; }
    markUpgraded(): void { this._upgraded = true; this.keepAlive = false; }
    get isUpgraded(): boolean { return this._upgraded; }
    takeUpgradeLeftover(): Uint8Array | null { const v = this.upgradeLeftover; this.upgradeLeftover = null; return v; }
    async readRequest(): Promise<RawRequest> { return { method: this.method, url: this.url, httpVersion: this.requestHttpVersion, headers: this.reqHeaders, body: null }; }
}

/* ------------------------------------------------------------------ */
/* H1 Client Connection                                               */
/* ------------------------------------------------------------------ */

class H1ClientConnection implements ProtocolConnection {
    readonly version = HttpVersion.HTTP11;
    readonly secure: boolean;
    private socket: TcpSocket;
    private parser: HttpResponseParser | null = null;
    /** Bytes after a completed response, retained for the next pipelined read. */
    private pendingInput: Uint8Array | null = null;
    /** HTTP/1.x request/response exchanges are serialized on one connection. */
    private requestQueue: Promise<void> = Promise.resolve();
    private activeRequest: H1ClientRequest | null = null;
    private events: ProtocolConnectionEvents = { onstream: null, onError: null, onClose: null, onGoaway: null, onSettings: null };

    constructor(socket: TcpSocket, secure: boolean) { this.socket = socket; this.secure = secure; }

    async sendRequest(req: HttpRequestBuilder): Promise<RawResponse> {
        return this.enqueue(() => this.sendRequestLocked(req));
    }
    private async sendRequestLocked(req: HttpRequestBuilder): Promise<RawResponse> {
        await this.socket.write(req.build());
        this.parser = new HttpResponseParser();
        return this.driveParser(this.parser);
    }

    private enqueue<T>(operation: () => Promise<T>): Promise<T> {
        const run = this.requestQueue.then(operation, operation);
        // Keep the queue usable after a failed exchange while preserving the
        // original rejection for the caller that owns this request.
        this.requestQueue = run.then(() => undefined, () => undefined);
        return run;
    }

    private async reserveRequest(): Promise<() => void> {
        const previous = this.requestQueue;
        let release!: () => void;
        this.requestQueue = new Promise<void>(resolve => { release = resolve; });
        await previous.catch(() => { /* queued exchanges keep the slot usable */ });
        return release;
    }

    async beginRequest(req: RawRequest): Promise<H1ClientRequest> {
        const prepared = prepareH1Request(req);
        const release = await this.reserveRequest();
        try {
            await this.socket.write(prepared.head);
            let request!: H1ClientRequest;
            request = new H1ClientRequest(this, prepared, () => {
                if (this.activeRequest === request) this.activeRequest = null;
                release();
            });
            this.activeRequest = request;
            // A null body is the H1 equivalent of H2 END_STREAM on HEADERS. This
            // also emits an empty chunked terminator when the caller explicitly
            // requested Transfer-Encoding: chunked.
            if (!prepared.hasBody) await request.end();
            return request;
        } catch (err) {
            release();
            this.close();
            throw err;
        }
    }

    async sendRawRequest(req: RawRequest): Promise<RawResponse> {
        const request = await this.beginRequest(req);
        try {
            if (req.body) {
                for (;;) {
                    const chunk = await req.body();
                    if (chunk === null) break;
                    await request.writeData(chunk);
                }
            }
            if (!request.isEnded) await request.end();
            return await request.readResponse();
        } catch (err) {
            request.abort();
            throw err;
        }
    }

    async writeRequestBytes(data: Uint8Array): Promise<void> {
        await this.socket.write(data);
    }
    receive(_d: Uint8Array): void { }
    wantWrite(): boolean { return false; }
    flush(): Uint8Array | null { return null; }
    createStream(): ProtocolStream { return new H1Stream(this, false); }
    on(events: Partial<ProtocolConnectionEvents>): void { Object.assign(this.events, events); }
    goaway(): void { this.close(); }
    close(): void {
        this.socket.close();
        const active = this.activeRequest;
        this.activeRequest = null;
        active?.connectionClosed();
    }
    destroy(): void { this.close(); }
    async readResponse(): Promise<RawResponse> {
        // Drive the parser until the response is complete.
        if (!this.parser || this.parser.isCompleted) this.parser = new HttpResponseParser();
        return this.driveParser(this.parser);
    }

    /**
     * Read until the response is complete. An EOF before completion is an error,
     * not an empty result: returning `{status: 0, body: <partial>}` hands the caller
     * a truncated body that looks like a successful short response. Node surfaces
     * the same condition as ECONNRESET / "socket hang up".
     */
    private async driveParser(parser: HttpResponseParser): Promise<RawResponse> {
        let status = 0; const headers: Array<[string, string]> = []; const chunks: Uint8Array[] = [];
        parser.onHeadersComplete = (code, hdrs) => { status = code; headers.push(...hdrs); };
        parser.onData = (chunk) => chunks.push(chunk);
        while (!parser.isCompleted) {
            let d = this.pendingInput;
            this.pendingInput = null;
            if (d === null) d = await this.socket.read();
            if (!d) {
                // A close-delimited response (no CL, no chunked) legitimately ends at EOF:
                // tell llhttp so it can complete the message before we judge it.
                parser.finishOnEof();
                if (parser.isCompleted) break;
                throw error.Error(error.errno.ECONNRESET);
            }
            const result = parser.feed(d);
            if (result) {
                const consumed = Number(result.bytesConsumed ?? d.byteLength);
                if (Number.isFinite(consumed) && consumed >= 0 && consumed < d.byteLength) {
                    this.pendingInput = d.subarray(consumed);
                }
            }
        }
        return { status, statusText: strstatus(status), headers, body: mergeChunks(chunks) };
    }
    async writeRequest(data: Uint8Array): Promise<void> { await this.socket.write(data); }
}

/* ------------------------------------------------------------------ */
/* H1 Protocol                                                        */
/* ------------------------------------------------------------------ */

class H1Client implements ProtocolClient {
    readonly version = HttpVersion.HTTP11;
    async connect(socket: TcpSocket, _c: ProtocolClientConfig): Promise<ProtocolConnection> { return new H1ClientConnection(socket, _c.secure); }
    async request(conn: ProtocolConnection, req: RawRequest): Promise<RawResponse> {
        if (!(conn instanceof H1ClientConnection)) {
            throw new TypeError('HTTP/1.x request requires H1ClientConnection');
        }
        return conn.sendRawRequest(req);
    }
}

class H1Server implements ProtocolServer {
    readonly version = HttpVersion.HTTP11;
    async accept(socket: TcpSocket, config: ProtocolServerConfig): Promise<ProtocolConnection> {
        return new H1ServerConnection(socket, config.secure, config.keepAliveTimeout, config.maxHeadersCount, config.maxHeaderSize);
    }
    negotiate(alpn?: string): HttpVersion | null { return (!alpn || alpn === ALPN.HTTP11 || alpn === ALPN.HTTP10) ? HttpVersion.HTTP11 : null; }
}

export const h1 = { version: HttpVersion.HTTP11, client: new H1Client(), server: new H1Server() } as const;

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

function mergeChunks(chunks: Uint8Array[]): Uint8Array {
    if (chunks.length === 0) return new Uint8Array(0);
    const first = chunks[0];
    if (chunks.length === 1 && first !== undefined) return first;
    const total = chunks.reduce((s, c) => s + c.length, 0);
    const merged = new Uint8Array(total); let off = 0;
    for (const c of chunks) { merged.set(c, off); off += c.length; }
    return merged;
}

const HTTP_METHODS = ["DELETE", "GET", "HEAD", "POST", "PUT", "CONNECT", "OPTIONS", "TRACE", "COPY", "LOCK", "MKCOL", "MOVE", "PROPFIND", "PROPPATCH", "SEARCH", "UNLOCK", "BIND", "REBIND", "UNBIND", "ACL", "REPORT", "MKACTIVITY", "CHECKOUT", "MERGE", "MSEARCH", "NOTIFY", "SUBSCRIBE", "UNSUBSCRIBE", "PATCH", "PURGE", "MKCALENDAR", "LINK", "UNLINK"] as const;
const STATUS_TEXT_MAP: Record<number, string> = { 100: 'Continue', 101: 'Switching Protocols', 200: 'OK', 201: 'Created', 204: 'No Content', 301: 'Moved Permanently', 302: 'Found', 304: 'Not Modified', 400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found', 500: 'Internal Server Error', 502: 'Bad Gateway', 503: 'Service Unavailable' };
function strstatus(code: number): string { return STATUS_TEXT_MAP[code] ?? `Status ${code}`; }
