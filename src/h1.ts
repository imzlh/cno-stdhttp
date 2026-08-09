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
import { StreamingDecompressor, StreamingCompressor, parseAcceptEncoding, pickEncoding, shouldCompress } from "./zlib";
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

// RFC 7230 §3.3.1: `chunked` must be the last coding. Substring match ("xchunked") is a desync vector.
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
    if (!Number.isFinite(n) || n < 0) return -1;
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
    private bodyChunks: Uint8Array[] = [];
    private completed: boolean = false;
    private headersComplete: boolean = false;
    private decompressor: StreamingDecompressor | null = null;

    public onHeadersComplete?: (statusCode: number, headers: Array<[string, string]>) => void;
    public onData?: (chunk: Uint8Array) => void;
    public onComplete?: () => void;
    public onError?: (error: Error) => void;

    constructor() { this.parser = new http.Parser(http.RESPONSE); this.setupCallbacks(); }

    private setupCallbacks(): void {
        this.parser.onStatus = (buf, off, len) => { this.statusText = decodeParserBytes(buf, off, len); };
        this.parser.onHeaderField = (buf, off, len) => { this.currentHeaderField = decodeParserBytes(buf, off, len).toLowerCase(); };
        this.parser.onHeaderValue = (buf, off, len) => {
            const name = this.currentHeaderField, value = decodeParserBytes(buf, off, len);
            validateHeader(name, value);
            this.headers.push([name, value]); this.currentHeaderField = '';
        };
        this.parser.onHeadersComplete = () => {
            this.statusCode = this.parser.state.status; this.headersComplete = true;
            if (!this.statusText) this.statusText = strstatus(this.statusCode);
            const major = this.parser.state.httpMajor ?? 1;
            const minor = this.parser.state.httpMinor ?? 1;
            this.httpVersion = `${major}.${minor}`;
            const ce = this.headers.find(([n]) => n === 'content-encoding');
            if (ce) this.decompressor = new StreamingDecompressor(ce[1]);
            this.onHeadersComplete?.(this.statusCode, this.headers);
        };
        this.parser.onBody = (buf, off, len) => {
            let view = toByteView(buf).slice(off, off + len);
            if (this.decompressor?.isActive) view = this.decompressor.decompress(view);
            if (!this.onData) this.bodyChunks.push(view);
            this.onData?.(view);
        };
        this.parser.onMessageComplete = () => {
            // A gzip/deflate body that stops mid-stream decompresses to a short but
            // otherwise valid-looking result. Validating the trailer here turns silent
            // truncation into an error, as Node's zlib does.
            try {
                this.decompressor?.finish();
            } catch (err) {
                const e = err instanceof Error ? err : new Error(String(err));
                if (this.onError) { this.onError(e); return; }
                throw e;
            }
            this.completed = true; this.onComplete?.();
        };
    }

    feed(data: Uint8Array): CModuleHTTP.ParserExecuteResult | undefined {
        try {
            const result = this.parser.execute(data.buffer.slice(data.byteOffset, data.byteLength + data.byteOffset));
            if (result.errno !== 0) {
                if (result.name === 'HPE_PAUSED_UPGRADE') return result;
                const e = new Error(`HTTP parse error: ${result.reason}`); if (this.onError) this.onError(e); else throw e;
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
        this.currentHeaderField = ''; this.completed = false; this.headersComplete = false;
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
    constructor(conn: H1ServerConnection | H1ClientConnection, isServer: boolean) { this.conn = conn; this.isServer = isServer; }

    async writeHead(data: RawRequest | RawResponse): Promise<void> {
        if (this.isServer) {
            const res = data as RawResponse;
            await (this.conn as H1ServerConnection).writeHead(res.status, res.statusText, res.headers);
        } else {
            const req = data as RawRequest;
            const builder = new HttpRequestBuilder({ method: req.method, path: req.url, body: req.body as Uint8Array | null });
            for (const [k, v] of req.headers) builder.setHeader(k, v);
            await (this.conn as H1ClientConnection).writeRequest(builder.build());
        }
    }
    async writeData(data: Uint8Array): Promise<void> {
        if (this.isServer) await (this.conn as H1ServerConnection).writeData(data);
    }
    async end(data?: Uint8Array): Promise<void> {
        if (this.isServer) await (this.conn as H1ServerConnection).endResponse(data);
    }
    async readMessage(): Promise<RawRequest | RawResponse> {
        return this.isServer ? (this.conn as H1ServerConnection).readRequest() : (this.conn as H1ClientConnection).readResponse();
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
    private headerField = ''; private headersOk = false;
    private expectBody = false; private contentLength = 0; private chunked = false;
    private bodyRead = 0;
    private headersSent = false; private responseEnded = false; private chunkedEncoding = false;
    /** Response has explicit framing (chunked, content-length, or bodyless status/HEAD). */
    private responseFramed = false;
    /** RFC 9112 §6.3: HEAD / 1xx / 204 / 304 end at the header block — no body bytes at all. */
    private bodyless = false;
    /** Header-block fault (oversized headers, bad framing) — answer 400, never run the handler. */
    private requestError: Error | null = null;
    /** Status to answer a rejected header block with (431 for an oversized head). */
    private requestErrorStatus = 400;
    /** Chunked trailer fields; kept out of reqHeaders so they cannot forge request headers. */
    private trailers: Array<[string, string]> = [];
    /** Server loop said this is the last request — response must announce Connection: close. */
    private forceClose = false;
    private compressEncoding: 'gzip' | 'deflate' | null = null;
    private compressor: StreamingCompressor | null = null;
    private requestCount = 0; private keepAlive = true; private requestHttpVersion = '1.1';
    private _closed = false;
    private _upgraded = false;
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
        // Nobody is waiting: the bytes are retained, so they must be accounted for.
        // Without this counter the queue is a plain unbounded array and a peer that
        // sends a body no handler reads grows RSS one-for-one with what it sends.
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
        // Peer gone: end the body stream (resolve null) only if the body had actually
        // reached its declared end. Resolving null on a body that is still short would
        // report a clean EOF, making a truncated upload indistinguishable from a whole
        // one — Node marks req.complete=false and emits 'aborted'/ECONNRESET here, and a
        // handler that commits on end-of-body would otherwise store a partial object.
        if (TcpSocket.isDisconnectError(err) && !this.bodyIncomplete()) {
            this.discardBody();
            this.finishBody();
            return;
        }
        if (TcpSocket.isDisconnectError(err)) {
            // Surface truncation as a coded error. Setting bodyError alone cannot raise an
            // unhandled rejection: a pendingPromise only exists because req.body() created
            // it for a caller that is awaiting it, and with no caller nothing is rejected.
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
            this.headerField = decodeParserBytes(buf, off, len).toLowerCase();
        };
        this.parser.onHeaderValue = (buf, off, len) => {
            if (!this.chargeHeaderBytes(len)) return;
            const name = this.headerField.toLowerCase();
            const value = decodeParserBytes(buf, off, len);
            validateHeader(name, value);
            // Fields after the header block are chunked trailers — never request headers.
            if (this.headersOk) this.trailers.push([name, value]);
            else this.reqHeaders.push([name, value]);
        };
        this.parser.onHeadersComplete = () => {
            this.method = HTTP_METHODS[this.parser.state.method] ?? 'UNKNOWN'; this.headersOk = true;
            if (this.maxHeadersCount > 0 && this.reqHeaders.length > this.maxHeadersCount) {
                this.rejectHeaders(new Error(`request exceeds max headers (${this.maxHeadersCount})`));
                return;
            }
            const connH = this.reqHeaders.find(([n]) => n === 'connection')?.[1];
            const ver = `${this.parser.state.httpMajor}.${this.parser.state.httpMinor}`;
            this.requestHttpVersion = ver;
            this.keepAlive = wantsKeepAlive(ver, connH) && !this.forceClose;
            // Deliberately NOT negotiating response compression from accept-encoding.
            // Neither node:http nor Deno.serve ever compresses a response the handler
            // did not compress itself, and doing so silently invalidates the handler's
            // Content-Length (express.static sets it from stat()) — the peer then gets
            // a chunked gzip stream with no length, and any CL-dependent client,
            // proxy or progress bar is wrong. Compression is the app's job
            // (compression middleware), which sets content-encoding itself.
            const cl = this.reqHeaders.find(([n]) => n === 'content-length')?.[1];
            const te = this.reqHeaders.find(([n]) => n === 'transfer-encoding')?.[1];
            // RFC 7230 §3.3.3: TE wins when both CL and TE are present (closes CL.TE smuggling).
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
            // slice(), not subarray(): a view keeps its whole parent read buffer alive,
            // so the retained total would exceed what bufferedBody counts and the cap
            // would under-measure real memory.
            const u8 = toByteView(buf).slice(off, off + len);
            // Counts what the framing actually delivered, so a peer that vanishes short of
            // Content-Length can be told apart from one that finished (see bodyIncomplete).
            this.bodyRead += len;
            this.enqueue(u8);
            if (this.bufferedBody > MAX_BUFFERED_BODY_BYTES) {
                // Reached only when no consumer is draining — backpressure caps a real
                // consumer at BODY_HIGH_WATER_MARK, far below this. Fail the body and drop
                // keep-alive; growing further is how a single request exhausts the process.
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
            this.finishBody();
            this.parser.pause();
        };
    }

    async handleRequest(handler: (req: RawRequest, res: RawResponse) => void | Promise<void>, onHeaders?: () => void): Promise<boolean> {
        this.method = ''; this.url = ''; this.reqHeaders = []; this.headerField = ''; this.headersOk = false;
        this.expectBody = false; this.contentLength = 0; this.chunked = false; this.bodyRead = 0;
        this.headersSent = false; this.responseEnded = false; this.responseFramed = false;
        this.chunkedEncoding = false; this.compressEncoding = null; this.compressor = null;
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
            // Flow control: a consumer that has fallen behind must not be raced. Leaving
            // the bytes in the kernel receive buffer closes the TCP window, so the peer
            // slows down instead of us growing the queue. Gated on bodyPolled so a handler
            // that never reads the body cannot deadlock the loop — that case is bounded by
            // MAX_BUFFERED_BODY_BYTES in onBody instead.
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
                        if (TcpSocket.isDisconnectError(e)) return false;
                        throw e;
                    }
                    this.failBody(e);
                    break;
                }
            }
            if (data === null) {
                // Clean TCP EOF: n===0 → null. Always structured IOError, never bare message.
                if (!this.headersOk) return false;
                this.failBody(this.peerClosedError());
                break;
            }
            if (data.length === 0) continue;

            const r = this.parser.execute(data.buffer.slice(data.byteOffset, data.byteLength + data.byteOffset));

            // Bad header block (oversized head, too many headers, malformed
            // Content-Length): answer 400/431 and drop the connection. The handler must
            // never run, or a request the parser refused to frame would still be served.
            if (this.requestError && !handlerStarted) {
                this.finishBody();
                const status = this.requestErrorStatus;
                await this.rejectRequest(status, status === 431 ? 'Request Header Fields Too Large' : 'Bad Request');
                return false;
            }
            // Same fault raised while parsing trailers: the handler is already running and
            // may be awaiting the body. rejectHeaders() paused the parser, so
            // onMessageComplete will never arrive — fail the body or the handler hangs
            // forever on a promise nothing will ever resolve.
            if (this.requestError && handlerStarted && !this.ended) {
                this.failBody(this.requestError);
                this.keepAlive = false;
            }

            // Start the handler as soon as headers are parsed. This must run
            // before the HPE_PAUSED break below: when the whole request arrives
            // in one buffer, onMessageComplete pauses the parser mid-execute,
            // so execute() returns HPE_PAUSED on the same call that produced
            // the headers. Checking errno first would skip the handler entirely.
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
                    // A WebSocket/upgrade handshake completes via onMessageComplete,
                    // which pauses the parser — so execute() returns plain HPE_PAUSED
                    // (not HPE_PAUSED_UPGRADE) even though state.upgrade is set. If we
                    // don't capture the leftover here, any bytes the client coalesced
                    // after the handshake (the first WS frame) are dropped, and the
                    // upgraded WebSocket hangs waiting for a frame already consumed.
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
                throw parseError;
            }
        }

        this.parser.reset(http.REQUEST); this.requestCount++;
        await handlePromise;
        // Peer/transport fault ends the connection — do not wait for another request.
        if (this.transportError || this._closed) return false;
        return this._upgraded ? false : this.keepAlive;
    }

    async writeHead(status: number, statusText: string, headers: Array<[string, string]>): Promise<void> {
        this.throwIfTransportDead();
        if (this.headersSent) throw new Error("Headers already sent");
        if (this.responseEnded) throw new Error("Response already ended");
        // Work on our own copy: the filters/pushes below would otherwise mutate the
        // handler's array, so a handler that reuses its header list on the next
        // request would silently inherit content-encoding/transfer-encoding from this one.
        headers = headers.map(([n, v]) => [n, v] as [string, string]);
        const headerValue = (name: string): string | undefined =>
            headers.find(([n]) => n.toLowerCase() === name)?.[1];
        const hasHeader = (name: string): boolean =>
            headers.some(([n]) => n.toLowerCase() === name);
        const isBodyForbiddenStatus = (status >= 100 && status < 200) || status === 204 || status === 304;
        // RFC 9112 §6.3: a HEAD response also ends at the header block. Headers stay as the
        // handler set them (HEAD must mirror GET), but no body byte may ever be written.
        this.bodyless = isBodyForbiddenStatus || this.method === 'HEAD';
        if (isBodyForbiddenStatus) {
            // Strip only the FRAMING headers. content-length is metadata about the
            // representation, not a promise of bytes on this response: RFC 9110 says a
            // 304/204 never carries a body whatever the length says, and node:http
            // passes a handler-set Content-Length straight through on a 304 (measured).
            // Dropping it loses a cache validator's size and diverges from node.
            headers = headers.filter(([n]) => {
                const key = n.toLowerCase();
                return key !== 'content-encoding' && key !== 'transfer-encoding';
            });
            this.chunkedEncoding = false;
            this.compressor = null;
            this.compressEncoding = null;
        }
        const te = headerValue('transfer-encoding');
        if (te?.toLowerCase().includes('chunked')) this.chunkedEncoding = true;
        // A handler-supplied `Connection: close` is binding on us too. Without this the
        // wire says close while the server keeps looping for another request on a socket
        // the peer has stopped using — the connection lingers until the idle timer fires.
        if (connectionTokens(headerValue('connection')).includes('close')) this.keepAlive = false;
        // No opportunistic compression here: see onHeadersComplete. `compressor` is
        // only ever non-null if a caller wires one up explicitly, so the guards in
        // writeData/endResponse below stay correct without re-introducing the
        // Content-Length-dropping auto-gzip path.
        // No framing given by the handler: chunked on 1.1, close-delimited otherwise (Node parity).
        const needsFraming = !isBodyForbiddenStatus && this.method !== 'HEAD'
            && !this.chunkedEncoding && !hasHeader('content-length');
        if (needsFraming) {
            if (this.requestHttpVersion === '1.0' || hasHeader('transfer-encoding')) this.keepAlive = false;
            else this.chunkedEncoding = true;
        }
        this.responseFramed = !needsFraming || this.chunkedEncoding;
        if (this.forceClose) this.keepAlive = false;
        let outHeaders = headers.slice();
        if (needsFraming && this.chunkedEncoding) outHeaders.push(['transfer-encoding', 'chunked']);
        if (!hasHeader('connection')) {
            outHeaders.push(['Connection', this.keepAlive ? 'keep-alive' : 'close']);
        } else if (!this.keepAlive) {
            // The handler asked for keep-alive but this connection will not be reused
            // (1.0 close-delimited body, maxRequestsPerConnection reached, upgrade).
            // Advertising reuse we then refuse desyncs the peer: it pipelines a second
            // request into a socket we close, or waits forever for a body terminator.
            outHeaders = outHeaders.filter(([n]) => n.toLowerCase() !== 'connection');
            outHeaders.push(['Connection', 'close']);
        }
        // Node adds Keep-Alive: timeout=<sec> when the connection stays open.
        if (this.keepAlive && !hasHeader('keep-alive') && this.keepAliveTimeoutMs > 0) {
            const sec = Math.max(1, Math.floor(this.keepAliveTimeoutMs / 1000));
            outHeaders.push(['Keep-Alive', `timeout=${sec}`]);
        }
        try {
            await this.socket.write(encodeResponseHead(this.requestHttpVersion, status, statusText, outHeaders));
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
        if (this.compressor) data = this.compressor.compress(data);
        // A zero-length chunked frame IS the terminator (`0\r\n\r\n`): emitting one
        // mid-body tells the peer the response ended, silently truncating everything
        // after it. Node treats an empty write as a no-op on the wire, so drop it.
        // (Reached by res.write('')/write(empty buffer), and by any streaming
        // compressor that buffers a chunk and returns nothing.)
        if (data.byteLength === 0) return;
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
        this.throwIfTransportDead();
        if (chunk !== undefined) await this.writeData(chunk);
        else if (!this.headersSent) await this.writeHead(200, "OK", [['content-length', '0']]);
        try {
            // Bodyless: nothing follows the header block — no compressor tail, no `0\r\n\r\n`.
            if (this.bodyless) this.chunkedEncoding = false;
            else {
                if (this.compressor) {
                    const tail = this.compressor.finish();
                    if (tail.length > 0 && this.chunkedEncoding) {
                        await this.socket.write(encodeChunkedFrame(tail));
                    }
                }
                if (this.chunkedEncoding) {
                    await this.socket.write(encodeChunkedTrailer());
                    this.chunkedEncoding = false;
                }
                // Unframed body (1.0 / handler-supplied TE): EOF is the only terminator.
                else if (!this.responseFramed) this.keepAlive = false;
            }
        } catch (err) {
            const e = err instanceof Error ? err : new Error(String(err));
            this.markTransportError(e);
            throw e;
        }
        this.compressor = null; this.compressEncoding = null; this.responseEnded = true;
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
        // Pending body/waiters: local close looks like peer EOF to upper layers.
        if (!this.ended) this.failBody(this.transportError ?? this.peerClosedError());
        this.socket.close();
        this.events.onClose?.();
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
    private events: ProtocolConnectionEvents = { onstream: null, onError: null, onClose: null, onGoaway: null, onSettings: null };

    constructor(socket: TcpSocket, secure: boolean) { this.socket = socket; this.secure = secure; }

    async sendRequest(req: HttpRequestBuilder): Promise<RawResponse> {
        await this.socket.write(req.build());
        this.parser = new HttpResponseParser();
        return this.driveParser(this.parser);
    }
    receive(_d: Uint8Array): void { }
    wantWrite(): boolean { return false; }
    flush(): Uint8Array | null { return null; }
    createStream(): ProtocolStream { return new H1Stream(this, false); }
    on(events: Partial<ProtocolConnectionEvents>): void { Object.assign(this.events, events); }
    goaway(): void { this.close(); }
    close(): void { this.socket.close(); }
    destroy(): void { this.socket.close(); }
    async readResponse(): Promise<RawResponse> {
        // Drive the parser until the response is complete.
        if (!this.parser) this.parser = new HttpResponseParser();
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
            const d = await this.socket.read();
            if (!d) {
                // A close-delimited response (no CL, no chunked) legitimately ends at EOF:
                // tell llhttp so it can complete the message before we judge it.
                parser.finishOnEof();
                if (parser.isCompleted) break;
                throw error.Error(error.errno.ECONNRESET);
            }
            parser.feed(d);
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
        const b = new HttpRequestBuilder({ method: req.method, path: req.url, body: req.body as Uint8Array | null });
        for (const [k, v] of req.headers) b.setHeader(k, v);
        return (conn as H1ClientConnection).sendRequest(b);
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
