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
} from "./h1-frame";
import { assert } from "../utils/assert";

type Uint8Array = globalThis.Uint8Array<ArrayBuffer>;

function toByteView(buf: CModuleHTTP.BufferSource): Uint8Array {
    if (buf instanceof ArrayBuffer) return new Uint8Array(buf);
    return new Uint8Array(new globalThis.Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength));
}

function decodeParserBytes(buf: CModuleHTTP.BufferSource, off: number, len: number): string {
    return engine.decodeString(toByteView(buf).slice(off, off + len));
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
        this.parser.onHeaderValue = (buf, off, len) => { this.headers.push([this.currentHeaderField, decodeParserBytes(buf, off, len)]); this.currentHeaderField = ''; };
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
        this.parser.onMessageComplete = () => { this.completed = true; this.onComplete?.(); };
    }

    feed(data: Uint8Array): CModuleHTTP.ParserExecuteResult | undefined {
        try {
            const result = this.parser.execute(data.buffer.slice(data.byteOffset, data.length + data.byteOffset));
            if (result.errno !== 0) {
                if (result.name === 'HPE_PAUSED_UPGRADE') return result;
                const e = new Error(`HTTP parse error: ${result.reason}`); if (this.onError) this.onError(e); else throw e;
            }
            return result;
        } catch (err) { if (this.onError) this.onError(err as Error); else throw err; }
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
    private parser: CModuleHTTP.Parser;
    private method = ''; private url = ''; private reqHeaders: Array<[string, string]> = [];
    private headerField = ''; private headersOk = false;
    private expectBody = false; private contentLength = 0; private chunked = false;
    private bodyRead = 0;
    private headersSent = false; private responseEnded = false; private chunkedEncoding = false;
    /** Response has explicit framing (chunked, content-length, or bodyless status/HEAD). */
    private responseFramed = false;
    private compressEncoding: 'gzip' | 'deflate' | null = null;
    private compressor: StreamingCompressor | null = null;
    private requestCount = 0; private keepAlive = true; private requestHttpVersion = '1.1';
    private _closed = false;
    private _upgraded = false;
    private upgradeLeftover: Uint8Array | null = null;
    private pendingInput: Uint8Array | null = null;
    private events: ProtocolConnectionEvents = { onstream: null, onError: null, onClose: null, onGoaway: null, onSettings: null };
    private bodyChunk: Uint8Array[] = [];
    private pendingPromise: PromiseWithResolvers<Uint8Array | null> | null = null;
    private bodyError: Error | null = null;
    /** Peer/transport fault observed on read — writers must see the same coded error. */
    private transportError: Error | null = null;
    private ended = false;

    constructor(socket: TcpSocket, secure: boolean, keepAliveTimeoutMs = 5000) {
        this.socket = socket;
        this.secure = secure;
        this.keepAliveTimeoutMs = keepAliveTimeoutMs;
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
        } else {
            this.bodyChunk.push(u8);
        }
    }

    private finishBody(): void {
        this.ended = true;
        const pending = this.pendingPromise;
        if (pending) {
            this.pendingPromise = null;
            pending.resolve(null);
        }
    }

    private failBody(err: Error): void {
        this.markTransportError(err);
        // Peer gone: end the body stream (resolve null). Rejecting would race the
        // pump and surface as unhandled rejection when no body consumer is attached.
        if (TcpSocket.isDisconnectError(err)) {
            this.finishBody();
            return;
        }
        this.bodyError = err;
        this.ended = true;
        const pending = this.pendingPromise;
        if (pending) {
            this.pendingPromise = null;
            pending.reject(err);
        }
    }

    private setupParser(): void {
        this.parser.onUrl = (buf, off, len) => { this.url += decodeParserBytes(buf, off, len); };
        this.parser.onHeaderField = (buf, off, len) => { this.headerField = decodeParserBytes(buf, off, len).toLowerCase(); };
        this.parser.onHeaderValue = (buf, off, len) => {
            this.reqHeaders.push(
                [this.headerField.toLowerCase(), decodeParserBytes(buf, off, len)]
            )
        };
        this.parser.onHeadersComplete = () => {
            this.method = HTTP_METHODS[this.parser.state.method] ?? 'UNKNOWN'; this.headersOk = true;
            const connH = this.reqHeaders.find(([n]) => n === 'connection')?.[1];
            const ver = `${this.parser.state.httpMajor}.${this.parser.state.httpMinor}`;
            this.requestHttpVersion = ver;
            this.keepAlive = wantsKeepAlive(ver, connH);
            const ae = this.reqHeaders.find(([n]) => n === 'accept-encoding')?.[1];
            if (ae) this.compressEncoding = pickEncoding(parseAcceptEncoding(ae));
            const cl = this.reqHeaders.find(([n]) => n === 'content-length')?.[1];
            const te = this.reqHeaders.find(([n]) => n === 'transfer-encoding')?.[1];
            if (cl) {
                this.contentLength = parseInt(cl); this.expectBody = this.contentLength > 0;
            } else if (te?.toLowerCase().includes('chunked')) {
                this.chunked = true; this.expectBody = true;
            }
        };
        this.parser.onBody = (buf, off, len) => {
            const u8 = toByteView(buf).subarray(off, off + len);
            this.enqueue(u8);
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
        this.bodyChunk = [];
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
                        if (this.bodyChunk.length) {
                            const chunk = this.bodyChunk.shift();
                            if (chunk !== undefined) return Promise.resolve(chunk);
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
                this.failBody(new Error(`Parse error: ${r.reason}`));
                throw new Error(`Parse error: ${r.reason}`);
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
        const headerValue = (name: string): string | undefined =>
            headers.find(([n]) => n.toLowerCase() === name)?.[1];
        const hasHeader = (name: string): boolean =>
            headers.some(([n]) => n.toLowerCase() === name);
        const isBodyForbiddenStatus = (status >= 100 && status < 200) || status === 204 || status === 304;
        if (isBodyForbiddenStatus) {
            headers = headers.filter(([n]) => {
                const key = n.toLowerCase();
                return key !== 'content-length' && key !== 'content-encoding' && key !== 'transfer-encoding';
            });
            this.chunkedEncoding = false;
            this.compressor = null;
            this.compressEncoding = null;
        }
        const te = headerValue('transfer-encoding');
        if (te?.toLowerCase().includes('chunked')) this.chunkedEncoding = true;
        if (!isBodyForbiddenStatus && this.compressEncoding && !hasHeader('content-encoding') && !this.chunkedEncoding) {
            const ct = headerValue('content-type');
            if (!ct || shouldCompress(ct)) {
                this.compressor = new StreamingCompressor(this.compressEncoding);
                headers.push(['content-encoding', this.compressEncoding]);
                headers.push(['transfer-encoding', 'chunked']);
                headers = headers.filter(([n]) => n.toLowerCase() !== 'content-length');
                this.chunkedEncoding = true;
            }
        }
        // No framing given by the handler: chunked on 1.1, close-delimited otherwise (Node parity).
        const needsFraming = !isBodyForbiddenStatus && this.method !== 'HEAD'
            && !this.chunkedEncoding && !hasHeader('content-length');
        if (needsFraming) {
            if (this.requestHttpVersion === '1.0' || hasHeader('transfer-encoding')) this.keepAlive = false;
            else this.chunkedEncoding = true;
        }
        this.responseFramed = !needsFraming || this.chunkedEncoding;
        const outHeaders = headers.slice();
        if (needsFraming && this.chunkedEncoding) outHeaders.push(['transfer-encoding', 'chunked']);
        if (!hasHeader('connection')) {
            outHeaders.push(['Connection', this.keepAlive ? 'keep-alive' : 'close']);
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
        let data = typeof chunk === "string" ? engine.encodeString(chunk) : chunk;
        if (this.compressor) data = this.compressor.compress(data);
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
        let status = 0; const headers: Array<[string, string]> = []; const chunks: Uint8Array[] = [];
        this.parser.onHeadersComplete = (code, hdrs) => { status = code; headers.push(...hdrs); };
        this.parser.onData = (chunk) => chunks.push(chunk);
        while (!this.parser.isCompleted) { const d = await this.socket.read(); if (!d) break; this.parser.feed(d); }
        return { status, statusText: strstatus(status), headers, body: mergeChunks(chunks) };
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
        let status = 0; const headers: Array<[string, string]> = []; const chunks: Uint8Array[] = [];
        this.parser.onHeadersComplete = (code, hdrs) => { status = code; headers.push(...hdrs); };
        this.parser.onData = (chunk) => chunks.push(chunk);
        while (!this.parser.isCompleted) { const d = await this.socket.read(); if (!d) break; this.parser.feed(d); }
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
        return new H1ServerConnection(socket, config.secure, config.keepAliveTimeout);
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
