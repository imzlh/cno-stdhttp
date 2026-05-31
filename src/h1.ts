/**
 * HTTP/1.x protocol implementation — low-level, no WebAPI dependencies.
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

import { TcpSocket } from "./socket";
import {
    type ProtocolClient, type ProtocolServer, type ProtocolConnection,
    type ProtocolStream, type RawRequest, type RawResponse,
    type ProtocolClientConfig, type ProtocolServerConfig,
    type ProtocolConnectionEvents,
    HttpVersion, ALPN,
} from "./protocol";
import { StreamingDecompressor, StreamingCompressor, parseAcceptEncoding, pickEncoding, shouldCompress } from "./zlib";

type Uint8Array = globalThis.Uint8Array<ArrayBuffer>;

function assert(condition: unknown, message?: string): asserts condition {
    if (!condition) throw new Error(message ?? "Assertion failed");
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
        if (!this.headers.find(([n]) => n === 'connection'))
            this.setHeader('connection', this.httpVersion === '1.0' ? 'close' : 'keep-alive');

        const path = this.useFullUrl ?? this.path;
        let request = `${this.method} ${path} HTTP/${this.httpVersion}\r\n`;
        for (const [k, v] of this.headers) { if (k && v) request += `${k}: ${v}\r\n`; }
        request += '\r\n';

        const headerBytes = engine.encodeString(request);
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
        const decode = (buf: any, off: number, len: number) =>
            engine.decodeString(new Uint8Array(buf as ArrayBuffer).slice(off, off + len));
        this.parser.onStatus = (buf, off, len) => { this.statusText = decode(buf, off, len); };
        this.parser.onHeaderField = (buf, off, len) => { this.currentHeaderField = decode(buf, off, len).toLowerCase(); };
        this.parser.onHeaderValue = (buf, off, len) => { this.headers.push([this.currentHeaderField, decode(buf, off, len)]); this.currentHeaderField = ''; };
        this.parser.onHeadersComplete = () => {
            this.statusCode = this.parser.state.status; this.headersComplete = true;
            if (!this.statusText) this.statusText = strstatus(this.statusCode);
            const major = (this.parser.state as any).http_major ?? 1;
            const minor = (this.parser.state as any).http_minor ?? 1;
            this.httpVersion = `${major}.${minor}`;
            const ce = this.headers.find(([n]) => n === 'content-encoding');
            if (ce) this.decompressor = new StreamingDecompressor(ce[1]);
            this.onHeadersComplete?.(this.statusCode, this.headers);
        };
        this.parser.onBody = (buf, off, len) => {
            let view = new Uint8Array(buf as ArrayBuffer).slice(off, off + len);
            if (this.decompressor?.isActive) view = this.decompressor.decompress(view);
            if (!this.onData) this.bodyChunks.push(view);
            this.onData?.(view);
        };
        this.parser.onMessageComplete = () => { this.completed = true; this.onComplete?.(); };
    }

    feed(data: Uint8Array): void {
        try {
            const result = this.parser.execute(data.buffer.slice(data.byteOffset, data.length + data.byteOffset));
            if (result.errno !== 0) { const e = new Error(`HTTP parse error: ${result.reason}`); if (this.onError) this.onError(e); else throw e; }
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
    async writeData(data: Uint8Array): Promise<void> { if (this.isServer) (this.conn as H1ServerConnection).writeData(data); }
    async end(data?: Uint8Array): Promise<void> { if (this.isServer) (this.conn as H1ServerConnection).endResponse(data); }
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
    protected socket: TcpSocket;
    private parser: CModuleHTTP.Parser;
    private method = ''; private url = ''; private reqHeaders: Array<[string, string]> = [];
    private headerField = ''; private headersOk = false;
    private expectBody = false; private contentLength = 0; private chunked = false;
    private bodyRead = 0; private bodyCtrl: ((chunk: Uint8Array) => void) | null = null;
    private bodyEnd: (() => void) | null = null;
    private headersSent = false; private responseEnded = false; private chunkedEncoding = false;
    private compressEncoding: 'gzip' | 'deflate' | null = null;
    private compressor: StreamingCompressor | null = null;
    private requestCount = 0; private keepAlive = true; private requestHttpVersion = '1.1';
    private _closed = false;
    private events: ProtocolConnectionEvents = { onstream: null, onError: null, onClose: null, onGoaway: null, onSettings: null };

    constructor(socket: TcpSocket, secure: boolean) { this.socket = socket; this.secure = secure; this.parser = new http.Parser(http.REQUEST); this.setupParser(); }

    isClosed(): boolean { return this._closed; }

    private setupParser(): void {
        const decode = (buf: any, off: number, len: number) => engine.decodeString(new Uint8Array(buf as ArrayBuffer).slice(off, off + len));
        this.parser.onUrl = (buf, off, len) => { this.url += decode(buf, off, len); };
        this.parser.onHeaderField = (buf, off, len) => { this.headerField = decode(buf, off, len).toLowerCase(); };
        this.parser.onHeaderValue = (buf, off, len) => { this.reqHeaders.push([this.headerField, decode(buf, off, len)]); };
        this.parser.onHeadersComplete = () => {
            this.method = HTTP_METHODS[this.parser.state.method] ?? 'UNKNOWN'; this.headersOk = true;
            const connH = this.reqHeaders.find(([n]) => n === 'connection')?.[1]?.toLowerCase();
            const ver = `${this.parser.state.httpMajor}.${this.parser.state.httpMinor}`;
            this.keepAlive = ver === '1.1' ? connH !== 'close' : connH === 'keep-alive';
            const ae = this.reqHeaders.find(([n]) => n === 'accept-encoding')?.[1];
            if (ae) this.compressEncoding = pickEncoding(parseAcceptEncoding(ae));
            const cl = this.reqHeaders.find(([n]) => n === 'content-length')?.[1];
            const te = this.reqHeaders.find(([n]) => n === 'transfer-encoding')?.[1];
            if (cl) { this.contentLength = parseInt(cl); this.expectBody = this.contentLength > 0; }
            else if (te?.toLowerCase().includes('chunked')) { this.chunked = true; this.expectBody = true; }
        };
        this.parser.onBody = (buf, off, len) => { if (this.bodyCtrl) this.bodyCtrl(new Uint8Array(buf as ArrayBuffer).slice(off, off + len)); this.bodyRead += len; if (!this.chunked && this.bodyRead >= this.contentLength && this.bodyEnd) { this.bodyEnd(); this.bodyCtrl = null; this.bodyEnd = null; } };
        this.parser.onMessageComplete = () => { if (this.bodyEnd) { this.bodyEnd(); this.bodyCtrl = null; this.bodyEnd = null; } };
    }

    async handleRequest(handler: (req: RawRequest, res: RawResponse) => void | Promise<void>): Promise<boolean> {
        this.method = ''; this.url = ''; this.reqHeaders = []; this.headerField = ''; this.headersOk = false;
        this.expectBody = false; this.contentLength = 0; this.chunked = false; this.bodyRead = 0;
        this.headersSent = false; this.responseEnded = false;
        this.chunkedEncoding = false; this.compressEncoding = null; this.compressor = null;

        // Set up body collection before any execute() — headers and body may arrive
        // in the same TCP segment (coalescing), so we can't set this up after headers.
        const bodyChunks: Uint8Array[] = [];
        let messageDone = false;
        this.bodyCtrl = (chunk) => bodyChunks.push(chunk);
        this.bodyEnd  = () => { messageDone = true; this.bodyCtrl = null; this.bodyEnd = null; };

        // Single loop: reads until we have headers (for GET) or full message (for POST).
        while (true) {
            // After headers: if no body expected the message is logically done.
            if (this.headersOk && !this.expectBody) break;
            // After headers + body via coalesced packet.
            if (messageDone) break;

            const data = await this.socket.read();
            if (data === null) {
                if (!this.headersOk) return false;
                break; // EOF mid-body — handler will see partial body
            }
            if (data.length === 0) continue;

            const r = this.parser.execute(data.buffer.slice(data.byteOffset, data.byteLength + data.byteOffset));
            if (r.errno !== 0) {
                if (r.name === 'HPE_PAUSED_UPGRADE') { this.keepAlive = false; break; }
                throw new Error(`Parse error: ${r.reason}`);
            }
        }

        this.bodyCtrl = null; this.bodyEnd = null;

        let body: Uint8Array | null = null;
        if (bodyChunks.length > 0) {
            const total = bodyChunks.reduce((s, c) => s + c.length, 0);
            body = new Uint8Array(total); let off = 0;
            for (const c of bodyChunks) { body.set(c, off); off += c.length; }
        }

        const req: RawRequest = { method: this.method, url: this.url, httpVersion: `${this.parser.state.httpMajor}.${this.parser.state.httpMinor}`, headers: this.reqHeaders, body };
        const res: RawResponse = { status: 200, statusText: 'OK', headers: [], body: null };
        await handler(req, res);
        this.parser.reset(http.REQUEST); this.requestCount++;
        return this.keepAlive;
    }

    async writeHead(status: number, statusText: string, headers: Array<[string, string]>): Promise<void> {
        if (this.headersSent) throw new Error("Headers already sent");
        const te = headers.find(([n]) => n === 'transfer-encoding')?.[1];
        if (te?.toLowerCase().includes('chunked')) this.chunkedEncoding = true;
        if (this.compressEncoding && !headers.find(([n]) => n === 'content-encoding') && !this.chunkedEncoding) {
            const ct = headers.find(([n]) => n === 'content-type')?.[1];
            if (!ct || shouldCompress(ct)) { this.compressor = new StreamingCompressor(this.compressEncoding); headers.push(['content-encoding', this.compressEncoding]); headers.push(['transfer-encoding', 'chunked']); headers = headers.filter(([n]) => n !== 'content-length'); this.chunkedEncoding = true; }
        }
        let raw = `HTTP/${this.requestHttpVersion} ${status} ${statusText}\r\n`;
        if (!headers.find(([n]) => n === 'connection')) raw += this.keepAlive ? "Connection: keep-alive\r\n" : "Connection: close\r\n";
        for (const [k, v] of headers) raw += `${k}: ${v}\r\n`;
        raw += "\r\n";
        await this.socket.write(engine.encodeString(raw));
        this.headersSent = true;
    }

    async writeData(chunk: Uint8Array | string): Promise<void> {
        if (this.responseEnded) throw new Error("Response already ended");
        if (!this.headersSent) { if (this.requestHttpVersion === "1.0") { this.keepAlive = false; await this.writeHead(200, "OK", []); } else { this.chunkedEncoding = true; await this.writeHead(200, "OK", [['transfer-encoding', 'chunked']]); } }
        let data = typeof chunk === "string" ? engine.encodeString(chunk) : chunk;
        if (this.compressor) data = this.compressor.compress(data);
        if (this.chunkedEncoding) { await this.socket.write(engine.encodeString(data.length.toString(16) + "\r\n")); await this.socket.write(data); await this.socket.write(engine.encodeString("\r\n")); }
        else await this.socket.write(data);
    }

    async endResponse(chunk?: Uint8Array | string): Promise<void> {
        if (this.responseEnded) return;
        if (chunk !== undefined) await this.writeData(chunk);
        else if (!this.headersSent) await this.writeHead(200, "OK", [['content-length', '0']]);
        if (this.compressor) {
            const tail = this.compressor.finish();
            if (tail.length > 0 && this.chunkedEncoding) {
                await this.socket.write(engine.encodeString(tail.length.toString(16) + "\r\n"));
                await this.socket.write(tail);
                await this.socket.write(engine.encodeString("\r\n"));
            }
        }
        if (this.chunkedEncoding) { await this.socket.write(engine.encodeString("0\r\n\r\n")); this.chunkedEncoding = false; }
        this.compressor = null; this.compressEncoding = null; this.responseEnded = true;
    }

    receive(_d: Uint8Array): void {}
    wantWrite(): boolean { return false; }
    flush(): Uint8Array | null { return null; }
    createStream(): ProtocolStream { return new H1Stream(this, true); }
    on(events: Partial<ProtocolConnectionEvents>): void { Object.assign(this.events, events); }
    goaway(): void { this.close(); }
    close(): void { this._closed = true; this.socket.close(); }
    destroy(): void { this._closed = true; this.socket.close(); }
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
    receive(_d: Uint8Array): void {}
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
    async accept(socket: TcpSocket, config: ProtocolServerConfig): Promise<ProtocolConnection> { return new H1ServerConnection(socket, config.secure); }
    negotiate(alpn?: string): HttpVersion | null { return (!alpn || alpn === ALPN.HTTP11 || alpn === ALPN.HTTP10) ? HttpVersion.HTTP11 : null; }
}

export const h1 = { version: HttpVersion.HTTP11, client: new H1Client(), server: new H1Server() } as const;

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

function mergeChunks(chunks: Uint8Array[]): Uint8Array {
    if (chunks.length === 0) return new Uint8Array(0);
    if (chunks.length === 1) return chunks[0]!;
    const total = chunks.reduce((s, c) => s + c.length, 0);
    const merged = new Uint8Array(total); let off = 0;
    for (const c of chunks) { merged.set(c, off); off += c.length; }
    return merged;
}

const HTTP_METHODS = ["DELETE","GET","HEAD","POST","PUT","CONNECT","OPTIONS","TRACE","COPY","LOCK","MKCOL","MOVE","PROPFIND","PROPPATCH","SEARCH","UNLOCK","BIND","REBIND","UNBIND","ACL","REPORT","MKACTIVITY","CHECKOUT","MERGE","MSEARCH","NOTIFY","SUBSCRIBE","UNSUBSCRIBE","PATCH","PURGE","MKCALENDAR","LINK","UNLINK"] as const;
const STATUS_TEXT_MAP: Record<number, string> = { 100:'Continue',101:'Switching Protocols',200:'OK',201:'Created',204:'No Content',301:'Moved Permanently',302:'Found',304:'Not Modified',400:'Bad Request',401:'Unauthorized',403:'Forbidden',404:'Not Found',500:'Internal Server Error',502:'Bad Gateway',503:'Service Unavailable' };
function strstatus(code: number): string { return STATUS_TEXT_MAP[code] ?? `Status ${code}`; }
