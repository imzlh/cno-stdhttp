/**
 * HTTP/2 protocol adapter — nghttp2 Session + TcpSocket.
 * Implements ProtocolConnection / ProtocolStream for multiplexed streams.
 * Node:http2 and other callers sit above this; no WebAPI types here.
 */

import { TcpSocket } from './socket';
import {
    type ProtocolClient,
    type ProtocolServer,
    type ProtocolConnection,
    type ProtocolStream,
    type RawRequest,
    type RawResponse,
    type ProtocolClientConfig,
    type ProtocolServerConfig,
    type ProtocolConnectionEvents,
    type RawHeaders,
    HttpVersion,
    ALPN,
} from './protocol';
import { requireH2, type H2Session, type H2Header, type H2Settings, type H2Module } from './h2-native';

type Uint8Array = globalThis.Uint8Array<ArrayBufferLike>;

const END_STREAM = 0x1;

function ownedBytes(bytes: Uint8Array): globalThis.Uint8Array<ArrayBuffer> {
    const out = new globalThis.Uint8Array(bytes.byteLength);
    out.set(bytes);
    return out;
}

function headerMap(headers: H2Header[]): Map<string, string> {
    const m = new Map<string, string>();
    for (const [n, v] of headers) m.set(n.toLowerCase(), v);
    return m;
}

function pick(headers: H2Header[], name: string): string | undefined {
    const lower = name.toLowerCase();
    for (const [n, v] of headers) {
        if (n.toLowerCase() === lower) return v;
    }
    return undefined;
}

function toRawHeaders(headers: H2Header[]): RawHeaders {
    return headers.map(([n, v]) => [n, v]);
}

function mergeChunks(chunks: Uint8Array[]): Uint8Array | null {
    if (chunks.length === 0) return null;
    if (chunks.length === 1) return chunks[0]!;
    let n = 0;
    for (const c of chunks) n += c.byteLength;
    const out = new Uint8Array(n);
    let off = 0;
    for (const c of chunks) {
        out.set(c, off);
        off += c.byteLength;
    }
    return out;
}

function isRawRequest(data: RawRequest | RawResponse): data is RawRequest {
    return 'method' in data && typeof data.method === 'string';
}

/* ── per-stream state ─────────────────────────────────────────── */

export class H2Stream implements ProtocolStream {
    readonly id: number;
    private readonly conn: H2Connection;
    private readonly isServer: boolean;
    private headers: H2Header[] | null = null;
    private chunks: Uint8Array[] = [];
    private bodyCursor = 0;
    private ended = false;
    private closed = false;
    private headSent = false;
    private messageWaiters: Array<{
        resolve: (v: RawRequest | RawResponse) => void;
        reject: (e: Error) => void;
    }> = [];
    private headerWaiters: Array<(headers: H2Header[], ended: boolean) => void> = [];
    private dataWaiters: Array<() => void> = [];
    private bodyOnce: Uint8Array | null | undefined;
    private trailers: H2Header[][] = [];
    private streamError: Error | null = null;
    private errorListeners: Array<(error: Error) => void> = [];

    constructor(conn: H2Connection, id: number, isServer: boolean) {
        this.conn = conn;
        this.id = id;
        this.isServer = isServer;
    }

    acceptHeaders(headers: H2Header[], flags: number): void {
        this.headers = headers;
        if (flags & END_STREAM) this.ended = true;
        const cbs = this.headerWaiters.splice(0);
        for (const cb of cbs) cb(headers, this.ended);
        this.tryResolveMessage();
    }

    acceptData(chunk: Uint8Array, endStream: boolean): void {
        if (chunk.byteLength > 0) this.chunks.push(chunk);
        if (endStream) this.ended = true;
        this.wakeData();
        this.tryResolveMessage();
    }

    acceptTrailers(headers: H2Header[], flags: number): void {
        this.trailers.push(headers);
        if (flags & END_STREAM) this.ended = true;
        this.wakeData();
        this.tryResolveMessage();
    }

    acceptEnd(): void {
        if (this.ended) return;
        this.ended = true;
        this.wakeData();
        this.tryResolveMessage();
    }

    acceptClose(errorCode: number): void {
        if (errorCode !== 0) {
            this.setStreamError(Object.assign(
                new Error(`HTTP/2 stream closed with error code ${errorCode}`),
                { code: 'ERR_HTTP2_STREAM_ERROR', errno: errorCode },
            ));
        }
        this.closed = true;
        this.ended = true;
        this.wakeData();
        this.tryResolveMessage();
    }

    acceptConnectionError(error: Error): void {
        this.setStreamError(error);
        this.closed = true;
        this.ended = true;
        this.wakeData();
        this.tryResolveMessage();
    }

    private setStreamError(error: Error): void {
        if (this.streamError) return;
        this.streamError = error;
        const listeners = this.errorListeners.splice(0);
        for (const listener of listeners) listener(error);
    }

    private wakeData(): void {
        const w = this.dataWaiters.splice(0);
        for (const fn of w) fn();
    }

    private tryResolveMessage(): void {
        if (this.streamError) {
            const waiters = this.messageWaiters.splice(0);
            for (const waiter of waiters) waiter.reject(this.streamError);
            return;
        }
        if (!this.headers || (!this.ended && !this.closed)) return;
        if (this.messageWaiters.length === 0) return;
        const msg = this.buildMessage();
        const waiters = this.messageWaiters.splice(0);
        for (const w of waiters) w.resolve(msg);
    }

    private buildMessage(): RawRequest | RawResponse {
        const headers = this.headers ?? [];
        const body = mergeChunks(this.chunks);
        if (this.isServer) {
            let delivered = false;
            return {
                method: pick(headers, ':method') ?? 'GET',
                url: pick(headers, ':path') ?? '/',
                headers: toRawHeaders(headers.filter(([n]) => !n.startsWith(':'))),
                body: body
                    ? async () => {
                          if (delivered) return null;
                          delivered = true;
                          return body;
                      }
                    : null,
                httpVersion: '2.0',
            };
        }
        return {
            status: Number(pick(headers, ':status') ?? '0'),
            statusText: '',
            headers: toRawHeaders(headers.filter(([n]) => !n.startsWith(':'))),
            body,
        };
    }

    async readMessage(): Promise<RawRequest | RawResponse> {
        if (this.streamError) throw this.streamError;
        if (this.headers && (this.ended || this.closed)) return this.buildMessage();
        return new Promise((resolve, reject) => {
            this.messageWaiters.push({ resolve, reject });
        });
    }

    whenHeaders(cb: (headers: H2Header[], ended: boolean) => void): void {
        if (this.headers) {
            cb(this.headers, this.ended);
            return;
        }
        this.headerWaiters.push(cb);
    }

    whenError(cb: (error: Error) => void): void {
        if (this.streamError) {
            cb(this.streamError);
            return;
        }
        this.errorListeners.push(cb);
    }

    async *bodyChunks(): AsyncGenerator<Uint8Array> {
        for (;;) {
            while (this.bodyCursor < this.chunks.length) {
                yield this.chunks[this.bodyCursor]!;
                this.bodyCursor++;
            }
            if (this.streamError) throw this.streamError;
            if (this.ended || this.closed) return;
            await new Promise<void>(r => this.dataWaiters.push(r));
        }
    }

    takeBody(): Uint8Array | null {
        if (this.bodyOnce !== undefined) return this.bodyOnce;
        this.bodyOnce = mergeChunks(this.chunks);
        return this.bodyOnce;
    }

    get remoteEnded(): boolean {
        return this.ended || this.closed;
    }

    get headerList(): H2Header[] | null {
        return this.headers;
    }

    get trailerList(): H2Header[][] {
        return this.trailers;
    }

    async writeHead(data: RawRequest | RawResponse): Promise<void> {
        if (this.headSent) throw new Error('HTTP/2 headers already sent');
        this.headSent = true;
        const sess = this.conn.session;
        if (isRawRequest(data)) {
            const headers: H2Header[] = [
                [':method', data.method],
                [':path', data.url],
                [':scheme', this.conn.secure ? 'https' : 'http'],
                ...data.headers.filter(([n]) => !n.startsWith(':')),
            ];
            // client stream already created via request(); this path is for createStream+writeHead
            sess.respond(this.id, headers, !data.body);
        } else {
            const headers: H2Header[] = [
                [':status', String(data.status)],
                ...data.headers,
            ];
            const end = data.body === null || data.body.byteLength === 0;
            sess.respond(this.id, headers, end);
            if (data.body && data.body.byteLength > 0) {
                sess.write(this.id, data.body, true);
            }
        }
    }

    async writeData(data: Uint8Array): Promise<void> {
        this.conn.session.write(this.id, data, false);
    }

    async end(data?: Uint8Array): Promise<void> {
        if (data && data.byteLength > 0) {
            this.conn.session.write(this.id, data, true);
        } else if (!this.headSent && this.isServer) {
            // empty response
            this.conn.session.respond(this.id, [[':status', '200']], true);
            this.headSent = true;
        } else {
            this.conn.session.write(this.id, new Uint8Array(0), true);
        }
    }

    /** Server: respond with headers (+ optional body end). */
    respond(headers: H2Header[], endStream = false): void {
        this.headSent = true;
        this.conn.session.respond(this.id, headers, endStream);
    }

    /** Client: headers already submitted via session.request. */
    markHeadSent(): void {
        this.headSent = true;
    }

    sendData(data: Uint8Array, endStream = false): void {
        this.conn.session.write(this.id, data, endStream);
    }

    abort(code = 0): void {
        this.conn.session.reset(this.id, code);
    }

    close(): void {
        if (!this.closed) this.conn.session.reset(this.id, 0);
    }
}

/* ── connection ───────────────────────────────────────────────── */

export class H2Connection implements ProtocolConnection {
    readonly version = HttpVersion.HTTP2;
    readonly secure: boolean;
    readonly session: H2Session;
    private readonly socket: TcpSocket;
    private readonly isServer: boolean;
    private readonly dataFrameType: number;
    private readonly streams = new Map<number, H2Stream>();
    private events: ProtocolConnectionEvents = {
        onstream: null,
        onError: null,
        onClose: null,
        onGoaway: null,
        onSettings: null,
    };
    private _closed = false;
    /** Node-level stream open hook (server). */
    onStreamOpen: ((stream: H2Stream) => void) | null = null;
    /** Client: response headers for a stream. */
    onClientHeaders: ((stream: H2Stream, headers: H2Header[], ended: boolean) => void) | null = null;

    constructor(socket: TcpSocket, isServer: boolean, secure: boolean, settings?: H2Settings) {
        this.socket = socket;
        this.isServer = isServer;
        this.secure = secure;
        const h2 = requireH2();
        this.dataFrameType = h2.constants.DATA;
        this.session = new h2.Session(isServer, settings);
        this.wireSession();
        this.wireSocket();
    }

    private wireSession(): void {
        const sess = this.session;
        // onsend first: C Session queues preface/SETTINGS until this is set,
        // then auto-flushes. Later request/respond/receive also session_send.
        sess.onsend = (chunk: Uint8Array) => {
            void this.socket.write(ownedBytes(chunk)).catch(e => {
                this.events.onError?.(e instanceof Error ? e : new Error(String(e)));
            });
        };
        sess.onstream = (streamId: number, headers: H2Header[], flags: number) => {
            let stream = this.streams.get(streamId);
            if (!stream) {
                stream = new H2Stream(this, streamId, this.isServer);
                this.streams.set(streamId, stream);
                if (this.isServer) {
                    this.events.onstream?.(stream);
                    this.onStreamOpen?.(stream);
                }
            }
            stream.acceptHeaders(headers, flags);
            if (!this.isServer) {
                this.onClientHeaders?.(stream, headers, !!(flags & END_STREAM));
            }
        };
        sess.ondata = (streamId: number, chunk: Uint8Array, endStream: boolean) => {
            const stream = this.streams.get(streamId);
            if (stream) stream.acceptData(chunk, endStream);
        };
        sess.onheaders = (streamId: number, headers: H2Header[], flags: number) => {
            const stream = this.streams.get(streamId);
            if (stream) stream.acceptTrailers(headers, flags);
        };
        // nghttp2 does not invoke ondata for an empty DATA frame. Observe the
        // frame itself so an empty request/response still reaches EOF.
        sess.onframe = (frameType: number, streamId: number, flags: number) => {
            if (frameType !== this.dataFrameType || !(flags & END_STREAM)) return;
            this.streams.get(streamId)?.acceptEnd();
        };
        sess.onclose = (streamId: number, errorCode: number) => {
            const stream = this.streams.get(streamId);
            if (stream) stream.acceptClose(errorCode);
            this.streams.delete(streamId);
        };
        sess.ongoaway = () => {
            this.events.onGoaway?.();
        };
        sess.onsettings = (isAck: boolean) => {
            if (isAck) this.events.onSettings?.();
        };
        sess.onerror = (_code: number, message: string) => {
            this.events.onError?.(new Error(message || 'HTTP/2 error'));
        };
    }

    private wireSocket(): void {
        this.socket.onReadable(
            data => {
                if (data === null) {
                    this.destroy();
                    return;
                }
                try {
                    this.session.receive(data);
                } catch (e) {
                    this.events.onError?.(e instanceof Error ? e : new Error(String(e)));
                    this.destroy();
                }
            },
            err => {
                this.events.onError?.(err);
                this.destroy();
            },
        );
    }

    /** Client: open a request stream. */
    request(headers: H2Header[], endStream = false): H2Stream {
        const id = this.session.request(headers, endStream);
        const stream = new H2Stream(this, id, false);
        stream.markHeadSent();
        this.streams.set(id, stream);
        return stream;
    }

    getStream(id: number): H2Stream | undefined {
        return this.streams.get(id);
    }

    receive(data: Uint8Array): void {
        this.session.receive(data);
    }

    wantWrite(): boolean {
        return this.session.wantWrite;
    }

    flush(): Uint8Array | null {
        return null;
    }

    createStream(): ProtocolStream {
        throw new Error('HTTP/2 client streams are created via request()');
    }

    on(events: Partial<ProtocolConnectionEvents>): void {
        Object.assign(this.events, events);
    }

    goaway(): void {
        try {
            this.session.goaway(0);
        } catch {
            /* destroyed */
        }
    }

    close(): void {
        if (this._closed) return;
        this._closed = true;
        try {
            this.session.goaway(0);
        } catch {
            /* */
        }
        try {
            this.session.destroy();
        } catch {
            /* */
        }
        for (const stream of this.streams.values()) {
            stream.acceptConnectionError(new Error('HTTP/2 connection closed'));
        }
        this.streams.clear();
        this.socket.close();
        this.events.onClose?.();
    }

    destroy(): void {
        if (this._closed) return;
        this._closed = true;
        try {
            this.session.destroy();
        } catch {
            /* */
        }
        for (const stream of this.streams.values()) {
            stream.acceptConnectionError(new Error('HTTP/2 connection terminated'));
        }
        this.streams.clear();
        this.socket.close();
        this.events.onClose?.();
    }
}

/* ── protocol module ──────────────────────────────────────────── */

class H2Client implements ProtocolClient {
    readonly version = HttpVersion.HTTP2;

    async connect(socket: TcpSocket, c: ProtocolClientConfig): Promise<ProtocolConnection> {
        requireH2();
        return new H2Connection(socket, false, c.secure, {
            maxConcurrentStreams: c.maxConcurrentStreams,
            initialWindowSize: c.initialWindowSize,
        });
    }

    async request(conn: ProtocolConnection, req: RawRequest): Promise<RawResponse> {
        if (!(conn instanceof H2Connection)) {
            throw new TypeError('HTTP/2 request requires H2Connection');
        }
        const authority = req.headers.find(([name]) => name.toLowerCase() === 'host')?.[1];
        const headers: H2Header[] = [
            [':method', req.method],
            [':path', req.url],
            [':scheme', conn.secure ? 'https' : 'http'],
            ...(authority ? [[':authority', authority] as H2Header] : []),
            ...req.headers.filter(([n]) => !n.startsWith(':')),
        ];
        const stream = conn.request(headers, req.body === null);
        if (req.body) {
            try {
                for (;;) {
                    const chunk = await req.body();
                    if (chunk === null) break;
                    if (chunk.byteLength > 0) stream.sendData(chunk, false);
                }
                stream.sendData(new Uint8Array(0), true);
            } catch (error) {
                stream.abort();
                throw error;
            }
        }
        const msg = await stream.readMessage();
        if (isRawRequest(msg)) throw new Error('unexpected request on client stream');
        return msg;
    }
}

class H2Server implements ProtocolServer {
    readonly version = HttpVersion.HTTP2;

    async accept(socket: TcpSocket, config: ProtocolServerConfig): Promise<ProtocolConnection> {
        requireH2();
        return new H2Connection(socket, true, config.secure, {
            maxConcurrentStreams: config.maxConcurrentStreams,
        });
    }

    negotiate(alpn?: string): HttpVersion | null {
        if (alpn === ALPN.HTTP2 || alpn === ALPN.HTTP2C) return HttpVersion.HTTP2;
        // cleartext prior-knowledge: no ALPN
        if (!alpn) return HttpVersion.HTTP2;
        return null;
    }
}

export const h2: {
    version: HttpVersion;
    client: ProtocolClient;
    server: ProtocolServer;
    Connection: typeof H2Connection;
    Stream: typeof H2Stream;
    requireH2: typeof requireH2;
} = {
    version: HttpVersion.HTTP2,
    client: new H2Client(),
    server: new H2Server(),
    Connection: H2Connection,
    Stream: H2Stream,
    requireH2,
};

export type { H2Module, H2Header, H2Settings };
