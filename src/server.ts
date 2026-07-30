/**
 * Core Server Layer
 *
 * Accepts connections and serves HTTP/1.x and HTTP/2 (when ext-h2 is linked).
 * Routes via ALPN (TLS) or configured protocols (cleartext h2c when only HTTP/2).
 *
 * Architecture:
 *   TCP accept -> optional TLS+ALPN -> H1 loop or H2 multiplexed streams
 */

type Uint8Array = globalThis.Uint8Array<ArrayBuffer>;
type NativeTcpCarrier = { __cnoTcp?: CModuleStreams.Stream };

function isTcpStream(stream: CModuleStreams.Stream): stream is CModuleStreams.TCP {
    return 'setNoDelay' in stream && 'setKeepAlive' in stream;
}

import { TcpSocket, type ISocket } from "./socket";
import { h1, H1ServerConnection } from "./h1";
import { h2, type H2Connection, type H2Stream } from "./h2";
import { h2Available } from "./h2-native";
import {
    type RawRequest, type RawResponse,
    type ProtocolConnection, type ProtocolServerConfig, type ProtocolClientConfig,
    HttpVersion, ALPN, defaultAlpnProtocols,
    type StreamPoll
} from "./protocol";
import { assert } from "../utils/assert";

const console = import.meta.use('console');
const engine = import.meta.use('engine');
const os = import.meta.use('os');
const ssl = import.meta.use('ssl');
const streams = import.meta.use('streams');
const timers = import.meta.use('timers');

/* ------------------------------------------------------------------ */
/* Types                                                              */
/* ------------------------------------------------------------------ */

export interface ServerConfig {
    hostname?: string;
    port: number;
    path?: string;
    cert?: string;
    key?: string;
    keepAliveTimeout?: number;
    maxRequestsPerConnection?: number;
    requestTimeout?: number;
    protocols?: HttpVersion[];
    maxHeadersCount?: number;
    maxConnections?: number;
}

export type RequestHandler = (req: HttpRequest, res: HttpResponse) => void | Promise<void>;

export interface HttpRequest {
    method: string;
    url: string;
    httpVersion: string;
    headers: Array<[string, string]>;
    body: StreamPoll | null;
}

export interface HttpResponse {
    status: number;
    statusText: string;
    headers: Array<[string, string]>;
    writeHead(status: number, statusText?: string, headers?: Array<[string, string]>): Promise<void>;
    write(chunk: Uint8Array | string): Promise<void>;
    end(chunk?: Uint8Array | string): Promise<void>;
    upgrade(): UpgradedConnection;
    close(): void;
}

export interface UpgradedConnection extends ISocket {
    socket: TcpSocket;
    sslPipe: CModuleSSL.Pipe | null;
    isClosed(): boolean;
}

interface IProtocol {
    client: {
        connect(socket: TcpSocket, config: ProtocolClientConfig): Promise<ProtocolConnection>;
    };
    server: {
        accept(socket: TcpSocket, config: ProtocolServerConfig): Promise<ProtocolConnection>;
        negotiate(alpn?: string): HttpVersion | null;
    };
}

/* ------------------------------------------------------------------ */
/* Protocol registry NOTE: add H3 here when ready                     */
/* ------------------------------------------------------------------ */

const PROTOCOL_MODULES = new Map<HttpVersion, IProtocol>([
    [HttpVersion.HTTP11, h1],
]);
if (h2Available()) {
    PROTOCOL_MODULES.set(HttpVersion.HTTP2, h2);
}

/* ------------------------------------------------------------------ */
/* Server                                                             */
/* ------------------------------------------------------------------ */

export class Server {
    public readonly config: Required<ServerConfig>;
    public readonly handler: RequestHandler;
    public onRequestError: ((error: Error, socket: TcpSocket) => void) | null = null;

    private listener: CModuleStreams.TCP | CModuleStreams.Pipe | null = null;
    private sslContext: CModuleSSL.Context | null = null;
    private connections = new Set<ProtocolConnection>();
    private listening = false;
    private draining = false;
    private drainResolve: (() => void) | null = null;
    private _drainResolved = false;

    private _completeDrain(): void {
        if (!this._drainResolved && this.drainResolve) {
            this._drainResolved = true;
            this.drainResolve();
        }
    }

    constructor(handler: RequestHandler, config: ServerConfig) {
        this.handler = handler;
        this.config = {
            hostname: config.hostname ?? "0.0.0.0",
            port: config.port,
            path: config.path ?? "",
            cert: config.cert ?? "",
            key: config.key ?? "",
            keepAliveTimeout: config.keepAliveTimeout ?? 60000,
            maxRequestsPerConnection: config.maxRequestsPerConnection ?? 100,
            requestTimeout: config.requestTimeout ?? 300000,
            protocols: config.protocols ?? [HttpVersion.HTTP11],
            maxHeadersCount: config.maxHeadersCount ?? 2000,
            maxConnections: config.maxConnections ?? 0,
        };
    }

    listen(): void {
        assert(!this.listening, "Server already listening");
        if (this.config.cert && this.config.key) {
            const alpn = defaultAlpnProtocols(this.config.protocols);
            this.sslContext = new ssl.Context({
                mode: "server",
                cert: this.config.cert,
                key: this.config.key,
                alpn: alpn.length > 0 ? alpn : undefined,
            });
        }
        if (this.config.path) {
            this.listener = new streams.Pipe();
            this.listener.bind(this.config.path);
        } else {
            const family = this.config.hostname.includes(':') ? os.AF_INET6 : os.AF_INET;
            this.listener = new streams.TCP(family);
            this.listener.bind({ ip: this.config.hostname, port: this.config.port });
        }
        this.listener.listen(511);
        // Update config with the actual bound port (OS-assigned when port was 0)
        if (!this.config.path) {
            const sn = (this.listener as CModuleStreams.TCP).sockname;
            if (sn) this.config.port = sn.port;
        }
        this.listening = true;
    }

    async acceptLoop(): Promise<void> {
        assert(this.listener, "Server not listening");
        const listener = this.listener;
        const proto = this.sslContext ? "https" : "http";
        console.debug(`Server listening on ${proto}://${this.config.hostname}:${this.config.port}`);

        listener.onconnection = (error: CModuleError.Error | undefined, client: CModuleStreams.Stream | undefined) => {
            if (error) {
                if (!this.listening || TcpSocket.isDisconnectError(error)) return;
                return console.error("Accept error:", error);
            }
            if (!client) return;
            if (this.draining) { client.close(); return; }
            // Max connections: reject new connections once at capacity (DoS backpressure).
            if (this.config.maxConnections > 0 && this.connections.size >= this.config.maxConnections) {
                client.close();
                return;
            }
            if (isTcpStream(client)) {
                client.setNoDelay(true);
                client.setKeepAlive(true, 1000);
            }
            const tcpSocket = new TcpSocket(client);
            this.handleConnection(tcpSocket).catch((e: Error) => {
                // Handshake/negotiation rejects before registration: close or the fd leaks.
                tcpSocket.close();
                if (!TcpSocket.isDisconnectError(e)) console.error("Connection error:", e);
            });
        };
    }

    close(): void {
        if (!this.listening) return;
        this.listening = false;
        for (const conn of this.connections) conn.close();
        this.connections.clear();
        this.listener?.close();
        this.listener = null;
    }

    async shutdown(): Promise<void> {
        if (this.draining) return;
        this.draining = true;
        const drainPromise = new Promise<void>(resolve => { this.drainResolve = resolve; });
        this.listener?.close(); this.listener = null; this.listening = false;
        for (const conn of this.connections) conn.close();
        if (this.connections.size === 0) this._completeDrain();
        return drainPromise;
    }

    address(): { ip: string; port: number } | { path: string } | null {
        if (!this.listener) return null;
        if (this.config.path) return { path: (this.listener as CModuleStreams.Pipe).getsockname() };
        return (this.listener as CModuleStreams.TCP).sockname;
    }

    /* -------------------------------------------------------------- */
    /* Per-connection handler                                          */
    /* -------------------------------------------------------------- */

    private async handleConnection(socket: TcpSocket): Promise<void> {
        // TLS handshake
        if (this.sslContext) {
            await socket.serverHandshake(this.sslContext);
        }

        const alpnProtocol = socket.alpnProtocol;
        const secure = !!this.sslContext;

        // Negotiate protocol
        const version = this.negotiateProtocol(alpnProtocol);
        if (!version) {
            console.error(`No supported protocol negotiated (ALPN: ${alpnProtocol})`);
            socket.close();
            return;
        }

        const protoConfig: ProtocolServerConfig = {
            secure,
            alpnProtocols: defaultAlpnProtocols(this.config.protocols),
            cert: this.config.cert, key: this.config.key,
            maxConcurrentStreams: 100,
            keepAliveTimeout: this.config.keepAliveTimeout,
            requestTimeout: this.config.requestTimeout,
            maxHeadersCount: this.config.maxHeadersCount,
            maxConnections: this.config.maxConnections,
        };

        const protoModule = PROTOCOL_MODULES.get(version);
        if (!protoModule) throw new Error(`Unsupported HTTP protocol version: ${version}`);
        const protoConn = await protoModule.server.accept(socket, protoConfig);
        this.connections.add(protoConn);

        if (version === HttpVersion.HTTP2) {
            await this.h2RequestLoop(protoConn as H2Connection, socket);
            this.connections.delete(protoConn);
            if (this.draining && this.connections.size === 0) this._completeDrain();
            try {
                protoConn.close();
            } catch {
                /* already closed */
            }
            return;
        }

        // Set up event handlers
        protoConn.on({
            onError: (err: Error) => console.error(`Protocol error:`, err),
            onClose: () => {
                this.connections.delete(protoConn);
                if (this.draining && this.connections.size === 0) this._completeDrain();
            },
        });

        await this.h1RequestLoop(protoConn as H1ServerConnection);
        // Non-upgraded connections: close so onClose fires and cleans up the set.
        // Upgraded connections (WebSocket etc.) stay in the set; their close() is
        // called either by the protocol layer or by shutdown().
        if (!(protoConn as H1ServerConnection).isUpgraded) {
            protoConn.close();
        }
    }

    private negotiateProtocol(alpnProtocol?: string): HttpVersion | null {
        const allowed = this.config.protocols;
        const allow = (v: HttpVersion) => allowed.includes(v);

        if (alpnProtocol === ALPN.HTTP2 || alpnProtocol === ALPN.HTTP2C) {
            return allow(HttpVersion.HTTP2) ? HttpVersion.HTTP2 : null;
        }
        if (alpnProtocol === ALPN.HTTP11 || alpnProtocol === ALPN.HTTP10) {
            return allow(HttpVersion.HTTP11) ? HttpVersion.HTTP11 : null;
        }
        // No ALPN: TLS falls back to H1; cleartext may be prior-knowledge h2c
        // only when HTTP/2 is configured and H1 is not.
        if (!alpnProtocol) {
            if (!this.sslContext && allow(HttpVersion.HTTP2) && !allow(HttpVersion.HTTP11)) {
                return HttpVersion.HTTP2;
            }
            if (allow(HttpVersion.HTTP11)) return HttpVersion.HTTP11;
            if (allow(HttpVersion.HTTP2)) return HttpVersion.HTTP2;
        }
        return null;
    }

    /* -------------------------------------------------------------- */
    /* HTTP request loop                                              */
    /* -------------------------------------------------------------- */

    private async h2RequestLoop(conn: H2Connection, socket: TcpSocket): Promise<void> {
        await new Promise<void>(resolve => {
            let done = false;
            const finish = () => {
                if (done) return;
                done = true;
                resolve();
            };
            conn.on({
                onClose: finish,
                onError: (err: Error) => {
                    if (!TcpSocket.isDisconnectError(err)) console.error('HTTP/2 protocol error:', err);
                    finish();
                },
            });
            conn.onStreamOpen = stream => {
                void this.handleH2Stream(stream).catch((e: Error) => {
                    if (!TcpSocket.isDisconnectError(e)) {
                        try {
                            if (this.onRequestError) this.onRequestError(e, socket);
                            else console.error('HTTP/2 request error:', e);
                        } catch (cbErr) {
                            console.error('onRequestError threw:', cbErr);
                        }
                    }
                    try {
                        stream.abort();
                    } catch {
                        /* */
                    }
                });
            };
        });
    }

    private async handleH2Stream(stream: H2Stream): Promise<void> {
        await new Promise<void>(resolve => {
            stream.whenHeaders(() => resolve());
        });
        const headers = stream.headerList ?? [];
        let method = 'GET';
        let url = '/';
        let authority: string | undefined;
        const raw: Array<[string, string]> = [];
        for (const [n, v] of headers) {
            const lower = n.toLowerCase();
            if (lower === ':method') method = v;
            else if (lower === ':path') url = v;
            else if (lower === ':authority') authority = v;
            else if (!n.startsWith(':')) raw.push([n, v]);
        }
        if (authority && !raw.some(([n]) => n.toLowerCase() === 'host')) {
            raw.push(['host', authority]);
        }
        // Web Request forbids a body on GET/HEAD; keep poll only when needed.
        const body = (method === 'GET' || method === 'HEAD')
            ? null
            : this.h2BodyPoll(stream);
        const httpReq: HttpRequest = {
            method,
            url,
            httpVersion: '2.0',
            headers: raw,
            body,
        };
        const httpRes = this.toH2HttpResponse(stream);
        await this.handler(httpReq, httpRes);
    }

    private h2BodyPoll(stream: H2Stream): StreamPoll {
        const gen = stream.bodyChunks();
        return async () => {
            const next = await gen.next();
            return next.done ? null : next.value;
        };
    }

    private toH2HttpResponse(stream: H2Stream): HttpResponse {
        let headersSent = false;
        const response: HttpResponse = {
            status: 200,
            statusText: 'OK',
            headers: [],
            writeHead: async (status: number, _statusText?: string, headers?: Array<[string, string]>) => {
                if (headersSent) return;
                headersSent = true;
                const h2h: Array<[string, string]> = [[':status', String(status)]];
                for (const [n, v] of headers ?? []) {
                    const lower = n.toLowerCase();
                    // H2 forbids connection-specific hop-by-hop headers
                    if (lower === 'connection' || lower === 'transfer-encoding' || lower === 'keep-alive'
                        || lower === 'proxy-connection' || lower === 'upgrade') {
                        continue;
                    }
                    h2h.push([n, v]);
                }
                stream.respond(h2h, false);
            },
            write: async (chunk: Uint8Array | string) => {
                if (!headersSent) {
                    await response.writeHead(200, 'OK', [['content-type', 'application/octet-stream']]);
                }
                const data = typeof chunk === 'string' ? engine.encodeString(chunk) : chunk;
                stream.sendData(data, false);
            },
            end: async (chunk?: Uint8Array | string) => {
                if (!headersSent) {
                    headersSent = true;
                    if (chunk !== undefined) {
                        const data = typeof chunk === 'string' ? engine.encodeString(chunk) : chunk;
                        stream.respond([[':status', '200']], false);
                        stream.sendData(data, true);
                    } else {
                        stream.respond([[':status', '200']], true);
                    }
                    return;
                }
                if (chunk !== undefined) {
                    const data = typeof chunk === 'string' ? engine.encodeString(chunk) : chunk;
                    stream.sendData(data, true);
                } else {
                    stream.sendData(new Uint8Array(0), true);
                }
            },
            upgrade: () => {
                throw new Error('HTTP/2 does not support connection upgrade');
            },
            close: () => {
                try {
                    stream.abort();
                } catch {
                    /* */
                }
            },
        };
        return response;
    }

    private async h1RequestLoop(conn: H1ServerConnection): Promise<void> {
        let keepAlive = true;
        let firstRequest = true;
        let requestCount = 0;
        while (keepAlive && !conn.isClosed()) {
            const timeoutMs = firstRequest ? this.config.requestTimeout : this.config.keepAliveTimeout;
            let timedOut = false;
            let tid: number | null = timeoutMs > 0
                ? timers.setTimeout(() => { timedOut = true; conn.close(); }, timeoutMs)
                : null;
            try {
                keepAlive = await conn.handleRequest(async (req: RawRequest, _res: RawResponse) => {
                    const httpReq = this.toHttpRequest(req);
                    const httpRes = this.toHttpResponse(conn);
                    await this.handler(httpReq, httpRes);
                }, () => {
                    // Headers arrived: the connection is no longer idle. Cancel the
                    // keep-alive/request timer so it bounds only the idle wait for
                    // the next request — not body streaming or handler execution.
                    if (tid !== null) { timers.clearTimeout(tid); tid = null; }
                });
                firstRequest = false;
                requestCount++;
                if (requestCount >= this.config.maxRequestsPerConnection) keepAlive = false;
            } catch (err) {
                if (!TcpSocket.isDisconnectError(err) && !timedOut) {
                    const error = err instanceof Error ? err : new Error(String(err));
                    try {
                        if (this.onRequestError) this.onRequestError(error, conn.socket);
                        else console.error("Request error:", error);
                    } catch (cbErr) { console.error("onRequestError threw:", cbErr); }
                }
                keepAlive = false;
            } finally { if (tid !== null) timers.clearTimeout(tid); }
        }
    }

    /* -------------------------------------------------------------- */
    /* Adapters: Raw for HttpRequest/Response                         */
    /* -------------------------------------------------------------- */

    private toHttpRequest(raw: RawRequest): HttpRequest {
        const request = {
            method: raw.method, url: raw.url, httpVersion: raw.httpVersion,
            headers: raw.headers, body: raw.body as StreamPoll | null,
        };
        Reflect.set(request as object, '__cnoTcp', (raw as RawRequest & NativeTcpCarrier).__cnoTcp);
        return request;
    }

    private toHttpResponse(conn: H1ServerConnection): HttpResponse {
        let headersSent = false;
        const response = {
            status: 200, statusText: 'OK', headers: [] as Array<[string, string]>,
            writeHead: async (status: number, statusText?: string, headers?: Array<[string, string]>) => {
                await conn.writeHead(status, statusText ?? 'OK', headers ?? []);
                headersSent = true;
            },
            write: async (chunk: Uint8Array | string) => {
                if (!headersSent) { await conn.writeHead(200, 'OK', [['transfer-encoding', 'chunked']]); headersSent = true; }
                await conn.writeData(typeof chunk === 'string' ? engine.encodeString(chunk) : chunk);
            },
            end: async (chunk?: Uint8Array | string) => {
                if (chunk !== undefined) await conn.writeData(typeof chunk === 'string' ? engine.encodeString(chunk) : chunk);
                await conn.endResponse();
            },
            upgrade: () => {
                conn.markUpgraded();
                let pending = conn.takeUpgradeLeftover();
                return {
                    socket: conn.socket,
                    sslPipe: conn.socket.sslPipe,
                    write: (data: Uint8Array) => conn.socket.write(data),
                    read: (size?: number) => {
                        if (pending && pending.byteLength > 0) { const data = pending; pending = null; return Promise.resolve(data); }
                        return conn.socket.read(size);
                    },
                    onReadable: (cb: (data: Uint8Array | null) => void, errHandler?: (err: Error) => void) => {
                        conn.socket.onReadable(cb, errHandler);
                        if (pending && pending.byteLength > 0) { const data = pending; pending = null; cb(data); }
                    },
                    stopReading: () => conn.socket.stopReading(),
                    serverHandshake: (ctx: CModuleSSL.Context) => conn.socket.serverHandshake(ctx),
                    clientHandshake: (ctx: CModuleSSL.Context, servername?: string) => conn.socket.clientHandshake(ctx, servername),
                    get alpnProtocol() { return conn.socket.alpnProtocol; },
                    close: () => conn.close(),
                    isClosed: () => conn.isClosed(),
                };
            },
            close: () => conn.close(),
        };
        Reflect.set(response as object, '__cnoTcp', conn.socket.socket);
        return response;
    }


    get isSecure(): boolean {
        return !!this.sslContext;
    }
}

export function createServer(handler: RequestHandler, config: ServerConfig): Server {
    return new Server(handler, config);
}
