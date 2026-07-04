/**
 * Core Server Layer
 * NOTE: currently only h1 is supported
 *
 * Accepts connections and serves HTTP/1.x requests.
 * Routes incoming requests to the handler via the H1 protocol layer.
 *
 * Architecture:
 *   TCP accept -> optional TLS handshake -> H1 handler loop
 */

type Uint8Array = globalThis.Uint8Array<ArrayBuffer>;

import { TcpSocket } from "./socket";
import { h1, H1ServerConnection } from "./h1";
import {
    type RawRequest, type RawResponse,
    type ProtocolConnection, type ProtocolServerConfig, type ProtocolClientConfig,
    HttpVersion, ALPN,
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
    cert?: string;
    key?: string;
    keepAliveTimeout?: number;
    maxRequestsPerConnection?: number;
    requestTimeout?: number;
    protocols?: HttpVersion[];
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
    upgrade(): any;
    close(): void;
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
    [HttpVersion.HTTP11, h1]
]);

/* ------------------------------------------------------------------ */
/* Server                                                             */
/* ------------------------------------------------------------------ */

export class Server {
    public readonly config: Required<ServerConfig>;
    public readonly handler: RequestHandler;
    public onRequestError: ((error: Error, socket: TcpSocket) => void) | null = null;

    private listener: CModuleStreams.TCP | null = null;
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
            cert: config.cert ?? "",
            key: config.key ?? "",
            keepAliveTimeout: config.keepAliveTimeout ?? 60000,
            maxRequestsPerConnection: config.maxRequestsPerConnection ?? 100,
            requestTimeout: config.requestTimeout ?? 300000,
            protocols: config.protocols ?? [HttpVersion.HTTP11],
        };
    }

    listen(): void {
        assert(!this.listening, "Server already listening");
        if (this.config.cert && this.config.key) {
            this.sslContext = new ssl.Context({ mode: "server", cert: this.config.cert, key: this.config.key });
        }
        const family = this.config.hostname.includes(':') ? os.AF_INET6 : os.AF_INET;
        this.listener = new streams.TCP(family);
        this.listener.bind({ ip: this.config.hostname, port: this.config.port });
        this.listener.listen(511);
        // Update config with the actual bound port (OS-assigned when port was 0)
        const sn = this.listener.sockname;
        if (sn) this.config.port = sn.port;
        this.listening = true;
    }

    async acceptLoop(): Promise<void> {
        assert(this.listener, "Server not listening");
        const proto = this.sslContext ? "https" : "http";
        console.debug(`Server listening on ${proto}://${this.config.hostname}:${this.config.port}`);

        this.listener!.onconnection = (error: any, client: any) => {
            if (error) return console.error("Accept error:", error);
            if (this.draining) { client.close(); return; }
            client.setNoDelay(true);
            client.setKeepAlive(true, 1000);
            const tcpSocket = new TcpSocket(client);
            this.handleConnection(tcpSocket).catch((e: Error) => {
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

    address(): { ip: string; port: number } | null { return this.listener?.sockname ?? null; }

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
            alpnProtocols: this.config.protocols.map(p => {
                if (p === HttpVersion.HTTP11) return ALPN.HTTP11;
                return ALPN.HTTP10;
            }),
            cert: this.config.cert, key: this.config.key,
            maxConcurrentStreams: 100,
            keepAliveTimeout: this.config.keepAliveTimeout,
            requestTimeout: this.config.requestTimeout,
        };

        const protoModule = PROTOCOL_MODULES.get(version)!;
        const protoConn = await protoModule.server.accept(socket, protoConfig);
        this.connections.add(protoConn);

        // Set up event handlers
        protoConn.on({
            onError: (err: Error) => console.error(`Protocol error:`, err),
            onClose: () => {
                this.connections.delete(protoConn);
                if (this.draining && this.connections.size === 0) this._completeDrain();
            },
        });

        await this.h1RequestLoop(protoConn as import("./h1").H1ServerConnection);
        // Non-upgraded connections: close so onClose fires and cleans up the set.
        // Upgraded connections (WebSocket etc.) stay in the set; their close() is
        // called either by the protocol layer or by shutdown().
        if (!(protoConn as import("./h1").H1ServerConnection).isUpgraded) {
            protoConn.close();
        }
    }

    private negotiateProtocol(alpnProtocol?: string): HttpVersion | null {
        if (!alpnProtocol || alpnProtocol === ALPN.HTTP11 || alpnProtocol === ALPN.HTTP10) return HttpVersion.HTTP11;
        return null;
    }

    /* -------------------------------------------------------------- */
    /* HTTP request loop                                              */
    /* -------------------------------------------------------------- */

    private async h1RequestLoop(conn: H1ServerConnection): Promise<void> {
        let keepAlive = true;
        let firstRequest = true;
        while (keepAlive && !conn.isClosed()) {
            const timeoutMs = firstRequest ? this.config.requestTimeout : this.config.keepAliveTimeout;
            let timedOut = false;
            let tid: any = timers.setTimeout(() => { timedOut = true; conn.close(); }, timeoutMs);
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
            } catch (err: any) {
                if (!TcpSocket.isDisconnectError(err) && !timedOut) {
                    try {
                        if (this.onRequestError) this.onRequestError(err, conn.socket);
                        else console.error("Request error:", err);
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
        Reflect.set(request as object, '__cnoTcp', (raw as any).__cnoTcp);
        return request;
    }

    private toHttpResponse(conn: any): HttpResponse {
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
