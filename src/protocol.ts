/**
 * Protocol abstraction layer — defines the interface that all HTTP protocol
 * implementations (H1, H2, H3) must satisfy.
 *
 * NO WebAPI dependencies. All types use primitives:
 * - Headers → Array<[string, string]>
 * - Body → Uint8Array | null
 * - No URL, Headers, Request, Response, ReadableStream, EventTarget, etc.
 *
 * Architecture:
 * ┌─────────────────────────────────────────────────────────────────┐
 * │                   CNO Secondary Wrapping Layer                   │
 * │   (URL→string, Headers→Array, Request/Response→H1 types, etc.)  │
 * └──────────────────────────┬──────────────────────────────────────┘
 *                            │ uses
 *                            ▼
 * ┌─────────────────────────────────────────────────────────────────┐
 * │                    Protocol Interface (this file)                │
 * │   ProtocolClient, ProtocolServer, ProtocolConnection, Stream    │
 * └───────┬──────────────────┬──────────────────┬───────────────────┘
 *         │                  │                  │
 *         ▼                  ▼                  ▼
 * ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
 * │    h1.ts     │  │    h2.ts     │  │    h3.ts     │  (future)
 * │  HTTP/1.x    │  │  HTTP/2      │  │  HTTP/3      │
 * └──────────────┘  └──────────────┘  └──────────────┘
 *         │                  │                  │
 *         └──────────────────┼──────────────────┘
 *                            │ uses
 *                            ▼
 * ┌─────────────────────────────────────────────────────────────────┐
 * │              Shared Transport (socket.ts / connection.ts)       │
 * │                    TcpSocket, ConnectionManager                  │
 * └─────────────────────────────────────────────────────────────────┘
 */

/* ------------------------------------------------------------------ */
/* Connection-level protocol negotiation                              */
/* ------------------------------------------------------------------ */

export enum HttpVersion {
    HTTP10 = '1.0',
    HTTP11 = '1.1',
    HTTP2  = '2',
    HTTP3  = '3',
}

export const ALPN = {
    HTTP11: 'http/1.1',
    HTTP10: 'http/1.0',
    HTTP2:  'h2',
    HTTP2C: 'h2c',
    HTTP3:  'h3',
} as const;

export type AlpnProtocol = typeof ALPN[keyof typeof ALPN];

/* ------------------------------------------------------------------ */
/* Stream abstraction (protocol-independent request/response)         */
/* ------------------------------------------------------------------ */

/** Headers as raw [name, value] pairs (low-level, no WebAPI Headers) */
export type RawHeaders = Array<[string, string]>;

export interface RawRequest {
    method: string;
    url: string;
    headers: RawHeaders;
    body: Uint8Array | null;
    httpVersion: string;
}

export interface RawResponse {
    status: number;
    statusText: string;
    headers: RawHeaders;
    body: Uint8Array | null;
}

export interface ProtocolStream {
    readonly id: number | string;
    /** Send headers. Server sends RawResponse (status + headers), client sends RawRequest. */
    writeHead(data: RawRequest | RawResponse): Promise<void>;
    writeData(data: Uint8Array): Promise<void>;
    end(data?: Uint8Array): Promise<void>;
    readMessage(): Promise<RawRequest | RawResponse>;
    abort(code?: number): void;
    close(): void;
}

/* ------------------------------------------------------------------ */
/* Protocol connection                                                */
/* ------------------------------------------------------------------ */

export interface ProtocolConnectionEvents {
    onstream: ((stream: ProtocolStream) => void) | null;
    onError: ((error: Error) => void) | null;
    onClose: (() => void) | null;
    onGoaway: ((lastStreamId?: number) => void) | null;
    onSettings: (() => void) | null;
}

export interface ProtocolConnection {
    readonly version: HttpVersion;
    readonly secure: boolean;
    receive(data: Uint8Array): void;
    wantWrite(): boolean;
    flush(): Uint8Array | null;
    createStream(): ProtocolStream;
    on(events: Partial<ProtocolConnectionEvents>): void;
    goaway(): void;
    close(): void;
    destroy(): void;
}

/* ------------------------------------------------------------------ */
/* Protocol client                                                    */
/* ------------------------------------------------------------------ */

export interface ProtocolClientConfig {
    hostname: string;
    port: number;
    secure: boolean;
    alpnProtocols?: AlpnProtocol[];
    maxConcurrentStreams?: number;
    initialWindowSize?: number;
    caCerts?: string[];
    cert?: string;
    key?: string;
}

export interface ProtocolClient {
    readonly version: HttpVersion;
    connect(socket: any, config: ProtocolClientConfig): Promise<ProtocolConnection>;
    request(conn: ProtocolConnection, req: RawRequest): Promise<RawResponse>;
}

/* ------------------------------------------------------------------ */
/* Protocol server                                                    */
/* ------------------------------------------------------------------ */

export interface ProtocolServerConfig {
    secure: boolean;
    alpnProtocols?: AlpnProtocol[];
    cert?: string;
    key?: string;
    maxConcurrentStreams?: number;
    keepAliveTimeout?: number;
    requestTimeout?: number;
}

export interface ProtocolServer {
    readonly version: HttpVersion;
    accept(socket: any, config: ProtocolServerConfig): Promise<ProtocolConnection>;
    negotiate(alpnProtocol?: string): HttpVersion | null;
}

/* ------------------------------------------------------------------ */
/* Protocol module registry                                           */
/* ------------------------------------------------------------------ */

export interface ProtocolModule {
    readonly version: HttpVersion;
    readonly client: ProtocolClient;
    readonly server: ProtocolServer;
}

/* ------------------------------------------------------------------ */
/* Utilities                                                          */
/* ------------------------------------------------------------------ */

export function alpnToProtocol(alpn?: string): HttpVersion | null {
    switch (alpn) {
        case ALPN.HTTP11: return HttpVersion.HTTP11;
        case ALPN.HTTP10: return HttpVersion.HTTP10;
        case ALPN.HTTP2:  return HttpVersion.HTTP2;
        case ALPN.HTTP3:  return HttpVersion.HTTP3;
        default:          return null;
    }
}

export function defaultAlpnProtocols(versions: HttpVersion[]): AlpnProtocol[] {
    const result: AlpnProtocol[] = [];
    for (const v of versions) {
        switch (v) {
            case HttpVersion.HTTP2:  result.push(ALPN.HTTP2);  break;
            case HttpVersion.HTTP11: result.push(ALPN.HTTP11); break;
            case HttpVersion.HTTP10: result.push(ALPN.HTTP10); break;
            case HttpVersion.HTTP3:  result.push(ALPN.HTTP3);  break;
        }
    }
    return result;
}
