/**
 * @cnojs/http — Low-level HTTP protocol library.
 *
 * NO WebAPI dependencies (no URL, Headers, Request, Response, ReadableStream, EventTarget, etc.).
 * All I/O is via raw bytes and callbacks.
 *
 * CNO's secondary wrapping layer maps WebAPI types onto this low-level API.
 *
 * === Module Overview ===
 *
 * Core Transport:
 *   socket.ts       — TcpSocket: base TCP/SSL I/O, TLS handshake
 *   dns-cache.ts    — DnsCache: DNS resolution with TTL caching (async + sync)
 *   connection.ts   — Connection, ConnectionManager: HTTP/HTTPS connection pooling
 *   zlib.ts         — gzip/deflate compress/decompress utilities
 *
 * Protocol Layer:
 *   protocol.ts     — Protocol interface abstraction (ProtocolClient, ProtocolServer, etc.)
 *   h1.ts           — HTTP/1.x protocol (request builder, response parser, server/client connection)
 *   h2.ts           — HTTP/2 protocol (nghttp2 wrapper, multiplexed streams)
 *
 * Server:
 *   server.ts       — Protocol-aware server with ALPN negotiation
 *
 * Utilities:
 *   debug.ts        — hexDump: hexadecimal debugging output
 *   process.ts      — HttpProgressBar: graphical download progress bar
 */

// Core Transport
export { TcpSocket } from "./socket.js";
export { dnsCache } from "./dns-cache.js";
export type { DnsAddress } from "./dns-cache.js";
export { Connection, ConnectionManager, connectionManager, ConnectionState } from "./connection.js";
export type { ConnectionConfig, ConnectionLike } from "./connection.js";
export { parseAcceptEncoding, pickEncoding, shouldCompress, createDecompressor, StreamingDecompressor, createCompressor } from "./zlib.js";

// Protocol Layer
export { HttpVersion, ALPN, alpnToProtocol, defaultAlpnProtocols } from "./protocol.js";
export type { RawRequest, RawResponse, RawHeaders, ProtocolStream, ProtocolConnection, ProtocolConnectionEvents, ProtocolClient, ProtocolServer, ProtocolClientConfig, ProtocolServerConfig, ProtocolModule, AlpnProtocol } from "./protocol.js";

// HTTP/1.x
export { HttpRequestBuilder, HttpResponseParser, h1 } from "./h1.js";
export type { H1RequestOptions } from "./h1.js";

// HTTP/2
export { h2 } from "./h2.js";

// Server
export { Server, createServer } from "./server.js";
export type { ServerConfig, HttpRequest, HttpResponse, RequestHandler } from "./server.js";

// Fetch (sync + async)
export { fetchBytes, fetchSync, fetchText, fetchBytesAsync, fetchAsync, fetchTextAsync } from "./fetch.js";
export type { ProgressCallback, FetchOptions } from "./fetch.js";

// Utilities
export { hexDump } from "./debug.js";
export { HttpProgressBar, createProgressBar } from "./process.js";
export type { ProgressOptions } from "./process.js";
