/**
 * @cnojs/http 鈥?Low-level HTTP protocol library.
 *
 * NO WebAPI dependencies (no URL, Headers, Request, Response, ReadableStream, EventTarget, etc.).
 * All I/O is via raw bytes and callbacks.
 *
 * CNO's secondary wrapping layer maps WebAPI types onto this low-level API.
 *
 * === Module Overview ===
 *
 * Core Transport:
 *   socket.ts       鈥?TcpSocket: base TCP/SSL I/O, TLS handshake
 *   dns-cache.ts    鈥?DnsCache: DNS resolution with TTL caching (async + sync)
 *   connection.ts   鈥?Connection, ConnectionManager: HTTP/HTTPS connection pooling
 *   zlib.ts         鈥?gzip/deflate compress/decompress utilities
 *
 * Protocol Layer:
 *   protocol.ts     鈥?Protocol interface abstraction (ProtocolClient, ProtocolServer, etc.)
 *   h1.ts           鈥?HTTP/1.x protocol (request builder, response parser, server/client connection)
 *
 * Server:
 *   server.ts       鈥?Protocol-aware server with ALPN negotiation
 *
 * Utilities:
 *   debug.ts        鈥?hexDump: hexadecimal debugging output
 *   process.ts      鈥?HttpProgressBar: graphical download progress bar
 */

// Core Transport
export { TcpSocket } from "./socket.ts";
export { dnsCache } from "./dns-cache.ts";
export type { DnsAddress } from "./dns-cache.ts";
export { Connection, ConnectionManager, connectionManager, ConnectionState } from "./connection.ts";
export type { ConnectionConfig, ConnectionLike } from "./connection.ts";
export { parseAcceptEncoding, pickEncoding, shouldCompress, createDecompressor, StreamingDecompressor, createCompressor } from "./zlib.ts";

// Protocol Layer
export { HttpVersion, ALPN, alpnToProtocol, defaultAlpnProtocols } from "./protocol.ts";
export type { RawRequest, RawResponse, RawHeaders, ProtocolStream, ProtocolConnection, ProtocolConnectionEvents, ProtocolClient, ProtocolServer, ProtocolClientConfig, ProtocolServerConfig, ProtocolModule, AlpnProtocol } from "./protocol.ts";

// HTTP/1.x
export { HttpRequestBuilder, HttpResponseParser, h1 } from "./h1.ts";
export type { H1RequestOptions } from "./h1.ts";

// Server
export { Server, createServer } from "./server.ts";
export type { ServerConfig, HttpRequest, HttpResponse, RequestHandler } from "./server.ts";

// Fetch (sync + async)
export { fetchBytes, fetchSync, fetchText, fetchBytesAsync, fetchAsync, fetchTextAsync, closeCurlPool } from "./client.ts";
export type { ProgressCallback, FetchOptions } from "./client.ts";

// Utilities
export { hexDump } from "./debug.ts";
export { HttpProgressBar, createProgressBar } from "./process.ts";
export type { ProgressOptions } from "./process.ts";

