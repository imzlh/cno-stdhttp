/**
 * @cnojs/http Low-level HTTP protocol library.
 *
 * Core Transport:
 *   socket.ts         TcpSocket: base TCP/SSL I/O, TLS handshake
 *   dns-cache.ts      DnsCache: DNS resolution with TTL caching (async + sync)
 *   raw-connection.ts explicit raw transport entry for SSE/WebSocket-style clients
 *   zlib.ts           gzip/deflate compress/decompress utilities
 *
 * Protocol Layer:
 *   protocol.ts     Protocol interface abstraction (ProtocolClient, ProtocolServer, etc.)
 *   h1.ts           HTTP/1.x protocol (request builder, response parser, server/client connection)
 *
 * Server:
 *   server.ts       Protocol-aware server with ALPN negotiation
 *
 * Utilities:
 *   debug.ts        hexDump: hexadecimal debugging output
 *   process.ts      HttpProgressBar: graphical download progress bar
 */

// Core Transport
export { TcpSocket } from "./socket";
export { dnsCache } from "./dns-cache";
export type { DnsAddress } from "./dns-cache";
export { parseAcceptEncoding, pickEncoding, shouldCompress, createDecompressor, StreamingDecompressor, createCompressor } from "./zlib";

// Protocol Layer
export { HttpVersion, ALPN, alpnToProtocol, defaultAlpnProtocols } from "./protocol";
export type { RawRequest, RawResponse, RawHeaders, ProtocolStream, ProtocolConnection, ProtocolConnectionEvents, ProtocolClient, ProtocolServer, ProtocolClientConfig, ProtocolServerConfig, ProtocolModule, AlpnProtocol } from "./protocol";

// HTTP/1.x
export { HttpRequestBuilder, HttpResponseParser, h1 } from "./h1";
export type { H1RequestOptions } from "./h1";

// Server
export { Server, createServer } from "./server";
export type { ServerConfig, HttpRequest, HttpResponse, RequestHandler } from "./server";

// Utilities
export { hexDump } from "./debug";
export { HttpProgressBar, createProgressBar } from "./process";
export type { ProgressOptions } from "./process";
