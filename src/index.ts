/** @cnojs/http — low-level HTTP protocol library: transport (socket, dns-cache, zlib), protocol (protocol, h1, h2), server, utilities. */

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

// HTTP/2 (requires native ext-h2 / CNO_EMBED_EXT_H2)
export { h2, H2Connection } from "./h2";
export type { H2Stream, H2Header, H2Settings } from "./h2";
export { tryLoadH2, requireH2, h2Available, __forceH2Unavailable } from "./h2-native";
export {
    formatHead,
    encodeHead,
    encodeResponseHead,
    encodeRequestHead,
    formatRequestHead,
    encodeChunkedFrame,
    encodeChunkedTrailer,
    connectionTokens,
    wantsKeepAlive,
    shouldCloseAfterResponse,
} from "./h1-frame";

// Server
export { Server, createServer } from "./server";
export type { ServerConfig, HttpRequest, HttpResponse, RequestHandler } from "./server";

// Utilities
export { hexDump } from "./debug";
export { HttpProgressBar, createProgressBar } from "./process";
export type { ProgressOptions } from "./process";
