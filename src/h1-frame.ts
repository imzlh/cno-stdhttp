/**
 * Pure HTTP/1.x framing + connection policy — no I/O.
 *
 * Shared by H1ServerConnection, Node HTTPS, and Node http(s) client so wire
 * bytes and keep-alive decisions stay identical across stacks.
 */

const engine = import.meta.use('engine');

type Uint8Array = globalThis.Uint8Array<ArrayBuffer>;

const CRLF = engine.encodeString('\r\n');
const CHUNKED_TRAILER = engine.encodeString('0\r\n\r\n');

/**
 * Start-line + header block + final blank line.
 * `headerBlock` is zero or more `Name: value\r\n` lines (no trailing blank).
 */
export function formatHead(startLine: string, headerBlock = ''): string {
    const block = !headerBlock
        ? ''
        : (headerBlock.endsWith('\r\n') ? headerBlock : `${headerBlock}\r\n`);
    return `${startLine}\r\n${block}\r\n`;
}

export function encodeHead(startLine: string, headerBlock = ''): Uint8Array {
    return engine.encodeString(formatHead(startLine, headerBlock));
}

function formatPairs(headers: Array<[string, string]>): string {
    let block = '';
    for (const [k, v] of headers) {
        if (k) block += `${k}: ${v}\r\n`;
    }
    return block;
}

/** Status line + headers + blank line (no body). */
export function encodeResponseHead(
    httpVersion: string,
    status: number,
    statusText: string,
    headers: Array<[string, string]>,
): Uint8Array {
    return encodeHead(
        `HTTP/${httpVersion} ${status} ${statusText}`,
        formatPairs(headers),
    );
}

/** Request-line + headers + blank line (no body). */
export function encodeRequestHead(
    method: string,
    target: string,
    httpVersion: string,
    headers: Array<[string, string]>,
): Uint8Array {
    return encodeHead(
        `${method} ${target} HTTP/${httpVersion}`,
        formatPairs(headers),
    );
}

/** Same as encodeRequestHead but returns the wire string (Node `_header`). */
export function formatRequestHead(
    method: string,
    target: string,
    httpVersion: string,
    headerBlock: string,
): string {
    return formatHead(`${method} ${target} HTTP/${httpVersion}`, headerBlock);
}

/** One chunked body unit: `<hex-len>\r\n` + data + `\r\n`. */
export function encodeChunkedFrame(data: Uint8Array): Uint8Array {
    const sizeLine = engine.encodeString(data.byteLength.toString(16) + '\r\n');
    const out = new Uint8Array(sizeLine.length + data.byteLength + CRLF.length);
    out.set(sizeLine, 0);
    out.set(data, sizeLine.length);
    out.set(CRLF, sizeLine.length + data.byteLength);
    return out;
}

/** Final chunk `0\r\n\r\n` (no trailers). */
export function encodeChunkedTrailer(): Uint8Array {
    return CHUNKED_TRAILER;
}

/** Split a Connection header into lowercased tokens. */
export function connectionTokens(header: string | null | undefined): string[] {
    if (!header) return [];
    const out: string[] = [];
    for (const part of header.toLowerCase().split(',')) {
        const t = part.trim();
        if (t) out.push(t);
    }
    return out;
}

/**
 * Whether the peer wants keep-alive after this message.
 * HTTP/1.1 defaults open; HTTP/1.0 needs explicit keep-alive; `close` wins.
 */
export function wantsKeepAlive(
    httpVersion: string,
    connectionHeader?: string | null,
): boolean {
    const tokens = connectionTokens(connectionHeader);
    if (tokens.includes('close')) return false;
    // 1.0 and anything below 1.1 need explicit keep-alive
    if (httpVersion === '1.0' || httpVersion.startsWith('0.')) {
        return tokens.includes('keep-alive');
    }
    return true;
}

/** Inverse of wantsKeepAlive — server should close after the response. */
export function shouldCloseAfterResponse(
    httpVersion: string,
    connectionHeader?: string | null,
): boolean {
    return !wantsKeepAlive(httpVersion, connectionHeader);
}
