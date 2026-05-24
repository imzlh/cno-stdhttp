/**
 * Pure transport layer — TCP/SSL socket I/O.
 *
 * This module knows NOTHING about HTTP. It provides:
 * - TcpSocket: base TCP + TLS I/O (read/write/handshake)
 * - No HTTP parsing, no ALPN negotiation, no protocol assumptions
 *
 * Protocol layers (h1.ts, h2.ts, h3.ts) consume TcpSocket for I/O.
 */

const streams = import.meta.use("streams");
const ssl = import.meta.use("ssl");
const error = import.meta.use("error");

type Uint8Array = globalThis.Uint8Array<ArrayBuffer>;

const READ_SIZE = 16384;

/**
 * Base TCP socket with optional TLS.
 * Provides plaintext and SSL read/write, TLS handshake (both sides),
 * and callback-based readable events.
 */
export class TcpSocket {
    public  socket:  CModuleStreams.TCP;
    public  sslPipe: CModuleSSL.Pipe | null = null;
    private pending: Uint8Array | null = null;

    constructor(socket?: CModuleStreams.TCP) {
        this.socket = socket ?? new streams.TCP();
    }

    /* -------------------------------------------------------------- */
    /* Callback-based readable (for async event-driven protocols)     */
    /* -------------------------------------------------------------- */

    private _readCallback: ((data: Uint8Array | null) => void) | null = null;
    private _readErrHandler: ((err: Error) => void) | null = null;

    private setupReadCallback(): void {
        try { this.socket.stopRead(); } catch { /* ignore */ }
        (this.socket as any).onread = (data: Uint8Array | null | undefined, err?: any) => {
            if (data === undefined) {
                if (err) { this._readErrHandler?.(err as Error); (this.socket as any).onread = null; }
                return;
            }
            if (data === null) { this._readCallback?.(null); return; }
            this._readCallback?.(data);
            if (this._readCallback) {
                try { this.socket.startRead(); } catch (e: any) { if (e.code !== 'EALREADY') throw e; }
            }
        };
        try { this.socket.startRead(); } catch (e: any) { if (e.code !== 'EALREADY') throw e; }
    }

    onReadable(callback: (data: Uint8Array | null) => void, errHandler?: (err: Error) => void): void {
        this._readCallback = callback;
        this._readErrHandler = errHandler ?? null;
        this.setupReadCallback();
    }

    stopReading(): void {
        this.socket.stopRead();
        this._readCallback = null;
        this._readErrHandler = null;
        // @ts-ignore
        this.socket.onread = null;
    }

    /* -------------------------------------------------------------- */
    /* Read / Write (SSL-aware)                                       */
    /* -------------------------------------------------------------- */

    /** Read plaintext from socket (SSL-aware). Returns null on EOF. */
    async read(size = READ_SIZE): Promise<Uint8Array | null> {
        if (!this.sslPipe) {
            const buf = new Uint8Array(size);
            const n = await this.socket.read(buf);
            return (n === 0) ? null : buf.subarray(0, n);
        }

        const buffered = this.sslRead(size);
        if (buffered) return buffered;

        if (this.pending) {
            const plain = this.feedAndRead(this.pending, size);
            this.pending = null;
            if (plain) return plain;
        }

        const buf = new Uint8Array(size);
        while (true) {
            const n = await this.socket.read(buf);
            if (n === 0) return null;
            const cipher = buf.subarray(0, n);
            const consumed = this.feedCipher(cipher);
            if (consumed < cipher.length) this.pending = cipher.subarray(consumed);
            const plain = this.sslRead(size);
            if (plain) return plain;
        }
    }

    /** Write plaintext to socket (SSL-aware). */
    async write(data: Uint8Array): Promise<void> {
        if (data.length === 0) return;
        if (!this.sslPipe) { await this.socket.write(data); return; }

        let offset = 0;
        while (offset < data.length) {
            const written = this.sslPipe.write(data.subarray(offset));
            if (written < 0) throw new Error(`SSL_write failed: ${written}`);
            offset += written;
        }
        const encrypted = this.sslPipe.getOutput();
        if (encrypted) await this.socket.write(new Uint8Array(encrypted));
    }

    /* -------------------------------------------------------------- */
    /* TLS Handshake                                                  */
    /* -------------------------------------------------------------- */

    /** Server-side TLS handshake. */
    async serverHandshake(ctx: CModuleSSL.Context): Promise<void> {
        this.sslPipe = new ssl.Pipe(ctx);
        const buf = new Uint8Array(READ_SIZE);
        while (!this.sslPipe.handshakeComplete) {
            const n = await this.socket.read(buf);
            if (n === 0) throw new Error("SSL handshake failed: connection closed");
            let toFeed = buf.subarray(0, n);
            while (toFeed.length > 0) { const c = this.feedCipher(toFeed); if (c <= 0) break; toFeed = toFeed.subarray(c); }
            this.sslPipe.handshake();
            const out = this.sslPipe.getOutput();
            if (out) await this.socket.write(new Uint8Array(out));
        }
    }

    /** Client-side TLS handshake. */
    async clientHandshake(ctx: CModuleSSL.Context, servername?: string): Promise<void> {
        this.sslPipe = new ssl.Pipe(ctx, servername ? { servername } : undefined);
        this.sslPipe.handshake();
        const initial = this.sslPipe.getOutput();
        if (initial) await this.socket.write(new Uint8Array(initial));

        const buf = new Uint8Array(READ_SIZE);
        while (!this.sslPipe.handshakeComplete) {
            const n = await this.socket.read(buf);
            if (n === 0) throw new Error("TLS handshake failed: connection closed");
            let toFeed = buf.subarray(0, n);
            while (toFeed.length > 0) {
                const c = this.feedCipher(toFeed);
                if (c <= 0) throw new Error(`SSL feed failed during handshake: consumed=${c}`);
                toFeed = c < toFeed.length ? toFeed.subarray(c) : new Uint8Array(0);
            }
            this.sslPipe.handshake();
            const out = this.sslPipe.getOutput();
            if (out) await this.socket.write(new Uint8Array(out));
        }
    }

    /* -------------------------------------------------------------- */
    /* ALPN (Application-Layer Protocol Negotiation)                  */
    /* -------------------------------------------------------------- */

    /**
     * Get the ALPN protocol negotiated during TLS handshake.
     * Returns undefined if TLS is not active or ALPN was not negotiated.
     */
    get alpnProtocol(): string | undefined {
        return this.sslPipe?.alpnProtocol?.() ?? undefined;
    }

    /* -------------------------------------------------------------- */
    /* Close                                                          */
    /* -------------------------------------------------------------- */

    close(): void {
        this.pending = null;
        this.stopReading();
        try { this.sslPipe?.shutdown(); } catch { /* ignore */ }
        this.sslPipe = null;
        try { this.socket.close(); } catch { /* ignore */ }
    }

    /* -------------------------------------------------------------- */
    /* Helpers                                                        */
    /* -------------------------------------------------------------- */

    private feedCipher(data: Uint8Array): number {
        const n = this.sslPipe!.feed(data);
        if (n < 0) throw new Error(`SSL feed error: ${n}`);
        return n;
    }

    private feedAndRead(data: Uint8Array, size: number): Uint8Array | null {
        this.feedCipher(data);
        return this.sslRead(size);
    }

    private sslRead(size: number): Uint8Array | null {
        const plain = this.sslPipe!.read(size);
        return (plain && plain.byteLength > 0) ? new Uint8Array(plain) : null;
    }

    static isDisconnectError(err: unknown): boolean {
        if (!(err instanceof Error)) return false;
        const code = (err as any).code;
        return code === error.errno.ECONNRESET || code === error.errno.EPIPE || code === error.errno.EBADF;
    }
}
