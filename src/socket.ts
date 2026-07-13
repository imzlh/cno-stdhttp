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

export interface ISocket {
    onReadable(callback: (data: Uint8Array | null) => void, errHandler?: (err: Error) => void): void;
    stopReading(): void;
    read(size?: number): Promise<Uint8Array | null>;
    write(data: Uint8Array): Promise<void>;
    serverHandshake(ctx: CModuleSSL.Context): Promise<void>;
    clientHandshake(ctx: CModuleSSL.Context, servername?: string): Promise<void>;
    get alpnProtocol(): string | undefined;
    close(): void;
}

/** Minimal byte transport required by TcpSocket. Native streams and layered transports implement this. */
export interface SocketTransport {
    onread: CModuleStreams.Stream['onread'];
    startRead(): void;
    stopRead(): void;
    read(buffer: CModuleStreams.BufferSource): Promise<number>;
    write(buffer: CModuleStreams.BufferSource): Promise<number>;
    close(): void;
}

/**
 * Base TCP socket with optional TLS.
 * Provides plaintext and SSL read/write, TLS handshake (both sides),
 * and callback-based readable events.
 */
export class TcpSocket implements ISocket {
    public  socket:  SocketTransport;
    public  sslPipe: CModuleSSL.Pipe | null = null;
    private pending: Uint8Array | null = null;

    constructor(socket?: SocketTransport) {
        this.socket = socket ?? new streams.TCP();
    }

    /* -------------------------------------------------------------- */
    /* Callback-based readable (for async event-driven protocols)     */
    /* -------------------------------------------------------------- */

    private _readCallback: ((data: Uint8Array | null) => void) | null = null;
    private _readErrHandler: ((err: Error) => void) | null = null;

    private setupReadCallback(): void {
        try { this.socket.stopRead(); } catch { /* ignore */ }
        this.socket.onread = (data: Uint8Array | null | undefined, err?: CModuleError.Error) => {
            if (data === undefined) {
                if (err) {
                    this._readErrHandler?.(err);
                    Reflect.set(this.socket, 'onread', null);
                }
                return;
            }
            if (data === null) { this._readCallback?.(null); return; }
            // TLS: decrypt cipher before delivering (same path as read()).
            if (this.sslPipe) {
                try {
                    let cipher = data;
                    if (this.pending) {
                        const joined = new Uint8Array(this.pending.length + cipher.length);
                        joined.set(this.pending);
                        joined.set(cipher, this.pending.length);
                        cipher = joined;
                        this.pending = null;
                    }
                    const consumed = this.feedCipher(cipher);
                    if (consumed < cipher.length) this.pending = cipher.subarray(consumed);
                    this.sslPipe.handshake();
                    const out = this.sslPipe.getOutput();
                    if (out) void this.socket.write(new Uint8Array(out));
                    // Flush all available plaintext to the callback.
                    while (this._readCallback) {
                        const plain = this.sslRead(READ_SIZE);
                        if (!plain) break;
                        this._readCallback(plain);
                    }
                } catch (e) {
                    this._readErrHandler?.(e instanceof Error ? e : new Error(String(e)));
                    return;
                }
            } else {
                this._readCallback?.(data);
            }
            if (this._readCallback) {
                try {
                    this.socket.startRead();
                } catch (e: unknown) {
                    if ((e as CModuleError.Error).code !== error.errno.EALREADY) throw e;
                }
            }
        };
        try {
            this.socket.startRead();
        } catch (e) {
            if ((e as CModuleError.Error).code !== error.errno.EALREADY) throw e;
        }
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
        Reflect.set(this.socket, 'onread', null);
    }

    /* -------------------------------------------------------------- */
    /* Read / Write (SSL-aware)                                       */
    /* -------------------------------------------------------------- */

    /** Read plaintext from socket (SSL-aware). Returns null on EOF. */
    async read(size = READ_SIZE): Promise<Uint8Array | null> {
        if (!this.sslPipe) {
            const buf = new Uint8Array(size);
            const n = await this.readRaw(buf);
            return (n === 0) ? null : buf.subarray(0, n);
        }

        const buffered = this.sslRead(size);
        if (buffered) return buffered;

        if (this.pending) {
            const plain = this.feedAndRead(this.pending, size);
            this.pending = null;
            if (plain) return plain;
        }

        const buf = new Uint8Array(READ_SIZE);
        while (true) {
            const n = await this.readRaw(buf);
            if (n === 0) return null; // EOF
            const cipher = buf.subarray(0, n);
            const consumed = this.feedCipher(cipher);
            if (consumed < cipher.length) this.pending = cipher.subarray(consumed);
            // Drive SSL state machine (handles renegotiation), then flush any output
            const sslPipe = this.sslPipe;
            if (!sslPipe) return null;
            sslPipe.handshake();
            const out = sslPipe.getOutput();
            if (out) await this.socket.write(new Uint8Array(out));
            const plain = this.sslRead(size);
            if (plain) return plain;
            // No plaintext yet — renegotiation or partial TLS record, loop
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
            const n = await this.readRaw(buf);
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
            const n = await this.readRaw(buf);
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
        return this.sslPipe?.alpnProtocol ?? undefined;
    }

    /* -------------------------------------------------------------- */
    /* Close                                                          */
    /* -------------------------------------------------------------- */

    private _closed = false;

    close(): void {
        if (this._closed) return;
        this._closed = true;
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
        const sslPipe = this.sslPipe;
        if (!sslPipe) throw new Error('SSL pipe is not initialized');
        const n = sslPipe.feed(data);
        if (n < 0) throw new Error(`SSL feed error: ${n}`);
        return n;
    }

    private readRaw(buf: Uint8Array): Promise<number> {
        return this.socket.read(buf).catch((err) => {
            if (this._closed && TcpSocket.isDisconnectError(err)) return 0;
            throw err;
        });
    }

    private feedAndRead(data: Uint8Array, size: number): Uint8Array | null {
        this.feedCipher(data);
        return this.sslRead(size);
    }

    private sslRead(size: number): Uint8Array | null {
        const sslPipe = this.sslPipe;
        if (!sslPipe) return null;
        const plain = sslPipe.read(size);
        return (plain && plain.byteLength > 0) ? new Uint8Array(plain) : null;
    }

    static isDisconnectError(err: unknown): boolean {
        if (!(err instanceof Error)) return false;
        const code = (err as CModuleError.Error).code;
        return code === error.errno.ECONNRESET || code === error.errno.EPIPE ||
               code === error.errno.EBADF || code === error.errno.ECANCELED;
    }
}
