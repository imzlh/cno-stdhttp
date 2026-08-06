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
const timers = import.meta.use("timers");

type Uint8Array = globalThis.Uint8Array<ArrayBuffer>;

const READ_SIZE = 16384;
const MAX_WRITE_STALLS = 16;
/**
 * Hard ceiling on how long one `write()` may sit in the SSL stall path waiting for
 * the peer to move cipher. Bounds the whole stall sequence, not each wait, so a
 * dribbling peer cannot hold a write for MAX_WRITE_STALLS * timeout.
 */
const WRITE_STALL_TIMEOUT_MS = 10_000;
/**
 * Cap on how long a TLS handshake may take. A peer that connects and then sends
 * nothing (or dribbles bytes) otherwise parks an fd, a libuv read request and this
 * promise forever: the server's request timeout only starts once the handshake is
 * done, so a slow handshake is a free slowloris.
 */
const HANDSHAKE_TIMEOUT_MS = 30_000;

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
                    this.notifyInput();   // a write stalled on input must not wait out its deadline
                }
                return;
            }
            if (data === null) { this.notifyInput(); this._readCallback?.(null); return; }
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
                    this.pending = consumed < cipher.length ? cipher.subarray(consumed) : null;
                    this.sslPipe.handshake();
                    this.notifyInput();   // cipher reached the engine: a stalled SSL_write may proceed
                    const out = this.sslPipe.getOutput();
                    // Renegotiation output is fire-and-forget here; a rejected write must
                    // reach the error handler instead of surfacing as an unhandled rejection.
                    if (out) {
                        this.socket.write(new Uint8Array(out)).catch((e: unknown) => {
                            this._readErrHandler?.(e instanceof Error ? e : new Error(String(e)));
                        });
                    }
                    // Flush all available plaintext to the callback.
                    while (this._readCallback) {
                        const plain = this.sslRead(READ_SIZE);
                        if (!plain) break;
                        this._readCallback(plain);
                    }
                } catch (e) {
                    this.notifyInput();
                    this._readErrHandler?.(e instanceof Error ? e : new Error(String(e)));
                    return;
                }
            } else {
                this._readCallback?.(data);
            }
        };
        this.socket.startRead();
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
            if (plain) return plain;
        }

        const buf = new Uint8Array(READ_SIZE);
        while (true) {
            const n = await this.readRaw(buf);
            if (n === 0) return null; // EOF
            let cipher = buf.subarray(0, n);
            // Cipher the BIO refused earlier must go back in front, or the TLS record
            // stream is reordered and every later record fails to decrypt.
            if (this.pending) {
                const joined = new Uint8Array(this.pending.length + cipher.length);
                joined.set(this.pending);
                joined.set(cipher, this.pending.length);
                cipher = joined;
                this.pending = null;
            }
            const consumed = this.feedCipher(cipher);
            this.pending = consumed < cipher.length ? cipher.subarray(consumed) : null;
            // Drive SSL state machine (handles renegotiation), then flush any output
            const sslPipe = this.sslPipe;
            if (!sslPipe) return null;
            sslPipe.handshake();
            this.notifyInput();   // cipher reached the engine: a stalled SSL_write may proceed
            const out = sslPipe.getOutput();
            if (out) await this.socket.write(new Uint8Array(out));
            const plain = this.sslRead(size);
            if (plain) return plain;
            // No plaintext yet — renegotiation or partial TLS record, loop
        }
    }

    /**
     * Write plaintext to socket (SSL-aware).
     *
     * Serialised per socket: the TLS path interleaves `sslPipe.write` and
     * `flushOutput` across awaits, so two concurrent writers would emit each
     * other's records out of order and the peer would fail to decrypt. Plain TCP
     * writers would likewise interleave and corrupt the body framing.
     */
    write(data: Uint8Array): Promise<void> {
        const run = this.writeQueue.then(
            () => this.writeLocked(data),
            () => this.writeLocked(data),   // a previous write's failure must not block ours
        );
        // Keep the chain alive and unrejected; each caller still sees its own error.
        this.writeQueue = run.catch(() => { /* reported to the caller of that write */ });
        return run;
    }

    private writeQueue: Promise<void> = Promise.resolve();

    private async writeLocked(data: Uint8Array): Promise<void> {
        if (data.length === 0) return;
        if (!this.sslPipe) { await this.socket.write(data); return; }

        let offset = 0;
        let stalls = 0;
        let deadline = 0;
        while (offset < data.length) {
            // close() nulls sslPipe. A write that resumed here after that would fall
            // through to the plaintext branch on the next call and put cleartext on the
            // wire, so treat a vanished pipe as the disconnect it is.
            const sslPipe = this.sslPipe;
            if (!sslPipe) throw Object.assign(new Error('SSL_write failed: socket closed'), { code: 'ECONNRESET' });

            const written = sslPipe.write(data.subarray(offset));
            // SSL_write signals WANT_READ/WANT_WRITE by returning *null*, not 0 (see
            // CHECK_SSL_ERR in mod_ssl.c). `null === 0` is false and `offset += null`
            // leaves offset untouched, so the old code span this loop forever with no
            // await in it: one socket wedged the entire event loop at 100% CPU. Normalise
            // to a number before any comparison.
            const n = typeof written === 'number' ? written : 0;
            if (n < 0) throw new Error(`SSL_write failed: ${n}`);
            if (n === 0) {
                // SSL must flush output or consume input before accepting more plaintext.
                if (++stalls > MAX_WRITE_STALLS) throw new Error(`SSL_write failed: no progress after ${stalls} attempts`);
                if (deadline === 0) deadline = Date.now() + WRITE_STALL_TIMEOUT_MS;
                await this.makeWriteProgress(deadline);
                continue;
            }
            stalls = 0;
            deadline = 0;
            offset += n;
        }
        await this.flushOutput();
    }

    /**
     * Unblock a stalled SSL_write.
     *
     * Flushing pending cipher out is always safe. Pulling fresh cipher *in* is not:
     * `socket.read()` throws "startRead already in progress" whenever a callback reader
     * (onReadable) or a handshake loop already owns the read, which is every server
     * connection. So issue our own read only when nothing else is reading, and otherwise
     * wait for whoever is — they call notifyInput() once cipher reaches the engine.
     */
    private async makeWriteProgress(deadline: number): Promise<void> {
        if (await this.flushOutput()) return;
        if (this._readCallback || this._readInFlight || this._handshaking) {
            const remaining = deadline - Date.now();
            if (remaining <= 0 || !await this.waitForInput(remaining)) {
                throw Object.assign(new Error('SSL_write stalled: no cipher from peer'), { code: 'ETIMEDOUT' });
            }
            return;
        }
        await this.pumpInput();
    }

    /* -------------------------------------------------------------- */
    /* Input arrival signal (couples the read paths to writeLocked)   */
    /* -------------------------------------------------------------- */

    private _inputWaiters: Array<() => void> = [];
    private _readInFlight = false;
    private _handshaking = false;

    /** Wake writes stalled in makeWriteProgress. Must also run on EOF/error/close. */
    private notifyInput(): void {
        if (this._inputWaiters.length === 0) return;
        const waiters = this._inputWaiters;
        this._inputWaiters = [];
        for (const w of waiters) w();
    }

    /** Resolves true if cipher arrived, false if `ms` elapsed first. */
    private waitForInput(ms: number): Promise<boolean> {
        return new Promise<boolean>((resolve) => {
            let done = false;
            const tid = timers.setTimeout(() => {
                if (done) return;
                done = true;
                resolve(false);
            }, ms);
            this._inputWaiters.push(() => {
                if (done) return;
                done = true;
                timers.clearTimeout(tid);
                resolve(true);
            });
        });
    }

    /* -------------------------------------------------------------- */
    /* TLS Handshake                                                  */
    /* -------------------------------------------------------------- */

    /** Server-side TLS handshake. */
    async serverHandshake(ctx: CModuleSSL.Context): Promise<void> {
        this.sslPipe = new ssl.Pipe(ctx);
        const deadline = this.startHandshakeDeadline();
        this._handshaking = true;
        try {
            const buf = new Uint8Array(READ_SIZE);
            while (!this.sslPipe.handshakeComplete) {
                const n = await this.readRaw(buf);
                if (n === 0) throw new Error("SSL handshake failed: connection closed");
                let toFeed = buf.subarray(0, n);
                while (toFeed.length > 0) {
                    const c = this.feedCipher(toFeed);
                    if (c <= 0) throw new Error(`SSL feed failed during handshake: consumed=${c}`);
                    toFeed = c < toFeed.length ? toFeed.subarray(c) : new Uint8Array(0);
                }
                this.sslPipe.handshake();
                this.notifyInput();   // lets a write issued during the handshake retry SSL_write
                const out = this.sslPipe.getOutput();
                if (out) await this.socket.write(new Uint8Array(out));
            }
        } finally {
            this._handshaking = false;
            this.notifyInput();
            deadline();
        }
    }

    /** Client-side TLS handshake. */
    async clientHandshake(ctx: CModuleSSL.Context, servername?: string): Promise<void> {
        this.sslPipe = new ssl.Pipe(ctx, servername ? { servername } : undefined);
        const deadline = this.startHandshakeDeadline();
        this._handshaking = true;
        try {
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
                this.notifyInput();   // lets a write issued during the handshake retry SSL_write
                const out = this.sslPipe.getOutput();
                if (out) await this.socket.write(new Uint8Array(out));
            }
        } finally {
            this._handshaking = false;
            this.notifyInput();
            deadline();
        }
    }

    /**
     * Arm the handshake timeout. Closing the socket is what actually unblocks the
     * loop: the pending readRaw then completes and the loop throws. Returns the
     * disarm function — call it on every exit path so the timer never outlives
     * the handshake.
     */
    private startHandshakeDeadline(): () => void {
        if (HANDSHAKE_TIMEOUT_MS <= 0) return () => { /* disabled */ };
        const tid = timers.setTimeout(() => { this.close(); }, HANDSHAKE_TIMEOUT_MS);
        return () => { timers.clearTimeout(tid); };
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
        // Wake writes parked in makeWriteProgress; the retry sees sslPipe === null and
        // rejects at once instead of waiting out WRITE_STALL_TIMEOUT_MS on a dead socket.
        this.notifyInput();
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

    private async readRaw(buf: Uint8Array): Promise<number> {
        // Flagged so a stalled SSL_write knows a read is already outstanding and waits
        // for its result instead of racing it into "read already in progress".
        this._readInFlight = true;
        try {
            return await this.socket.read(buf).catch((err) => {
                if (this._closed && TcpSocket.isDisconnectError(err)) return 0;
                throw err;
            });
        } finally {
            this._readInFlight = false;
        }
    }

    private feedAndRead(data: Uint8Array, size: number): Uint8Array | null {
        const consumed = this.feedCipher(data);
        // Re-stash any leftover cipher so a partial TLS record is not dropped.
        this.pending = consumed < data.length ? data.subarray(consumed) : null;
        return this.sslRead(size);
    }

    /** Drain outgoing cipher to the socket. Returns true if anything was written. */
    private async flushOutput(): Promise<boolean> {
        const out = this.sslPipe?.getOutput();
        if (!out || out.byteLength === 0) return false;
        await this.socket.write(new Uint8Array(out));
        return true;
    }

    /** Feed one raw read into the SSL engine to unblock a stalled write. */
    private async pumpInput(): Promise<void> {
        const buf = new Uint8Array(READ_SIZE);
        const n = await this.readRaw(buf);
        if (n === 0) throw new Error('SSL_write failed: connection closed');
        let cipher = buf.subarray(0, n);
        if (this.pending) {
            const joined = new Uint8Array(this.pending.length + cipher.length);
            joined.set(this.pending);
            joined.set(cipher, this.pending.length);
            cipher = joined;
        }
        const consumed = this.feedCipher(cipher);
        this.pending = consumed < cipher.length ? cipher.subarray(consumed) : null;
        this.sslPipe?.handshake();
        this.notifyInput();
        await this.flushOutput();
    }

    private sslRead(size: number): Uint8Array | null {
        const sslPipe = this.sslPipe;
        if (!sslPipe) return null;
        const plain = sslPipe.read(size);
        return (plain && plain.byteLength > 0) ? new Uint8Array(plain) : null;
    }

    /** Peer/socket gone — structured `.code` only (UV number or Node string). */
    static isDisconnectError(err: unknown): boolean {
        if (!(err instanceof Error)) return false;
        const code = Reflect.get(err, 'code');
        if (typeof code === 'number') {
            return code === error.errno.ECONNRESET || code === error.errno.EPIPE ||
                code === error.errno.EBADF || code === error.errno.ECANCELED ||
                code === error.errno.ECONNABORTED || code === error.errno.ESHUTDOWN ||
                code === error.errno.ENOTCONN || code === error.errno.EOF;
        }
        if (typeof code === 'string') {
            return code === 'ECONNRESET' || code === 'EPIPE' || code === 'EBADF' ||
                code === 'ECANCELED' || code === 'ECONNABORTED' || code === 'ESHUTDOWN' ||
                code === 'ENOTCONN' || code === 'EOF';
        }
        return false;
    }
}
