/** TCP/TLS transport shared by the protocol layers. */

const streams = import.meta.use("streams");
const ssl = import.meta.use("ssl");
const error = import.meta.use("error");
const timers = import.meta.use("timers");

type Uint8Array = globalThis.Uint8Array<ArrayBuffer>;

const READ_SIZE = 16384;
const MAX_WRITE_STALLS = 16;
// Bound the entire stall sequence, including peers that dribble input.
const WRITE_STALL_TIMEOUT_MS = 10_000;
// Request timeouts only start after the handshake completes.
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

export class TcpSocket implements ISocket {
    public  socket:  SocketTransport;
    public  sslPipe: CModuleSSL.Pipe | null = null;
    private pending: Uint8Array | null = null;

    constructor(socket?: SocketTransport) {
        this.socket = socket ?? new streams.TCP();
    }

    private _readCallback: ((data: Uint8Array | null) => void) | null = null;
    private _readErrHandler: ((err: Error) => void) | null = null;

    private setupReadCallback(): void {
        try { this.socket.stopRead(); } catch { /* ignore */ }
        this.socket.onread = (data: Uint8Array | null | undefined, err?: CModuleError.Error) => {
            if (data === undefined) {
                if (err) {
                    // Detach terminal readers before invoking user callbacks.
                    const handler = this._readErrHandler;
                    this.stopReading();
                    this.notifyInput();   // a write stalled on input must not wait out its deadline
                    handler?.(err);
                }
                return;
            }
            if (data === null) {
                const callback = this._readCallback;
                this.stopReading();
                this.notifyInput();
                callback?.(null);
                return;
            }
            // TLS: decrypt cipher before delivering (same path as read()).
            if (this.sslPipe) {
                try {
                    this.feedInput(data);
                    this.sslPipe.handshake();
                    this.notifyInput();   // cipher reached the engine: a stalled SSL_write may proceed
                    const out = this.sslPipe.getOutput();
                    // Renegotiation output is fire-and-forget here; a rejected write must
                    // reach the error handler instead of surfacing as an unhandled rejection.
                    if (out) {
                        this.writeRaw(new Uint8Array(out)).catch((e: unknown) => {
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
                    const handler = this._readErrHandler;
                    this.stopReading();
                    this.notifyInput();
                    handler?.(e instanceof Error ? e : new Error(String(e)));
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
        try {
            this.socket.stopRead();
        } finally {
            this._readCallback = null;
            this._readErrHandler = null;
            Reflect.set(this.socket, 'onread', null);
        }
    }

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
            this.feedInput(buf.subarray(0, n));
            // Drive SSL state machine (handles renegotiation), then flush any output
            const sslPipe = this.sslPipe;
            if (!sslPipe) return null;
            sslPipe.handshake();
            this.notifyInput();   // cipher reached the engine: a stalled SSL_write may proceed
            const out = sslPipe.getOutput();
            if (out) await this.writeRaw(new Uint8Array(out));
            const plain = this.sslRead(size);
            if (plain) return plain;
            // No plaintext yet — renegotiation or partial TLS record, loop
        }
    }

    /** Serialize writes so concurrent callers cannot interleave TLS records or framing. */
    write(data: Uint8Array): Promise<void> {
        const run = this.writeQueue.then(() => this.writeLocked(data));
        // Keep the chain alive and unrejected; each caller still sees its own error.
        this.writeQueue = run.catch(() => { /* reported to the caller of that write */ });
        return run;
    }

    private writeQueue: Promise<void> = Promise.resolve();
    private rawWriteQueue: Promise<void> = Promise.resolve();

    private writeRaw(data: Uint8Array): Promise<void> {
        const run = this.rawWriteQueue.then(async () => {
            this.assertOpen();
            await this.socket.write(data);
        });
        this.rawWriteQueue = run.catch(() => { /* reported to the owning operation */ });
        return run;
    }

    private async writeLocked(data: Uint8Array): Promise<void> {
        this.assertOpen();
        if (data.length === 0) return;
        if (!this.sslPipe) { await this.writeRaw(data); return; }

        let offset = 0;
        let stalls = 0;
        let deadline = 0;
        while (offset < data.length) {
            // A vanished TLS pipe is a disconnect, never a plaintext fallback.
            const sslPipe = this.sslPipe;
            if (!sslPipe) throw Object.assign(new Error('SSL_write failed: socket closed'), { code: 'ECONNRESET' });

            const written = sslPipe.write(data.subarray(offset));
            // Native SSL_write returns null for retryable WANT_READ/WANT_WRITE.
            const n = written ?? 0;
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

    /** Borrow input only when no callback reader, read(), or handshake already owns it. */
    private async makeWriteProgress(deadline: number): Promise<void> {
        if (await this.flushOutput()) return;
        const remaining = deadline - Date.now();
        const timeoutError = Object.assign(new Error('SSL_write stalled: no cipher from peer'), { code: 'ETIMEDOUT' });
        if (remaining <= 0) throw timeoutError;
        if (this._readCallback || this._readInFlight || this._handshaking) {
            if (!await this.waitForInput(remaining)) throw timeoutError;
            return;
        }
        let timer: number | undefined;
        try {
            await Promise.race([
                this.pumpInput(),
                new Promise<never>((_, reject) => {
                    timer = timers.setTimeout(() => {
                        // Cancel the native read too; abandoning its promise leaks the reader.
                        this.close();
                        reject(timeoutError);
                    }, remaining);
                }),
            ]);
        } finally {
            if (timer !== undefined) timers.clearTimeout(timer);
        }
    }

    private _inputWaiters = new Set<() => void>();
    private _readInFlight = false;
    private _handshaking = false;

    /** Wake writes stalled in makeWriteProgress. Must also run on EOF/error/close. */
    private notifyInput(): void {
        if (this._inputWaiters.size === 0) return;
        const waiters = [...this._inputWaiters];
        this._inputWaiters.clear();
        for (const w of waiters) w();
    }

    /** Resolves true if cipher arrived, false if `ms` elapsed first. */
    private waitForInput(ms: number): Promise<boolean> {
        return new Promise<boolean>((resolve) => {
            const wake = () => {
                timers.clearTimeout(tid);
                resolve(true);
            };
            const tid = timers.setTimeout(() => {
                this._inputWaiters.delete(wake);
                resolve(false);
            }, ms);
            this._inputWaiters.add(wake);
        });
    }

    serverHandshake(ctx: CModuleSSL.Context): Promise<void> {
        return this.handshake(ctx, false);
    }

    clientHandshake(ctx: CModuleSSL.Context, servername?: string): Promise<void> {
        return this.handshake(ctx, true, servername);
    }

    private async handshake(ctx: CModuleSSL.Context, client: boolean, servername?: string): Promise<void> {
        this.assertOpen();
        const pipe = this.sslPipe = new ssl.Pipe(ctx, servername ? { servername } : undefined);
        // Closing cancels the pending native read as well as the TLS session.
        const timer = timers.setTimeout(() => this.close(), HANDSHAKE_TIMEOUT_MS);
        this._handshaking = true;
        try {
            if (client) {
                pipe.handshake();
                await this.flushOutput();
            }

            const buf = new Uint8Array(READ_SIZE);
            while (!pipe.handshakeComplete) {
                const n = await this.readRaw(buf);
                if (n === 0) throw new Error(`${client ? 'TLS' : 'SSL'} handshake failed: connection closed`);
                let toFeed = buf.subarray(0, n);
                while (toFeed.length > 0) {
                    const c = this.feedCipher(toFeed);
                    if (c <= 0) throw new Error(`SSL feed failed during handshake: consumed=${c}`);
                    toFeed = toFeed.subarray(c);
                }
                pipe.handshake();
                this.notifyInput();
                await this.flushOutput();
            }
        } finally {
            this._handshaking = false;
            this.notifyInput();
            timers.clearTimeout(timer);
        }
    }

    get alpnProtocol(): string | undefined {
        return this.sslPipe?.alpnProtocol ?? undefined;
    }

    private _closed = false;

    close(): void {
        if (this._closed) return;
        this._closed = true;
        this.pending = null;
        try { this.stopReading(); } catch { /* still release the TLS session and transport */ }
        try { this.sslPipe?.shutdown(); } catch { /* ignore */ }
        this.sslPipe = null;
        this.notifyInput();
        try { this.socket.close(); } catch { /* ignore */ }
    }

    private assertOpen(): void {
        if (this._closed) throw Object.assign(new Error('socket closed'), { code: 'ECONNRESET' });
    }

    private feedInput(data: Uint8Array): void {
        // Preserve rejected cipher ahead of new input to keep TLS records ordered.
        if (this.pending) {
            const joined = new Uint8Array(this.pending.length + data.length);
            joined.set(this.pending);
            joined.set(data, this.pending.length);
            data = joined;
        }
        const consumed = this.feedCipher(data);
        this.pending = consumed < data.length ? data.slice(consumed) : null;
    }

    private feedCipher(data: Uint8Array): number {
        const sslPipe = this.sslPipe;
        if (!sslPipe) throw new Error('SSL pipe is not initialized');
        const n = sslPipe.feed(data);
        if (n < 0) throw new Error(`SSL feed error: ${n}`);
        return n;
    }

    private async readRaw(buf: Uint8Array): Promise<number> {
        this._readInFlight = true;
        try {
            return await this.socket.read(buf);
        } catch (err) {
            if (this._closed && TcpSocket.isDisconnectError(err)) return 0;
            throw err;
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
        await this.writeRaw(new Uint8Array(out));
        return true;
    }

    /** Feed one raw read into the SSL engine to unblock a stalled write. */
    private async pumpInput(): Promise<void> {
        const buf = new Uint8Array(READ_SIZE);
        const n = await this.readRaw(buf);
        if (n === 0) throw new Error('SSL_write failed: connection closed');
        this.feedInput(buf.subarray(0, n));
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
