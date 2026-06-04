/**
 * Protocol-agnostic connection pooling.
 *
 * Manages TcpSocket connections with keep-alive, DNS resolution,
 * TLS setup, and cross-platform CA certificate discovery.
 *
 * This module does NOT know about HTTP — it just manages raw TCP/TLS connections.
 * Protocol negotiation (H1 vs H2 vs H3) happens at the protocol layer.
 *
 * Generator-based I/O: logic expressed as generators yielding IOOp,
 * dispatched by syncDriver (readSync/writeSync) or asyncDriver (await).
 */

const os = import.meta.use("os");
const timers = import.meta.use("timers");
const asfs = import.meta.use("asyncfs");
const engine = import.meta.use("engine");
const ssl = import.meta.use("ssl");
const windows = import.meta.use("win32");
const fs = import.meta.use("fs");
const streams = import.meta.use("streams");

import { dnsCache } from "./dns-cache";
import { dbg } from "./debug";

function assert(condition: unknown, message?: string): asserts condition {
    if (!condition) throw new Error(message ?? "Assertion failed");
}

type Uint8Array = globalThis.Uint8Array<ArrayBuffer>;

// ---------------------------------------------------------------------------
// IO Operation type — generators yield these, drivers dispatch
// ---------------------------------------------------------------------------

interface IORead  { tag: 'read';  buf: Uint8Array }
interface IOWrite { tag: 'write'; data: Uint8Array }
type IOOp = IORead | IOWrite;

function ioRead(buf: Uint8Array): IORead  { return { tag: 'read', buf }; }
function ioWrite(data: Uint8Array): IOWrite { return { tag: 'write', data }; }

// ---------------------------------------------------------------------------
// ConnectionConfig / ConnectionState / ConnectionLike
// ---------------------------------------------------------------------------

export interface ConnectionConfig {
    hostname: string;
    port: number;
    protocol: "http:" | "https:";
    timeout?: number;
    keepAlive?: boolean;
    keepAliveTimeout?: number;
    maxSockets?: number;
    client?: any;
}

export enum ConnectionState {
    IDLE       = "idle",
    ACTIVE     = "active",
    CONNECTING = "connecting",
    CLOSED     = "closed"
}

export interface ConnectionLike {
    socket:   CModuleStreams.TCP;
    sslPipe:  CModuleSSL.Pipe | null;
    state:    ConnectionState;
    lastUsed: number;
    requests: number;
    isSync:   boolean;
    connect(): void;
    connectAsync(): Promise<void>;
    write(data: Uint8Array): void;
    writeAsync(data: Uint8Array): Promise<void>;
    read(size?: number, waitForData?: boolean): Uint8Array | null;
    readAsync(size?: number, waitForData?: boolean): Promise<Uint8Array | null>;
    markActive(): void;
    markIdle(): void;
    close(): void;
    isAvailable(): boolean;
    isClosed(): boolean;
}

/* ------------------------------------------------------------------ */
/* CA Certificate Discovery                                           */
/* ------------------------------------------------------------------ */

let windowsCaCache: string | null = null;
let windowsCaPromise: Promise<string | null> | null = null;

async function generateWindowsCaBundle(): Promise<string | null> {
    const tmpDir = os.tmpDir || 'C:\\Windows\\Temp';
    const tmp = tmpDir + '\\cno-ca-bundle.pem';
    try {
        const certs = windows!.exportCerts();
        if (!certs || certs.length === 0) return null;
        const pemContent = certs.join("\n");
        const fh = await asfs.open(tmp, 'w', 0o600);
        await fh.write(engine.encodeString(pemContent));
        await fh.close();
        return tmp;
    } catch { return null; }
}

function findSystemCaPathSync(): string | null {
    const sysname = os.uname().sysname;

    if (sysname === "Windows_NT") {
        if (windowsCaCache) return windowsCaCache;
        if (!windowsCaPromise) {
            windowsCaPromise = generateWindowsCaBundle().then(result => {
                windowsCaCache = result; windowsCaPromise = null; return result;
            });
        }
        return engine.waitPromise(windowsCaPromise);
    }

    const candidates: string[] = (() => {
        switch (sysname) {
            case "Linux": return [
                "/etc/ssl/certs/ca-certificates.crt",
                "/etc/pki/tls/certs/ca-bundle.crt",
                "/etc/pki/tls/cert.pem",
                "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
                "/etc/ssl/cert.pem",
                "/etc/ssl/ca-bundle.pem",
                "/etc/ca-certificates/extracted/tls-ca-bundle.pem",
                "/etc/ssl/ca-bundle.pem",
                "/etc/ca-certificates.crt",
                "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
            ];
            case "Darwin": return [
                "/etc/ssl/cert.pem",
                "/usr/local/etc/openssl/cert.pem",
                "/opt/homebrew/etc/openssl/cert.pem",
                "/opt/homebrew/etc/openssl@3/cert.pem",
                "/usr/local/etc/openssl@3/cert.pem",
                "/System/Library/OpenSSL/certs",
            ];
            case "FreeBSD": return [
                "/usr/local/share/certs/ca-root-nss.crt",
                "/usr/local/openssl/cert.pem",
                "/etc/ssl/cert.pem",
            ];
            case "OpenBSD": return [
                "/etc/ssl/cert.pem",
                "/usr/local/share/cert.pem",
            ];
            default: return [];
        }
    })();

    for (const path of candidates) {
        try {
            const stat = fs.stat(path);
            if (stat.isFile) return path;
            if (stat.isDirectory && path.includes("certs")) return path;
        } catch { /* not found */ }
    }
    return null;
}

export async function findSystemCaPath(): Promise<string | null> {
    const sysname = os.uname().sysname;
    const candidates: string[] = await (async () => {
        switch (sysname) {
            case "Linux": return [
                "/etc/ssl/certs/ca-certificates.crt",
                "/etc/pki/tls/certs/ca-bundle.crt",
                "/etc/pki/tls/cert.pem",
                "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
                "/etc/ssl/cert.pem",
                "/etc/ssl/ca-bundle.pem",
                "/etc/ca-certificates/extracted/tls-ca-bundle.pem",
                "/etc/ssl/ca-bundle.pem",
                "/etc/ca-certificates.crt",
                "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
            ];
            case "Darwin": return [
                "/etc/ssl/cert.pem",
                "/usr/local/etc/openssl/cert.pem",
                "/opt/homebrew/etc/openssl/cert.pem",
                "/opt/homebrew/etc/openssl@3/cert.pem",
                "/usr/local/etc/openssl@3/cert.pem",
                "/System/Library/OpenSSL/certs",
            ];
            case "Windows_NT": return [];
            case "FreeBSD": return [
                "/usr/local/share/certs/ca-root-nss.crt",
                "/usr/local/openssl/cert.pem",
                "/etc/ssl/cert.pem",
            ];
            case "OpenBSD": return [
                "/etc/ssl/cert.pem",
                "/usr/local/share/cert.pem",
            ];
            default: return [];
        }
    })();

    for (const path of candidates) {
        try {
            const stat = await asfs.stat(path);
            if (stat.isFile) return path;
            if (stat.isDirectory && path.includes("certs")) return path;
        } catch { /* not found */ }
    }

    if (sysname === "Windows_NT") {
        if (windowsCaCache) return windowsCaCache;
        if (!windowsCaPromise) {
            windowsCaPromise = generateWindowsCaBundle().then(result => {
                windowsCaCache = result; windowsCaPromise = null; return result;
            });
        }
        return windowsCaPromise;
    }
    return null;
}

/* ------------------------------------------------------------------ */
/* Single Connection                                                  */
/* ------------------------------------------------------------------ */

export class Connection implements ConnectionLike {
    public socket:   CModuleStreams.TCP;
    public sslPipe:  CModuleSSL.Pipe | null = null;
    public state:    ConnectionState        = ConnectionState.CONNECTING;
    public lastUsed: number                 = Date.now();
    public requests: number                 = 0;
    public onClose:  (() => void) | null    = null;
    public isSync:   boolean                = false;

    private idleTimer: number | null = null;
    private config: ConnectionConfig;
    private pendingCiphertext: Uint8Array | null = null;

    constructor(cfg: ConnectionConfig) {
        this.config = cfg;
        this.socket = new streams.TCP();
    }

    // -----------------------------------------------------------------------
    // Connect (sync) — uses connectSync + readSync/writeSync
    // -----------------------------------------------------------------------

    connect(): void {
        try {
            this.isSync = true;
            const isSecure = this.config.protocol === "https:";
            dbg('http.conn', () => `connect(sync) ${this.config.protocol}//${this.config.hostname}:${this.config.port}`);

            if (this.config.client) {
                this.socket = engine.waitPromise(
                    this.config.client.connect(this.config.hostname, this.config.port, isSecure)
                );
            } else {
                const addrs = dnsCache.resolveSync(this.config.hostname, os.AF_UNSPEC);
                if (!addrs?.length) throw new Error(`DNS resolution failed for ${this.config.hostname}`);
                const addr = addrs.find((a: any) => a.family === 4) || addrs[0];
                assert(addr, `No IP address found for ${this.config.hostname}`);
                dbg('http.conn', () => `DNS resolved ${this.config.hostname} → ${addr.ip}`);
                (this.socket.connectSync as any)({ ip: addr.ip, port: this.config.port }, this.getTimeoutMs() ?? 30000);
            }

            if (isSecure) {
                const clientCtx = this.config.client?.getSSLContext();
                if (clientCtx) {
                    dbg('http.conn', () => `TLS handshake (custom ctx) for ${this.config.hostname}`);
                    this.syncDriver(this.performTLSHandshake(clientCtx, this.config.hostname));
                } else {
                    const caPath = findSystemCaPathSync();
                    if (!caPath) throw new Error("No system CA bundle found - cannot verify TLS certificates.");
                    dbg('http.conn', () => `TLS handshake for ${this.config.hostname} (ca: ${caPath})`);
                    const ctx = new ssl.Context({ mode: "client", verify: true, ca: caPath });
                    this.syncDriver(this.performTLSHandshake(ctx, this.config.hostname));
                }
            }

            (this.socket as any).onclose = () => {
                if (this.state === ConnectionState.CLOSED) return;
                dbg('http.conn', () => `socket closed: ${this.config.hostname}:${this.config.port}`);
                this.stopIdleTimer();
                this.state = ConnectionState.CLOSED;
                this.onClose?.();
            };

            dbg('http.conn', () => `connected(sync): ${this.config.hostname}:${this.config.port}`);
            this.state = ConnectionState.IDLE;
            this.startIdleTimer();
        } catch (err) {
            dbg('http.conn', () => `connect(sync) FAILED ${this.config.hostname}:${this.config.port}: ${err}`);
            this.state = ConnectionState.CLOSED;
            throw err;
        }
    }

    // -----------------------------------------------------------------------
    // Connect (async)
    // -----------------------------------------------------------------------

    async connectAsync(): Promise<void> {
        try {
            const isSecure = this.config.protocol === "https:";
            dbg('http.conn', () => `connect(async) ${this.config.protocol}//${this.config.hostname}:${this.config.port}`);

            if (this.config.client) {
                this.socket = await this.withTimeoutAsync(
                    `connect ${this.config.hostname}:${this.config.port}`,
                    () => this.config.client.connect(this.config.hostname, this.config.port, isSecure)
                );
            } else {
                const addrs = await dnsCache.resolve(this.config.hostname, { family: os.AF_UNSPEC });
                if (!addrs?.length) throw new Error(`DNS resolution failed for ${this.config.hostname}`);
                const addr = addrs.find((a: any) => a.family === 4) || addrs[0];
                assert(addr, `No IP address found for ${this.config.hostname}`);
                dbg('http.conn', () => `DNS resolved ${this.config.hostname} → ${addr.ip}`);
                await this.withTimeoutAsync(
                    `connect ${this.config.hostname}:${this.config.port}`,
                    () => this.socket.connect({ ip: addr.ip, port: this.config.port })
                );
            }

            if (isSecure) {
                const clientCtx = this.config.client?.getSSLContext();
                if (clientCtx) {
                    dbg('http.conn', () => `TLS handshake (custom ctx) for ${this.config.hostname}`);
                    await this.withTimeoutAsync(
                        `TLS handshake ${this.config.hostname}:${this.config.port}`,
                        () => this.asyncDriver(this.performTLSHandshake(clientCtx, this.config.hostname))
                    );
                } else {
                    const caPath = await findSystemCaPath();
                    if (!caPath) throw new Error("No system CA bundle found - cannot verify TLS certificates.");
                    dbg('http.conn', () => `TLS handshake for ${this.config.hostname} (ca: ${caPath})`);
                    const ctx = new ssl.Context({ mode: "client", verify: true, ca: caPath });
                    await this.withTimeoutAsync(
                        `TLS handshake ${this.config.hostname}:${this.config.port}`,
                        () => this.asyncDriver(this.performTLSHandshake(ctx, this.config.hostname))
                    );
                }
            }

            (this.socket as any).onclose = () => {
                if (this.state === ConnectionState.CLOSED) return;
                dbg('http.conn', () => `socket closed: ${this.config.hostname}:${this.config.port}`);
                this.stopIdleTimer();
                this.state = ConnectionState.CLOSED;
                this.onClose?.();
            };

            dbg('http.conn', () => `connected(async): ${this.config.hostname}:${this.config.port}`);
            this.state = ConnectionState.IDLE;
            this.startIdleTimer();
        } catch (err) {
            dbg('http.conn', () => `connect(async) FAILED ${this.config.hostname}:${this.config.port}: ${err}`);
            this.state = ConnectionState.CLOSED;
            throw err;
        }
    }

    // -----------------------------------------------------------------------
    // Write (sync) — direct writeSync on socket
    // -----------------------------------------------------------------------

    write(data: Uint8Array): void {
        if (this.sslPipe) {
            let offset = 0;
            while (offset < data.length) {
                const written = this.sslPipe.write(data.subarray(offset));
                if (written < 0) throw new Error(`SSL_write failed: ${written}`);
                offset += written;
            }
            const encrypted = this.sslPipe.getOutput();
            if (encrypted) engine.waitPromise(this.socket.write(new Uint8Array(encrypted)));
        } else {
            engine.waitPromise(this.socket.write(data));
        }
    }

    // -----------------------------------------------------------------------
    // Write (async)
    // -----------------------------------------------------------------------

    async writeAsync(data: Uint8Array): Promise<void> {
        if (data.length === 0) return;
        await this.withTimeoutAsync(`write ${this.config.hostname}:${this.config.port}`, async () => {
            if (this.sslPipe) {
                let offset = 0;
                while (offset < data.length) {
                    const written = this.sslPipe.write(data.subarray(offset));
                    if (written < 0) throw new Error(`SSL_write failed: ${written}`);
                    offset += written;
                }
                const encrypted = this.sslPipe.getOutput();
                if (encrypted) await this.socket.write(new Uint8Array(encrypted));
            } else {
                await this.socket.write(data);
            }
        });
    }

    // -----------------------------------------------------------------------
    // Read (sync/async) — dispatch to generator + driver
    // -----------------------------------------------------------------------

    read(size = 16384, waitForData = false): Uint8Array | null {
        return this.syncDriver(this.sslPipe
            ? this.readSSL(size, waitForData)
            : this.readPlain(size, waitForData));
    }

    readAsync(size = 16384, waitForData = false): Promise<Uint8Array | null> {
        return this.withTimeoutAsync(
            `read ${this.config.hostname}:${this.config.port}`,
            () => this.asyncDriver(this.sslPipe
                ? this.readSSL(size, waitForData)
                : this.readPlain(size, waitForData))
        );
    }

    // -----------------------------------------------------------------------
    // Plain read generator — yields IOOp (read)
    // -----------------------------------------------------------------------

    private *readPlain(size: number, waitForData: boolean): Generator<IOOp, Uint8Array | null> {
        const buf = new Uint8Array(size);
        const n = yield ioRead(buf);

        if (n === null) return null;
        if (n === 0) {
            if (!waitForData) return null;
            for (let i = 0; i < 3; i++) {
                const retryN = yield ioRead(buf);
                if (retryN === null) return null;
                if (retryN > 0) return buf.subarray(0, retryN);
            }
            return null;
        }
        return buf.subarray(0, n);
    }

    // -----------------------------------------------------------------------
    // SSL read generator — yields IOOp (read or write)
    // -----------------------------------------------------------------------

    private *readSSL(size: number, waitForData: boolean): Generator<IOOp, Uint8Array | null> {
        // Drain any buffered pending ciphertext first
        if (this.pendingCiphertext && this.pendingCiphertext.length > 0) {
            const consumed = this.feedCiphertext(this.pendingCiphertext);
            if (consumed > 0) {
                this.pendingCiphertext = consumed < this.pendingCiphertext.length
                    ? this.pendingCiphertext.subarray(consumed)
                    : null;
            }
            // Drive handshake state machine and flush any output (e.g. renegotiation)
            this.sslPipe!.handshake();
            const pending = this.sslPipe!.getOutput();
            if (pending) yield ioWrite(new Uint8Array(pending));
        }

        // Return buffered plaintext if available
        const buffered = this.sslPipe!.read(size);
        if (buffered && buffered.byteLength > 0) return new Uint8Array(buffered);

        // Read loop: keep reading until we get plaintext or true EOF.
        // We loop on "n > 0 but no plaintext" because that means SSL is processing
        // a mid-stream handshake (TLS renegotiation) and needs more data.
        while (true) {
            const cipherBuf = new Uint8Array(size);
            const n = yield ioRead(cipherBuf);

            if (n === null) return null; // sync EOF
            if (n === 0) {
                if (!waitForData) return null;
                // Windows/TLS may transiently yield 0 while the socket is still
                // alive. Retry a few times before treating it as EOF.
                for (let i = 0; i < 3; i++) {
                    const retryBuf = new Uint8Array(size);
                    const retryN = yield ioRead(retryBuf);
                    if (retryN === null) return null;
                    if (retryN === 0) continue;
                    const retryCiphertext = retryBuf.subarray(0, retryN);
                    const retryConsumed = this.feedCiphertext(retryCiphertext);
                    if (retryConsumed < retryCiphertext.length) {
                        const unfed = retryCiphertext.subarray(retryConsumed);
                        this.pendingCiphertext = this.pendingCiphertext
                            ? (() => {
                                const merged = new Uint8Array(this.pendingCiphertext!.length + unfed.length);
                                merged.set(this.pendingCiphertext!);
                                merged.set(unfed, this.pendingCiphertext!.length);
                                return merged;
                            })()
                            : unfed;
                    }
                    this.sslPipe!.handshake();
                    const retryOutput = this.sslPipe!.getOutput();
                    if (retryOutput) yield ioWrite(new Uint8Array(retryOutput));
                    const retryPlaintext = this.sslPipe!.read(size);
                    if (retryPlaintext && retryPlaintext.byteLength > 0) return new Uint8Array(retryPlaintext);
                }
                return null;
            }

            const ciphertext = cipherBuf.subarray(0, n);
            const consumed = this.feedCiphertext(ciphertext);
            if (consumed < ciphertext.length) {
                const unfed = ciphertext.subarray(consumed);
                this.pendingCiphertext = this.pendingCiphertext
                    ? (() => { const m = new Uint8Array(this.pendingCiphertext!.length + unfed.length); m.set(this.pendingCiphertext!); m.set(unfed, this.pendingCiphertext!.length); return m; })()
                    : unfed;
            }

            // Drive SSL state machine (handles renegotiation), then flush output
            this.sslPipe!.handshake();
            const sslOutput = this.sslPipe!.getOutput();
            if (sslOutput) yield ioWrite(new Uint8Array(sslOutput));

            const plaintext = this.sslPipe!.read(size);
            if (plaintext && plaintext.byteLength > 0) return new Uint8Array(plaintext);
            // No plaintext yet (renegotiation in progress or partial TLS record) — loop
        }
    }

    // -----------------------------------------------------------------------
    // I/O drivers
    //
    // syncDriver: uses readSync/writeSync — OS-level blocking I/O.
    //   On Windows: connectSync commits the socket to sync mode permanently;
    //   readSync/writeSync work natively.
    //
    // asyncDriver: uses native await for truly async execution.
    // -----------------------------------------------------------------------

    private async asyncDriver<T>(gen: Generator<IOOp, T>): Promise<T> {
        let next = gen.next();
        while (!next.done) try {
            const op = next.value as IOOp;
            if (op.tag === 'read') {
                const n = await this.withTimeoutAsync(
                    `read ${this.config.hostname}:${this.config.port}`,
                    () => this.socket.read(op.buf)
                );
                next = gen.next(n);
            } else {
                await this.withTimeoutAsync(
                    `write ${this.config.hostname}:${this.config.port}`,
                    () => this.socket.write(op.data)
                );
                next = gen.next(undefined);
            }
        } catch (e) {
            next = gen.throw(e);
        }
        return next.value;
    }

    private getTimeoutMs(): number | null {
        return typeof this.config.timeout === 'number' && this.config.timeout > 0
            ? this.config.timeout
            : null;
    }

    private withTimeoutAsync<T>(label: string, run: () => Promise<T>): Promise<T> {
        const timeoutMs = this.getTimeoutMs();
        if (!timeoutMs) return run();
        return new Promise<T>((resolve, reject) => {
            let settled = false;
            const timeoutId = timers.setTimeout(() => {
                if (settled) return;
                settled = true;
                try { this.close(); } catch {}
                reject(new Error(`${label} timeout after ${timeoutMs}ms`));
            }, timeoutMs);

            run().then(
                (value) => {
                    if (settled) return;
                    settled = true;
                    timers.clearTimeout(timeoutId);
                    resolve(value);
                },
                (error) => {
                    if (settled) return;
                    settled = true;
                    timers.clearTimeout(timeoutId);
                    reject(error);
                }
            );
        });
    }

    private syncDriver<T>(gen: Generator<IOOp, T>): T {
        let next = gen.next();
        while (!next.done) try {
            const op = next.value as IOOp;
            if (op.tag === 'read') {
                const n = engine.waitPromise(this.socket.read(op.buf));
                next = gen.next(n);
            } else {
                engine.waitPromise(this.socket.write(op.data));
                next = gen.next(undefined);
            }
        } catch (e) {
            next = gen.throw(e);
        }
        return next.value;
    }

    // -----------------------------------------------------------------------
    // TLS handshake generator — yields IOOp for both read AND write
    // -----------------------------------------------------------------------

    private *performTLSHandshake(ctx: CModuleSSL.Context, servername?: string): Generator<IOOp, void> {
        this.sslPipe = new ssl.Pipe(ctx, servername ? { servername } : undefined);
        this.sslPipe.handshake();

        const initialData = this.sslPipe.getOutput();
        if (initialData) {
            yield ioWrite(new Uint8Array(initialData));
        }

        while (!this.sslPipe.handshakeComplete) {
            const buf = new Uint8Array(16384);
            const n = yield ioRead(buf);

            if (n === null) throw new Error("TLS handshake failed: connection closed (EOF)");
            if (n === 0)    throw new Error("TLS handshake failed: no data available (EAGAIN)");

            let toFeed = buf.subarray(0, n);
            while (toFeed.length > 0) {
                const consumed = this.feedCiphertext(toFeed);
                if (consumed === 0) break;
                if (consumed < 0) throw new Error(`SSL feed failed during handshake: consumed=${consumed}`);
                toFeed = toFeed.subarray(consumed);
            }

            this.sslPipe.handshake();

            const responseData = this.sslPipe.getOutput();
            if (responseData) {
                yield ioWrite(new Uint8Array(responseData));
            }
        }
    }

    // -----------------------------------------------------------------------
    // SSL helpers
    // -----------------------------------------------------------------------

    private feedCiphertext(data: Uint8Array): number {
        if (!this.sslPipe) return 0;
        const consumed = this.sslPipe.feed(data);
        if (consumed < 0) throw new Error(`SSL feed error: ${consumed}`);
        return consumed;
    }

    // -----------------------------------------------------------------------
    // State transitions
    // -----------------------------------------------------------------------

    markActive(): void {
        this.stopIdleTimer();
        this.state    = ConnectionState.ACTIVE;
        this.lastUsed = Date.now();
        this.requests++;
    }

    markIdle(): void {
        this.state    = ConnectionState.IDLE;
        this.lastUsed = Date.now();
        if (this.config.keepAlive) this.startIdleTimer();
        else this.close();
    }

    close(): void {
        if (this.state === ConnectionState.CLOSED) return;
        this.stopIdleTimer();
        try {
            if (this.sslPipe) this.sslPipe.shutdown();
        } catch {}
        this.sslPipe = null;
        this.pendingCiphertext = null;
        try { this.socket.close(); } catch {}
        this.state = ConnectionState.CLOSED;
        this.onClose?.();
    }

    isAvailable(): boolean { return this.state === ConnectionState.IDLE; }
    isClosed():    boolean { return this.state === ConnectionState.CLOSED; }

    // -----------------------------------------------------------------------
    // Idle timer
    // -----------------------------------------------------------------------

    private startIdleTimer(): void {
        if (!this.config.keepAlive) return;
        this.stopIdleTimer();
        this.idleTimer = timers.setTimeout(() => {
            if (this.state === ConnectionState.IDLE) this.close();
        }, this.config.keepAliveTimeout || 5000);
    }

    private stopIdleTimer(): void {
        if (this.idleTimer !== null) { timers.clearTimeout(this.idleTimer); this.idleTimer = null; }
    }
}

/* ------------------------------------------------------------------ */
/* Connection Pool Manager                                            */
/* ------------------------------------------------------------------ */

export class ConnectionManager {
    private pools = new Map<string, Connection[]>();
    private waiters = new Map<string, Array<{
        resolve: (c: Connection) => void;
        reject: (e: Error) => void;
        timeoutId: number;
    }>>();

    private defaultConfig: Partial<ConnectionConfig> = {
        timeout: 30000, keepAlive: true, keepAliveTimeout: 5000, maxSockets: 10
    };

    private getKey(cfg: ConnectionConfig, sync = false): string {
        const clientId = cfg.client ? `[client-${cfg.client.getSSLContext() ? 'custom' : 'default'}]` : '';
        const proxyId  = cfg.client?.getProxyUrl() ? `[proxy]` : '';
        const modeTag  = sync ? '[sync]' : '[async]';
        return `${cfg.protocol}//${cfg.hostname}:${cfg.port}${clientId}${proxyId}${modeTag}`;
    }

    acquire(cfg: ConnectionConfig): Connection {
        const fullCfg: ConnectionConfig = { ...this.defaultConfig, ...cfg };
        const key = this.getKey(fullCfg, true);
        this.cleanupPool(key);

        let pool = this.pools.get(key) || [];
        const available = pool.find(c => c.isAvailable());
        if (available) {
            dbg('http.conn', () => `pool hit (sync): ${key} (pool size=${pool.length})`);
            available.markActive(); return available;
        }

        if (pool.length >= (fullCfg.maxSockets || 10)) {
            this.closeIdleConnections(key);
        }

        dbg('http.conn', () => `pool miss (sync): ${key} — creating new connection`);
        const conn = new Connection(fullCfg);
        conn.onClose = () => this.removeConnection(fullCfg, conn);
        pool.push(conn);
        this.pools.set(key, pool);
        conn.connect();
        conn.markActive();
        return conn;
    }

    async acquireAsync(cfg: ConnectionConfig): Promise<Connection> {
        const fullCfg: ConnectionConfig = { ...this.defaultConfig, ...cfg };
        const key = this.getKey(fullCfg);
        this.cleanupPool(key);

        let pool = this.pools.get(key) || [];
        const available = pool.find(c => c.isAvailable());
        if (available) {
            dbg('http.conn', () => `pool hit (async): ${key} (pool size=${pool.length})`);
            available.markActive(); return available;
        }

        if (pool.length >= (fullCfg.maxSockets || 10)) {
            dbg('http.conn', () => `pool full: ${key} — waiting for free connection`);
            return this.waitForConnection(key, fullCfg);
        }

        dbg('http.conn', () => `pool miss (async): ${key} — creating new connection`);
        const conn = new Connection(fullCfg);
        conn.onClose = () => this.removeConnection(fullCfg, conn);
        pool.push(conn);
        this.pools.set(key, pool);
        await conn.connectAsync();
        conn.markActive();
        return conn;
    }

    release(cfg: ConnectionConfig, conn: Connection): void {
        if (conn.isClosed()) { this.removeConnection(cfg, conn); return; }
        dbg('http.conn', () => `release: ${this.getKey(cfg, conn.isSync)} (requests=${conn.requests})`);
        conn.markIdle();
        this.notifyWaiters(this.getKey(cfg, conn.isSync));
    }

    private closeIdleConnections(key: string): void {
        const pool = this.pools.get(key) || [];
        for (const conn of pool) {
            if (conn.state === ConnectionState.IDLE) conn.close();
        }
    }

    private notifyWaiters(key: string): void {
        const queue = this.waiters.get(key);
        if (!queue || queue.length === 0) return;
        const pool = this.pools.get(key);
        if (!pool) return;
        const available = pool.find(c => c.isAvailable());
        if (!available) return;
        const waiter = queue.shift()!;
        timers.clearTimeout(waiter.timeoutId);
        if (queue.length === 0) this.waiters.delete(key);
        available.markActive();
        waiter.resolve(available);
    }

    closeAll(): void {
        for (const pool of this.pools.values()) for (const c of pool) c.close();
        this.pools.clear();
        for (const queue of this.waiters.values()) {
            for (const w of queue) { timers.clearTimeout(w.timeoutId); w.reject(new Error("Connection pool closed")); }
        }
        this.waiters.clear();
    }

    getStats(): Record<string, { total: number; idle: number; active: number }> {
        const stats: Record<string, any> = {};
        for (const [key, pool] of this.pools.entries()) {
            stats[key] = {
                total: pool.length,
                idle: pool.filter(c => c.state === ConnectionState.IDLE).length,
                active: pool.filter(c => c.state === ConnectionState.ACTIVE).length
            };
        }
        return stats;
    }

    private async waitForConnection(key: string, cfg: ConnectionConfig): Promise<Connection> {
        return new Promise((resolve, reject) => {
            const timeoutId = timers.setTimeout(() => {
                const queue = this.waiters.get(key);
                if (queue) {
                    const idx = queue.findIndex(w => w.reject === reject);
                    if (idx !== -1) queue.splice(idx, 1);
                    if (queue.length === 0) this.waiters.delete(key);
                }
                reject(new Error("Connection pool timeout"));
            }, cfg.timeout || 30000);

            let queue = this.waiters.get(key);
            if (!queue) { queue = []; this.waiters.set(key, queue); }
            queue.push({ resolve, reject, timeoutId });
        });
    }

    private cleanupPool(key: string): void {
        const pool = this.pools.get(key);
        if (!pool) return;
        const alive = pool.filter(c => !c.isClosed());
        if (alive.length === 0) this.pools.delete(key);
        else if (alive.length < pool.length) this.pools.set(key, alive);
    }

    private removeConnection(cfg: ConnectionConfig, conn: Connection): void {
        const key = this.getKey(cfg, conn.isSync);
        const pool = this.pools.get(key);
        if (!pool) return;
        const i = pool.indexOf(conn);
        if (i !== -1) pool.splice(i, 1);
        if (pool.length === 0) this.pools.delete(key);
    }
}

export const connectionManager = new ConnectionManager();
