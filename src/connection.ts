/**
 * Protocol-agnostic connection pooling.
 *
 * Manages TcpSocket connections with keep-alive, DNS resolution,
 * TLS setup, and cross-platform CA certificate discovery.
 *
 * This module does NOT know about HTTP — it just manages raw TCP/TLS connections.
 * Protocol negotiation (H1 vs H2 vs H3) happens at the protocol layer.
 */

const os = import.meta.use("os");
const timers = import.meta.use("timers");
const asfs = import.meta.use("asyncfs");
const engine = import.meta.use("engine");
const ssl = import.meta.use("ssl");
const dns = import.meta.use("dns");
const windows = import.meta.use("win32");

import { TcpSocket } from "./socket";
import { dnsCache } from "./dns-cache";

function assert(condition: unknown, message?: string): asserts condition {
    if (!condition) throw new Error(message ?? "Assertion failed");
}

type Uint8Array = globalThis.Uint8Array<ArrayBuffer>;

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
    connect(): Promise<void>;
    write(data: Uint8Array): Promise<void>;
    read(size?: number): Promise<Uint8Array | null>;
    onReadable(callback: (data: Uint8Array | null) => void, errHandler?: (err: Error) => void): void;
    stopReading(): void;
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

export class Connection extends TcpSocket implements ConnectionLike {
    public state:    ConnectionState = ConnectionState.CONNECTING;
    public lastUsed: number          = Date.now();
    public requests: number          = 0;
    public onClose:  (() => void) | null = null;

    private idleTimer: number | null = null;
    private config: ConnectionConfig;

    constructor(cfg: ConnectionConfig) {
        super();
        this.config = cfg;
    }

    async connect(): Promise<void> {
        try {
            const isSecure = this.config.protocol === "https:";

            if (this.config.client) {
                this.socket = await this.config.client.connect(
                    this.config.hostname, this.config.port, isSecure
                );
            } else {
                const addrs = await dnsCache.resolve(this.config.hostname, { family: os.AF_UNSPEC });
                if (!addrs?.length) throw new Error(`DNS resolution failed for ${this.config.hostname}`);
                const addr = addrs.find((a: any) => a.family === 4) || addrs[0];
                assert(addr, `No IP address found for ${this.config.hostname}`);
                await this.socket.connect({ ip: addr.ip, port: this.config.port });
            }

            if (isSecure) {
                const clientCtx = this.config.client?.getSSLContext();
                if (clientCtx) {
                    await this.clientHandshake(clientCtx, this.config.hostname);
                } else {
                    const caPath = await findSystemCaPath();
                    if (!caPath) throw new Error("No system CA bundle found - cannot verify TLS certificates.");
                    const ctx = new ssl.Context({ mode: "client", verify: true, ca: caPath });
                    await this.clientHandshake(ctx, this.config.hostname);
                }
            }

            this.socket.onclose = () => {
                if (this.state === ConnectionState.CLOSED) return;
                this.stopIdleTimer();
                this.state = ConnectionState.CLOSED;
                this.onClose?.();
            };
        } catch (err) {
            this.state = ConnectionState.CLOSED;
            throw err;
        }
    }

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
        super.close();
        this.state = ConnectionState.CLOSED;
        this.onClose?.();
    }

    isAvailable(): boolean { return this.state === ConnectionState.IDLE; }
    isClosed():    boolean { return this.state === ConnectionState.CLOSED; }

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

    private getKey(cfg: ConnectionConfig): string {
        const clientId = cfg.client ? `[client-${cfg.client.getSSLContext() ? 'custom' : 'default'}]` : '';
        const proxyId  = cfg.client?.getProxyUrl() ? `[proxy]` : '';
        return `${cfg.protocol}//${cfg.hostname}:${cfg.port}${clientId}${proxyId}`;
    }

    async acquire(cfg: ConnectionConfig): Promise<Connection> {
        const fullCfg: ConnectionConfig = { ...this.defaultConfig, ...cfg };
        const key = this.getKey(fullCfg);
        this.cleanupPool(key);

        let pool = this.pools.get(key) || [];
        const available = pool.find(c => c.isAvailable());
        if (available) { available.markActive(); return available; }

        if (pool.length >= (fullCfg.maxSockets || 10)) {
            return this.waitForConnection(key, fullCfg);
        }

        const conn = new Connection(fullCfg);
        conn.onClose = () => this.removeConnection(fullCfg, conn);
        pool.push(conn);
        this.pools.set(key, pool);
        await conn.connect();
        conn.markActive();
        return conn;
    }

    release(cfg: ConnectionConfig, conn: Connection): void {
        if (conn.isClosed()) { this.removeConnection(cfg, conn); return; }
        conn.markIdle();
        this.notifyWaiters(this.getKey(cfg));
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
        const key = this.getKey(cfg);
        const pool = this.pools.get(key);
        if (!pool) return;
        const i = pool.indexOf(conn);
        if (i !== -1) pool.splice(i, 1);
        if (pool.length === 0) this.pools.delete(key);
    }
}

export const connectionManager = new ConnectionManager();
