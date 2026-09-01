/**
 * DNS resolution caching with TTL-based expiry.
 *
 * Merged from:
 *   cno/src/module/http/dns-cache.ts  (primary)
 *   cts/src/http/connection.ts       (sync DNS resolution)
 */

const dns = import.meta.use("dns");
const os = import.meta.use("os");

function isIPv4(hostname: string): boolean {
    if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) return false;
    return hostname.split('.').every((part) => {
        if (part.length > 1 && part.startsWith('0')) return false;
        const value = Number(part);
        return Number.isInteger(value) && value >= 0 && value <= 255;
    });
}

function isIPv6(hostname: string): boolean {
    if (!hostname.includes(':')) return false;

    // Keep the literal check independent of DOM/Node URL implementations.
    const compression = hostname.indexOf('::');
    if (compression !== -1 && hostname.indexOf('::', compression + 2) !== -1) return false;
    if (compression !== -1 && (hostname[compression - 1] === ':' || hostname[compression + 2] === ':')) return false;
    const leftText = compression === -1 ? hostname : hostname.slice(0, compression);
    const rightText = compression === -1 ? '' : hostname.slice(compression + 2);
    const left = leftText ? leftText.split(':') : [];
    const right = rightText ? rightText.split(':') : [];
    if (left.some(part => part === '') || right.some(part => part === '')) return false;

    const parseSide = (parts: string[], allowIpv4: boolean): number => {
        let count = 0;
        for (let index = 0; index < parts.length; index++) {
            const part = parts[index];
            if (part.includes('.')) {
                if (!allowIpv4 || index !== parts.length - 1 || !isIPv4(part)) return -1;
                count += 2;
            } else {
                if (!/^[0-9a-fA-F]{1,4}$/.test(part)) return -1;
                count++;
            }
        }
        return count;
    };

    const supplied = parseSide(left, compression === -1) + parseSide(right, true);
    if (supplied < 0) return false;
    return compression === -1 ? supplied === 8 : supplied < 8;
}

function literalAddress(hostname: string): DnsAddress[] | null {
    if (isIPv4(hostname)) return [{ ip: hostname, family: 4 }];
    if (isIPv6(hostname)) return [{ ip: hostname, family: 6 }];
    return null;
}

export interface DnsAddress {
    ip: string;
    family: number;
    ttl?: number;
}

interface CacheEntry {
    addresses: DnsAddress[];
    expiresAt: number;
}

const DEFAULT_TTL_MS = 300_000;
/**
 * How long an empty answer is remembered. Without this, a hostname that resolves to
 * nothing is re-queried on every single connection attempt, so a client loop (or a
 * caller retrying a dead host) turns into unbounded outbound DNS traffic. Short
 * enough that a host coming online is picked up quickly.
 */
const NEGATIVE_TTL_MS = 5_000;

class DnsCache {
    private cache = new Map<string, CacheEntry>();
    private inflight = new Map<string, Promise<DnsAddress[]>>();
    private readonly maxSize: number;
    /**
     * Bumped by invalidate()/clear(). A lookup that started before the bump must not
     * write its (now known-stale) answer into the cache afterwards.
     */
    private generation = 0;

    constructor(maxSize = 256) {
        this.maxSize = maxSize;
    }

    async resolve(hostname: string, options?: { family?: number }): Promise<DnsAddress[]> {
        const literal = literalAddress(hostname);
        if (literal) return literal;

        const key = `${hostname}:${options?.family ?? 0}`;
        const cached = this.cache.get(key);
        if (cached && Date.now() < cached.expiresAt) return cached.addresses;
        // Concurrent misses on the same key share one query instead of each issuing its own.
        const running = this.inflight.get(key);
        if (running) return running;
        const query: Promise<DnsAddress[]> = this.lookup(hostname, key, options?.family ?? 0)
            .finally(() => {
                // Only retract our own entry: invalidate() may have dropped it and a newer
                // lookup may already hold the key, and deleting that would strip the
                // sharing from every caller now waiting on it.
                if (this.inflight.get(key) === query) this.inflight.delete(key);
            });
        this.inflight.set(key, query);
        return query;
    }

    private async lookup(hostname: string, key: string, family: number): Promise<DnsAddress[]> {
        const startedAt = this.generation;
        const addrs = await dns.resolve(hostname, {
            family: family == 4 ? os.AF_INET : family == 6 ? os.AF_INET6 : os.AF_UNSPEC
        });
        if (!addrs?.length) {
            // Negative result: cache briefly so a retry loop cannot amplify into a
            // DNS flood, but nowhere near as long as a positive answer.
            this.store(key, [], NEGATIVE_TTL_MS, startedAt);
            return addrs ?? [];
        }
        this.store(key, addrs, this.inferTtl(addrs), startedAt);
        return addrs;
    }

    /**
     * Insert unless the TTL is zero (authoritative "do not cache") or the entry was
     * invalidated while the query was in flight.
     */
    private store(key: string, addresses: DnsAddress[], ttl: number, generation = this.generation): void {
        if (ttl <= 0) return;
        if (generation !== this.generation) return;
        this.evictIfFull(key);
        this.cache.set(key, { addresses, expiresAt: Date.now() + ttl });
    }

    resolveSync(hostname: string, family = 0): DnsAddress[] {
        const literal = literalAddress(hostname);
        if (literal) return literal;

        const key = `${hostname}:${family}`;
        const cached = this.cache.get(key);
        if (cached && Date.now() < cached.expiresAt) return cached.addresses;
        // Use sync DNS resolution if available, otherwise return empty
        const addrs = dns.resolveSync?.(hostname, { family }) ?? [];
        if (!addrs?.length) {
            this.store(key, [], NEGATIVE_TTL_MS);
            return addrs ?? [];
        }
        this.store(key, addrs, this.inferTtl(addrs));
        return addrs;
    }

    invalidate(hostname: string): void {
        for (const key of this.cache.keys()) {
            if (key.startsWith(hostname + ":")) this.cache.delete(key);
        }
        // Drop the shared in-flight query too, and bump the generation: otherwise a
        // lookup already awaiting a reply would write its pre-invalidation answer back
        // into the cache, silently undoing this call.
        for (const key of this.inflight.keys()) {
            if (key.startsWith(hostname + ":")) this.inflight.delete(key);
        }
        this.generation++;
    }

    clear(): void {
        this.cache.clear();
        this.inflight.clear();
        this.generation++;
    }

    getStats(): { size: number; entries: Array<{ hostname: string; ttlRemaining: number }> } {
        const now = Date.now();
        return {
            size: this.cache.size,
            entries: [...this.cache.entries()].map(([key, entry]) => ({
                hostname: key.split(":")[0] ?? "",
                ttlRemaining: Math.max(0, entry.expiresAt - now)
            }))
        };
    }

    private inferTtl(addrs: DnsAddress[]): number {
        // A resolver-supplied TTL of 0 means "do not cache this"; the old `t > 0` filter
        // discarded exactly that answer and then fell back to DEFAULT_TTL_MS, pinning a
        // deliberately uncacheable record for five minutes. Keep zeros so store() can
        // honour them, and only default when no TTL was reported at all.
        const ttls = addrs.map(a => a.ttl).filter((t): t is number => typeof t === "number" && t >= 0);
        return ttls.length > 0 ? Math.min(...ttls) * 1000 : DEFAULT_TTL_MS;
    }

    /** Evict at capacity, expired entries first (skips `skipKey` to avoid re-inserting it). */
    private evictIfFull(skipKey: string): void {
        if (this.cache.size < this.maxSize) return;
        const now = Date.now();
        for (const [key, entry] of this.cache) {
            if (key !== skipKey && now >= entry.expiresAt) this.cache.delete(key);
        }
        if (this.cache.size < this.maxSize) return;
        for (const key of this.cache.keys()) {
            if (key !== skipKey) { this.cache.delete(key); return; }
        }
    }
}

export const dnsCache = new DnsCache();
export const clearDnsCache = () => dnsCache.clear();
export type { DnsAddress as DnsAddressType };
