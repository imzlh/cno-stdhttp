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
        const value = Number(part);
        return Number.isInteger(value) && value >= 0 && value <= 255;
    });
}

function isIPv6(hostname: string): boolean {
    if (!hostname.includes(':')) return false;
    const parts = hostname.split(':');
    if (parts.length < 3 || parts.length > 8) return false;
    return parts.every((part) => part === '' || /^[0-9a-fA-F]{1,4}$/.test(part));
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

class DnsCache {
    private cache = new Map<string, CacheEntry>();
    private readonly maxSize: number;

    constructor(maxSize = 256) {
        this.maxSize = maxSize;
    }

    async resolve(hostname: string, options?: { family?: number }): Promise<DnsAddress[]> {
        const literal = literalAddress(hostname);
        if (literal) return literal;

        const key = `${hostname}:${options?.family ?? 0}`;
        const cached = this.cache.get(key);
        if (cached && Date.now() < cached.expiresAt) return cached.addresses;
        const addrs = await dns.resolve(hostname, {
            family: options?.family == 4 ? os.AF_INET : options?.family == 6 ? os.AF_INET6 : os.AF_UNSPEC
        });
        if (!addrs?.length) return addrs;
        const ttl = this.inferTtl(addrs);
        this.evictIfFull(key);
        this.cache.set(key, { addresses: addrs, expiresAt: Date.now() + ttl });
        return addrs;
    }

    resolveSync(hostname: string, family = 0): DnsAddress[] {
        const literal = literalAddress(hostname);
        if (literal) return literal;

        const key = `${hostname}:${family}`;
        const cached = this.cache.get(key);
        if (cached && Date.now() < cached.expiresAt) return cached.addresses;
        // Use sync DNS resolution if available, otherwise return empty
        const addrs = dns.resolveSync?.(hostname, { family }) ?? [];
        if (!addrs?.length) return addrs;
        const ttl = this.inferTtl(addrs);
        this.evictIfFull(key);
        this.cache.set(key, { addresses: addrs, expiresAt: Date.now() + ttl });
        return addrs;
    }

    invalidate(hostname: string): void {
        for (const key of this.cache.keys()) {
            if (key.startsWith(hostname + ":")) this.cache.delete(key);
        }
    }

    clear(): void { this.cache.clear(); }

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
        const ttls = addrs.map(a => a.ttl).filter((t): t is number => typeof t === "number" && t > 0);
        return ttls.length > 0 ? Math.min(...ttls) * 1000 : DEFAULT_TTL_MS;
    }

    /** Evict the oldest entry if at capacity (skips `skipKey` to avoid re-inserting it). */
    private evictIfFull(skipKey: string): void {
        if (this.cache.size < this.maxSize) return;
        for (const key of this.cache.keys()) {
            if (key !== skipKey) { this.cache.delete(key); return; }
        }
    }
}

export const dnsCache = new DnsCache();
export const clearDnsCache = () => dnsCache.clear();
export type { DnsAddress as DnsAddressType };
