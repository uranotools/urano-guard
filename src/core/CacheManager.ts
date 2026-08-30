import { SecurityDecision } from '../types/context';

interface CacheEntry {
    decision: SecurityDecision;
    expiresAt: number;
}

export class CacheManager {
    private cache = new Map<string, CacheEntry>();
    private maxEntries: number;
    private defaultTtl: number;

    constructor(defaultTtlMs = 60000, maxEntries = 5000) {
        this.defaultTtl = defaultTtlMs;
        this.maxEntries = maxEntries;
    }

    get(key: string): SecurityDecision | null {
        const entry = this.cache.get(key);
        if (!entry) return null;
        if (Date.now() > entry.expiresAt) {
            this.cache.delete(key);
            return null;
        }
        this.cache.delete(key);
        this.cache.set(key, entry);
        return { ...entry.decision, source: 'CACHE' };
    }

    set(key: string, decision: SecurityDecision, ttlMs?: number): void {
        if (this.cache.has(key)) this.cache.delete(key);
        if (this.cache.size >= this.maxEntries) {
            const oldestKey = this.cache.keys().next().value;
            if (oldestKey) this.cache.delete(oldestKey);
        }
        this.cache.set(key, {
            decision,
            expiresAt: Date.now() + (ttlMs || this.defaultTtl)
        });
    }

    clear(): void {
        this.cache.clear();
    }

    get size(): number {
        return this.cache.size;
    }
}
