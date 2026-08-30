import { SharedStore, isPinnedStoreKey } from '../types/store';

export type { SharedStore };
export { RedisSharedStore } from './RedisSharedStore';
export type { RedisStoreClient, RedisSharedStoreOptions } from './RedisSharedStore';
export { PINNED_STORE_PREFIXES, isPinnedStoreKey } from '../types/store';
export type { PinnedStorePrefix } from '../types/store';

export interface MemoryStoreOptions {
    /**
     * Cap on evictable keys (plus any unpinned leftovers). Pinned prefixes
     * ({@link PINNED_STORE_PREFIXES}) are never LRU-evicted and may push
     * {@link size} above this number.
     */
    maxEntries?: number;
    defaultTtlMs?: number;
}

interface MemoryEntry {
    value: unknown;
    expiresAt: number;
}

export class MemoryStore implements SharedStore {
    private data = new Map<string, MemoryEntry>();
    private maxEntries: number;
    private defaultTtlMs: number;

    constructor(opts: MemoryStoreOptions = {}) {
        this.maxEntries = opts.maxEntries ?? 10_000;
        this.defaultTtlMs = opts.defaultTtlMs ?? 60_000;
    }

    /**
     * In-process read. SharedStore {@link get} wraps this in a resolved Promise.
     * CacheManager uses this when it owns the MemoryStore so LRU stays sync.
     */
    getImmediate<T = unknown>(key: string): T | undefined {
        const entry = this.data.get(key);
        if (!entry) return undefined;
        if (Date.now() > entry.expiresAt) {
            this.data.delete(key);
            return undefined;
        }
        this.data.delete(key);
        this.data.set(key, entry);
        return entry.value as T;
    }

    /**
     * In-process write. SharedStore {@link set} wraps this in a resolved Promise.
     * Evicts the oldest **unpinned** key when over {@link maxEntries}.
     * Pinned prefixes are never chosen as the victim.
     */
    setImmediate<T = unknown>(key: string, value: T, ttlMs?: number): void {
        if (this.data.has(key)) this.data.delete(key);
        if (this.data.size >= this.maxEntries) {
            this.evictOldestUnpinned();
        }
        const ttl = ttlMs === undefined ? this.defaultTtlMs : ttlMs;
        this.data.set(key, {
            value,
            expiresAt: ttl > 0 ? Date.now() + ttl : Number.POSITIVE_INFINITY
        });
    }

    async get<T = unknown>(key: string): Promise<T | undefined> {
        return this.getImmediate<T>(key);
    }

    async set<T = unknown>(key: string, value: T, ttlMs?: number): Promise<void> {
        this.setImmediate(key, value, ttlMs);
    }

    /**
     * Atomically increment. First write uses ttlMs; later increments keep the original expiry
     * so rate-limit windows do not slide on every hit.
     */
    async incr(key: string, ttlMs?: number): Promise<number> {
        const entry = this.data.get(key);
        const now = Date.now();
        if (!entry || now > entry.expiresAt) {
            this.setImmediate(key, 1, ttlMs);
            return 1;
        }
        const next = (typeof entry.value === 'number' ? entry.value : 0) + 1;
        entry.value = next;
        this.data.delete(key);
        this.data.set(key, entry);
        return next;
    }

    /**
     * Atomically decrement, floored at 0. Same event-loop semantics as {@link incr}:
     * no await between read and write, so concurrent callers both apply.
     */
    async decr(key: string): Promise<number> {
        const entry = this.data.get(key);
        const now = Date.now();
        if (!entry || now > entry.expiresAt) {
            if (entry) this.data.delete(key);
            this.setImmediate(key, 0, 0);
            return 0;
        }
        const current = typeof entry.value === 'number' ? entry.value : Number(entry.value);
        const next = Number.isFinite(current) ? Math.max(0, current - 1) : 0;
        entry.value = next;
        this.data.delete(key);
        this.data.set(key, entry);
        return next;
    }

    /**
     * In-process SET NX. No await between the miss check and the write, so
     * concurrent callers on the same event loop cannot both claim the key.
     */
    async setNX<T = unknown>(key: string, value: T, ttlMs?: number): Promise<boolean> {
        if (this.getImmediate(key) !== undefined) return false;
        this.setImmediate(key, value, ttlMs);
        return true;
    }

    /**
     * In-process compare-and-swap. No await between the compare and the write,
     * so only one concurrent caller can win a given expected → next transition.
     */
    async cas<T = unknown>(key: string, expected: T, next: T, ttlMs?: number): Promise<boolean> {
        const current = this.peekValue(key);
        if (current === undefined || !valuesEqual(current, expected)) return false;
        this.setImmediate(key, next, ttlMs);
        return true;
    }

    /**
     * In-process set add. First write uses ttlMs; later members keep the
     * original expiry so campaign windows do not slide.
     */
    async sadd(key: string, member: string, ttlMs?: number): Promise<number> {
        const now = Date.now();
        const entry = this.data.get(key);
        if (!entry || now > entry.expiresAt) {
            this.setImmediate(key, new Set([member]), ttlMs);
            return 1;
        }
        let set: Set<string>;
        if (entry.value instanceof Set) {
            set = entry.value as Set<string>;
        } else if (Array.isArray(entry.value)) {
            set = new Set((entry.value as unknown[]).map(String));
            entry.value = set;
        } else {
            set = new Set();
            entry.value = set;
        }
        const added = set.has(member) ? 0 : 1;
        set.add(member);
        this.data.delete(key);
        this.data.set(key, entry);
        return added;
    }

    async smembers(key: string): Promise<string[]> {
        const value = this.getImmediate<unknown>(key);
        if (value instanceof Set) return Array.from(value as Set<string>, String);
        if (Array.isArray(value)) return value.map(String);
        return [];
    }

    async delete(key: string): Promise<void> {
        this.data.delete(key);
    }

    clear(): void {
        this.data.clear();
    }

    get size(): number {
        return this.data.size;
    }

    /** Read without LRU promotion (used by CAS so compare does not reshuffle). */
    private peekValue(key: string): unknown {
        const entry = this.data.get(key);
        if (!entry) return undefined;
        if (Date.now() > entry.expiresAt) {
            this.data.delete(key);
            return undefined;
        }
        return entry.value;
    }

    /**
     * Drop the oldest unpinned key. If every remaining key is pinned, do
     * nothing — pinned writes are allowed to grow past {@link maxEntries}.
     */
    private evictOldestUnpinned(): void {
        for (const existing of this.data.keys()) {
            if (!isPinnedStoreKey(existing)) {
                this.data.delete(existing);
                return;
            }
        }
    }
}

function valuesEqual(a: unknown, b: unknown): boolean {
    if (Object.is(a, b)) return true;
    if (typeof a === 'object' && a !== null && typeof b === 'object' && b !== null) {
        try {
            return JSON.stringify(a) === JSON.stringify(b);
        } catch {
            return false;
        }
    }
    return false;
}
