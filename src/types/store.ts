/**
 * Shared key/value store for cache, rate-limit, replay nonces, and blocks.
 * Implement this (or use {@link RedisSharedStore}) so multiple Node processes
 * share state. This package does not depend on Redis.
 *
 * All methods return Promises so real ioredis / node-redis clients can be
 * used directly. {@link MemoryStore} resolves immediately (no I/O).
 *
 * Key prefixes used by Guard:
 * - `ug:cache:` — decision cache (**MemoryStore LRU may evict**)
 * - `ug:rl:count:` — semantic rate-limit counters (`incr`)
 * - `ug:rl:ips:` — semantic rate-limit unique IPs (`sadd` / `smembers`)
 * - `ug:nonce:` — ReplayGuard nonces (`setNX`)
 * - `ug:block:` — ThreatRegistry timed / permanent blocks
 * - `ug:allow:` — ThreatRegistry whitelist
 * - `ug:fp:` — RequestFingerprinter occurrence counts
 * - `ug:cb:` — CircuitBreaker shared state + HALF_OPEN probe lock
 *
 * {@link PINNED_STORE_PREFIXES} are never evicted by MemoryStore LRU.
 * `ug:cache:` is not pinned. Redis eviction is Redis's `maxmemory-policy`
 * (this adapter cannot pin keys there).
 *
 * `ttlMs` omitted uses the store default. `ttlMs <= 0` means no expiry
 * (permanent keys — used for non-TTL blacklist / allowlist entries).
 *
 * Custom writers must implement every method on this interface, including
 * {@link decr} and {@link cas}.
 */
export interface SharedStore {
    get<T = unknown>(key: string): Promise<T | undefined>;
    set<T = unknown>(key: string, value: T, ttlMs?: number): Promise<void>;
    incr(key: string, ttlMs?: number): Promise<number>;
    /**
     * Atomically decrement a numeric key, floored at 0.
     * Missing or non-numeric keys become 0 (no negative counters).
     * Does not change TTL on an existing key; a newly created 0 has no expiry.
     */
    decr(key: string): Promise<number>;
    delete(key: string): Promise<void>;
    /**
     * Atomically set only if the key is missing (or expired).
     * @returns true if this caller wrote the key
     */
    setNX<T = unknown>(key: string, value: T, ttlMs?: number): Promise<boolean>;
    /**
     * Compare-and-swap: write `next` only if the current value equals `expected`.
     * Missing keys do not match (even if `expected` is undefined).
     * Values are compared as stored (MemoryStore: `===` / JSON for objects;
     * Redis: JSON-encoded strings, same as {@link set}).
     * @returns true if this caller wrote `next`
     */
    cas<T = unknown>(key: string, expected: T, next: T, ttlMs?: number): Promise<boolean>;
    /**
     * Add `member` to a set. First write applies `ttlMs`; later adds keep
     * the original expiry (the window does not slide).
     * @returns number of members newly added (0 or 1)
     */
    sadd(key: string, member: string, ttlMs?: number): Promise<number>;
    smembers(key: string): Promise<string[]>;
}

/**
 * MemoryStore LRU never evicts keys with these prefixes. Cache keys
 * (`ug:cache:`) are not in this list and remain evictable.
 *
 * Pinning is MemoryStore-only. Redis uses its own maxmemory policy.
 */
export const PINNED_STORE_PREFIXES = [
    'ug:cb:',
    'ug:nonce:',
    'ug:rl:',
    'ug:block:',
    'ug:allow:',
    'ug:fp:',
    'ug:agent:'
] as const;

export type PinnedStorePrefix = (typeof PINNED_STORE_PREFIXES)[number];

/** True when MemoryStore must keep this key through LRU pressure. */
export function isPinnedStoreKey(key: string): boolean {
    for (const prefix of PINNED_STORE_PREFIXES) {
        if (key.startsWith(prefix)) return true;
    }
    return false;
}
