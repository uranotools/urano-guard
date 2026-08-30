/**
 * Multi-process store: inject your Redis client (this package has no redis dep).
 *
 * ioredis already matches RedisSharedStore's duck-typed client, including eval.
 * node-redis v4 needs the wrap in ENTERPRISE.md (camelCase + eval keys/arguments).
 *
 * Custom SharedStore implementations must include setNX, sadd, smembers, decr, cas.
 * MemoryStore LRU never evicts PINNED_STORE_PREFIXES (ug:cb:, ug:nonce:, ug:rl:,
 * ug:block:, ug:allow:, ug:fp:). ug:cache: may still evict.
 */
import { createUranoGuard, RedisSharedStore, PINNED_STORE_PREFIXES } from '../src';

// import Redis from 'ioredis';
// const client = new Redis(process.env.REDIS_URL);

const client = {
    get: async (_key: string) => null as string | null,
    set: async () => 'OK' as const,
    del: async () => 1,
    incr: async () => 1,
    sadd: async () => 1,
    smembers: async () => [] as string[],
    pexpire: async () => 1,
    pttl: async () => -1,
    eval: async () => 0
};

const store = new RedisSharedStore({ client });

const guard = createUranoGuard({
    store,
    blockedIdentifiers: ['1.2.3.4'],
    circuitBreaker: { enabled: true }
});

async function main(): Promise<void> {
    await guard.ready();
    console.log('seeded; pinned prefixes', PINNED_STORE_PREFIXES.join(', '));
}

void main();
