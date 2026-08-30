import { describe, expect, it } from 'vitest';
import { MemoryStore, RedisSharedStore } from '../src/core/SharedStore';
import { REDIS_CAS_LUA, REDIS_DECR_LUA } from '../src/core/RedisSharedStore';
import { ReplayGuard } from '../src/core/ReplayGuard';
import { ThreatRegistry } from '../src/core/ThreatRegistry';
import { CacheManager } from '../src/core/CacheManager';
import { SemanticRateLimiter } from '../src/core/SemanticRateLimiter';
import { RequestFingerprinter } from '../src/core/RequestFingerprinter';
import { SecurityDecision } from '../src/types/context';
import { isPinnedStoreKey } from '../src/types/store';

/** In-memory Redis stand-in: get / set PX|NX / del / incr / sadd / smembers / pexpire / pttl / eval. */
class FakeRedisClient {
    private data = new Map<string, { value: string; expiresAt: number }>();
    private sets = new Map<string, { members: Set<string>; expiresAt: number }>();

    async get(key: string): Promise<string | null> {
        const entry = this.data.get(key);
        if (!entry) return null;
        if (Date.now() > entry.expiresAt) {
            this.data.delete(key);
            return null;
        }
        return entry.value;
    }

    async set(
        key: string,
        value: string,
        mode?: 'PX' | 'NX',
        ms?: number,
        flag?: 'NX'
    ): Promise<'OK' | null> {
        const nx = mode === 'NX' || flag === 'NX';
        const existing = this.data.get(key);
        const alive = !!(existing && Date.now() <= existing.expiresAt);
        if (nx && alive) return null;
        const ttl = mode === 'PX' && ms && ms > 0 ? ms : Number.POSITIVE_INFINITY;
        this.data.set(key, {
            value,
            expiresAt: Number.isFinite(ttl) ? Date.now() + ttl : Number.POSITIVE_INFINITY
        });
        return 'OK';
    }

    async del(key: string): Promise<number> {
        const a = this.data.delete(key) ? 1 : 0;
        const b = this.sets.delete(key) ? 1 : 0;
        return a || b;
    }

    async incr(key: string): Promise<number> {
        const raw = await this.get(key);
        const next = (raw == null ? 0 : Number(JSON.parse(raw))) + 1;
        const existing = this.data.get(key);
        const expiresAt = existing && Date.now() <= existing.expiresAt
            ? existing.expiresAt
            : Number.POSITIVE_INFINITY;
        this.data.set(key, { value: JSON.stringify(next), expiresAt });
        return next;
    }

    private liveSet(key: string): { members: Set<string>; expiresAt: number } | undefined {
        const entry = this.sets.get(key);
        if (!entry) return undefined;
        if (Date.now() > entry.expiresAt) {
            this.sets.delete(key);
            return undefined;
        }
        return entry;
    }

    async sadd(key: string, member: string): Promise<number> {
        let entry = this.liveSet(key);
        if (!entry) {
            entry = { members: new Set(), expiresAt: Number.POSITIVE_INFINITY };
            this.sets.set(key, entry);
        }
        const before = entry.members.size;
        entry.members.add(member);
        return entry.members.size > before ? 1 : 0;
    }

    async smembers(key: string): Promise<string[]> {
        const entry = this.liveSet(key);
        return entry ? [...entry.members] : [];
    }

    async pexpire(key: string, ms: number): Promise<number> {
        const set = this.liveSet(key);
        if (set) {
            set.expiresAt = Date.now() + ms;
            return 1;
        }
        const entry = this.data.get(key);
        if (entry && Date.now() <= entry.expiresAt) {
            entry.expiresAt = Date.now() + ms;
            return 1;
        }
        return 0;
    }

    async pttl(key: string): Promise<number> {
        const set = this.liveSet(key);
        if (set) {
            if (!Number.isFinite(set.expiresAt)) return -1;
            return Math.max(0, set.expiresAt - Date.now());
        }
        const entry = this.data.get(key);
        if (!entry || Date.now() > entry.expiresAt) return -2;
        if (!Number.isFinite(entry.expiresAt)) return -1;
        return Math.max(0, entry.expiresAt - Date.now());
    }

    async eval(script: string, numKeys: number, ...rest: Array<string | number>): Promise<number> {
        const key = String(rest[0]);
        const args = rest.slice(numKeys);
        if (script === REDIS_DECR_LUA) return this.evalDecr(key);
        if (script === REDIS_CAS_LUA) {
            return this.evalCas(key, String(args[0]), String(args[1]), Number(args[2]));
        }
        throw new Error('FakeRedisClient: unknown eval script');
    }

    /** Same-tick as Redis Lua: no await between GET and SET. */
    private liveScalar(key: string): { value: string; expiresAt: number } | undefined {
        const entry = this.data.get(key);
        if (!entry) return undefined;
        if (Date.now() > entry.expiresAt) {
            this.data.delete(key);
            return undefined;
        }
        return entry;
    }

    private evalDecr(key: string): number {
        const entry = this.liveScalar(key);
        if (!entry) {
            this.data.set(key, { value: '0', expiresAt: Number.POSITIVE_INFINITY });
            return 0;
        }
        let v = Number(entry.value);
        if (!Number.isFinite(v)) {
            try {
                v = Number(JSON.parse(entry.value));
            } catch {
                v = NaN;
            }
        }
        if (!Number.isFinite(v) || v <= 0) {
            entry.value = '0';
            return 0;
        }
        const next = v - 1;
        entry.value = String(next);
        return next;
    }

    private evalCas(key: string, expected: string, next: string, ttlMs: number): number {
        const entry = this.liveScalar(key);
        if (!entry || entry.value !== expected) return 0;
        const ttl = ttlMs > 0 ? ttlMs : Number.POSITIVE_INFINITY;
        this.data.set(key, {
            value: next,
            expiresAt: Number.isFinite(ttl) ? Date.now() + ttl : Number.POSITIVE_INFINITY
        });
        return 1;
    }
}

const unusedRedisMethods = {
    sadd: async () => 0,
    smembers: async () => [] as string[],
    pexpire: async () => 1,
    pttl: async () => -1
};

const allowDecision = (): SecurityDecision => ({
    allowed: true,
    action: 'ALLOW',
    riskScore: 0,
    threats: [],
    latencyMs: 0,
    source: 'LOCAL_INSPECTOR'
});

describe('MemoryStore', () => {
    it('get/set/delete/incr honor TTL and permanent keys', async () => {
        const store = new MemoryStore({ defaultTtlMs: 20, maxEntries: 16 });
        await store.set('k', { n: 1 }, 20);
        expect(await store.get<{ n: number }>('k')).toEqual({ n: 1 });
        expect(await store.incr('c', 20)).toBe(1);
        expect(await store.incr('c', 20)).toBe(2);
        await store.set('perm', 'keep', 0);
        await store.delete('k');
        expect(await store.get('k')).toBeUndefined();
        await new Promise(r => setTimeout(r, 30));
        expect(await store.get('c')).toBeUndefined();
        expect(await store.incr('c', 20)).toBe(1);
        expect(await store.get('perm')).toBe('keep');
    });

    it('setNX fails for a second concurrent claim', async () => {
        const store = new MemoryStore();
        const [first, second] = await Promise.all([
            store.setNX('ug:nonce:x', 1, 60_000),
            store.setNX('ug:nonce:x', 2, 60_000)
        ]);
        expect([first, second].filter(Boolean)).toHaveLength(1);
        expect(await store.get('ug:nonce:x')).toBeTypeOf('number');
        expect(await store.setNX('ug:nonce:x', 3, 60_000)).toBe(false);
    });

    it('concurrent sadd keeps both members and does not slide TTL', async () => {
        const store = new MemoryStore({ defaultTtlMs: 60_000 });
        await Promise.all([
            store.sadd('ug:rl:ips:k', '1.1.1.1', 80),
            store.sadd('ug:rl:ips:k', '2.2.2.2', 80)
        ]);
        expect((await store.smembers('ug:rl:ips:k')).sort()).toEqual(['1.1.1.1', '2.2.2.2']);
        await new Promise(r => setTimeout(r, 30));
        await store.sadd('ug:rl:ips:k', '3.3.3.3', 80);
        expect((await store.smembers('ug:rl:ips:k')).sort()).toEqual(['1.1.1.1', '2.2.2.2', '3.3.3.3']);
        await new Promise(r => setTimeout(r, 70));
        expect(await store.smembers('ug:rl:ips:k')).toEqual([]);
    });

    it('does not LRU-evict pinned prefixes when cache keys fill the store', async () => {
        const store = new MemoryStore({ maxEntries: 8, defaultTtlMs: 60_000 });
        await store.set('ug:cb:state', 'OPEN', 0);
        await store.set('ug:nonce:abc', 1, 0);
        await store.set('ug:block:bad', true, 0);
        await store.set('ug:allow:friend', true, 0);
        await store.sadd('ug:rl:ips:k', '1.1.1.1', 0);
        await store.set('ug:rl:count:k', 3, 0);
        await store.set('ug:fp:hash', 2, 0);
        await store.set('ug:agent:mem:u1', { last: 'x' }, 0);

        for (let i = 0; i < 40; i++) {
            await store.set(`ug:cache:${i}`, { i }, 60_000);
        }

        expect(await store.get('ug:cb:state')).toBe('OPEN');
        expect(await store.get('ug:nonce:abc')).toBe(1);
        expect(await store.get('ug:block:bad')).toBe(true);
        expect(await store.get('ug:allow:friend')).toBe(true);
        expect(await store.smembers('ug:rl:ips:k')).toEqual(['1.1.1.1']);
        expect(await store.get('ug:rl:count:k')).toBe(3);
        expect(await store.get('ug:fp:hash')).toBe(2);
        expect(await store.get('ug:agent:mem:u1')).toEqual({ last: 'x' });
        expect(await store.get('ug:cache:0')).toBeUndefined();
        expect(isPinnedStoreKey('ug:cache:9')).toBe(false);
        expect(store.size).toBeGreaterThanOrEqual(7);
    });

    it('applies concurrent decr and allows only one cas winner', async () => {
        const store = new MemoryStore();
        await store.set('ug:cb:failures', 4, 0);
        const [d1, d2] = await Promise.all([
            store.decr('ug:cb:failures'),
            store.decr('ug:cb:failures')
        ]);
        expect([d1, d2].sort()).toEqual([2, 3]);
        expect(await store.get('ug:cb:failures')).toBe(2);
        expect(await store.decr('ug:cb:missing')).toBe(0);

        await store.set('ug:cb:state', 'OPEN', 0);
        const [c1, c2] = await Promise.all([
            store.cas('ug:cb:state', 'OPEN', 'HALF_OPEN', 0),
            store.cas('ug:cb:state', 'OPEN', 'HALF_OPEN', 0)
        ]);
        expect([c1, c2].filter(Boolean)).toHaveLength(1);
        expect(await store.get('ug:cb:state')).toBe('HALF_OPEN');
        expect(await store.cas('ug:cb:state', 'OPEN', 'CLOSED', 0)).toBe(false);
    });
});

describe('RedisSharedStore', () => {
    it('JSON-serializes values through a fake Redis client', async () => {
        const client = new FakeRedisClient();
        const a = new RedisSharedStore({ client });
        const b = new RedisSharedStore({ client });

        await a.set('obj', { ok: true }, 50);
        expect(await b.get<{ ok: boolean }>('obj')).toEqual({ ok: true });
        expect(await client.get('obj')).toBe(JSON.stringify({ ok: true }));

        expect(await a.incr('n', 50)).toBe(1);
        expect(await b.incr('n', 50)).toBe(2);
        await a.delete('obj');
        expect(await b.get('obj')).toBeUndefined();

        await a.set('forever', 'x', 0);
        await new Promise(r => setTimeout(r, 15));
        expect(await b.get('forever')).toBe('x');
    });

    it('expires keys set with PX TTL', async () => {
        const store = new RedisSharedStore({ client: new FakeRedisClient() });
        await store.set('ephemeral', 'v', 15);
        expect(await store.get('ephemeral')).toBe('v');
        await new Promise(r => setTimeout(r, 25));
        expect(await store.get('ephemeral')).toBeUndefined();
    });

    it('accepts a Promise-returning get/incr client', async () => {
        const client = {
            get: async () => JSON.stringify({ n: 1 }),
            set: async () => 'OK',
            del: async () => 1,
            incr: async () => 1,
            ...unusedRedisMethods
        };
        const store = new RedisSharedStore({ client });
        expect(await store.get<{ n: number }>('k')).toEqual({ n: 1 });
        expect(await store.incr('n')).toBe(1);
    });

    it('throws on unexpected get types', async () => {
        const client = {
            get: () => 42,
            set: () => 'OK',
            del: () => 1,
            incr: () => 1,
            ...unusedRedisMethods
        };
        const store = new RedisSharedStore({ client });
        await expect(store.get('k')).rejects.toThrow(/unexpected type/);
    });

    it('setNX is atomic and sadd keeps concurrent members', async () => {
        const store = new RedisSharedStore({ client: new FakeRedisClient() });
        expect(await store.setNX('lock', 1, 50)).toBe(true);
        expect(await store.setNX('lock', 2, 50)).toBe(false);
        expect(await store.get('lock')).toBe(1);

        const [a, b] = await Promise.all([
            store.sadd('ips', '1.1.1.1', 50),
            store.sadd('ips', '2.2.2.2', 50)
        ]);
        expect(a + b).toBe(2);
        expect((await store.smembers('ips')).sort()).toEqual(['1.1.1.1', '2.2.2.2']);
    });

    it('decr floors at 0 and cas is single-winner', async () => {
        const store = new RedisSharedStore({ client: new FakeRedisClient() });
        await store.set('n', 4, 0);
        const [d1, d2] = await Promise.all([store.decr('n'), store.decr('n')]);
        expect([d1, d2].sort()).toEqual([2, 3]);
        expect(await store.get('n')).toBe(2);
        expect(await store.decr('n')).toBe(1);
        expect(await store.decr('n')).toBe(0);
        expect(await store.decr('n')).toBe(0);

        await store.set('st', 'OPEN', 0);
        const [c1, c2] = await Promise.all([
            store.cas('st', 'OPEN', 'HALF_OPEN', 0),
            store.cas('st', 'OPEN', 'HALF_OPEN', 0)
        ]);
        expect([c1, c2].filter(Boolean)).toHaveLength(1);
        expect(await store.get('st')).toBe('HALF_OPEN');
    });

    it('throws when eval is missing for decr/cas', async () => {
        const store = new RedisSharedStore({
            client: {
                get: async () => null,
                set: async () => 'OK',
                del: async () => 1,
                incr: async () => 1,
                ...unusedRedisMethods
            }
        });
        await expect(store.decr('k')).rejects.toThrow(/client\.eval/);
        await expect(store.cas('k', 'OPEN', 'HALF_OPEN')).rejects.toThrow(/client\.eval/);
    });
});

describe('ReplayGuard shared store', () => {
    it('detects replay across two instances sharing MemoryStore', async () => {
        const store = new MemoryStore({ defaultTtlMs: 60_000 });
        const first = new ReplayGuard({ timestampWindowMs: 60_000, store });
        const second = new ReplayGuard({ timestampWindowMs: 60_000, store });
        const headers = {
            'x-urano-timestamp': String(Date.now()),
            'x-urano-nonce': 'shared-nonce-1'
        };
        expect((await first.check(headers)).valid).toBe(true);
        expect((await second.check(headers)).valid).toBe(false);
        expect((await second.check(headers)).reason).toBe('REPLAY_DETECTED');
        expect(await store.get('ug:nonce:shared-nonce-1')).toBeTypeOf('number');
    });

    it('rejects the loser when two checks race the same nonce', async () => {
        const store = new MemoryStore({ defaultTtlMs: 60_000 });
        const first = new ReplayGuard({ timestampWindowMs: 60_000, store });
        const second = new ReplayGuard({ timestampWindowMs: 60_000, store });
        const headers = {
            'x-urano-timestamp': String(Date.now()),
            'x-urano-nonce': 'raced-nonce'
        };
        const [a, b] = await Promise.all([first.check(headers), second.check(headers)]);
        const outcomes = [a, b];
        expect(outcomes.filter(r => r.valid)).toHaveLength(1);
        expect(outcomes.filter(r => r.reason === 'REPLAY_DETECTED')).toHaveLength(1);
    });

    it('falls back to process-local nonces when store is omitted', () => {
        const a = new ReplayGuard({ timestampWindowMs: 60_000 });
        const b = new ReplayGuard({ timestampWindowMs: 60_000 });
        const headers = {
            'x-urano-timestamp': String(Date.now()),
            'x-urano-nonce': 'local-only'
        };
        expect(a.check(headers)).toMatchObject({ valid: true });
        expect(b.check(headers)).toMatchObject({ valid: true });
    });
});

describe('ThreatRegistry shared store', () => {
    it('shares timed blocks via store and expires them', async () => {
        const store = new MemoryStore({ defaultTtlMs: 60_000 });
        const a = new ThreatRegistry([], [], store);
        const b = new ThreatRegistry([], [], store);

        await a.block('attacker-1', 25);
        expect(await b.isBlacklisted('attacker-1')).toBe(true);
        expect(await store.get('ug:block:attacker-1')).toBe(true);

        await new Promise(r => setTimeout(r, 35));
        expect(await b.isBlacklisted('attacker-1')).toBe(false);
        expect(await a.isBlacklisted('attacker-1')).toBe(false);
    });

    it('unblock removes the store key', async () => {
        const store = new MemoryStore();
        const registry = new ThreatRegistry(['seed-bad'], [], store);
        expect(await store.get('ug:block:seed-bad')).toBe(true);
        await registry.unblock('seed-bad');
        expect(await registry.isBlacklisted('seed-bad')).toBe(false);
        expect(await store.get('ug:block:seed-bad')).toBeUndefined();
    });

    it('seeds are visible after ready() / first isBlacklisted await', async () => {
        class SlowStore extends MemoryStore {
            async set<T = unknown>(key: string, value: T, ttlMs?: number): Promise<void> {
                await new Promise(r => setTimeout(r, 25));
                return super.set(key, value, ttlMs);
            }
        }
        const store = new SlowStore();
        const registry = new ThreatRegistry(['slow-bad'], ['slow-friend'], store);
        expect(await store.get('ug:block:slow-bad')).toBeUndefined();
        await registry.ready();
        expect(await store.get('ug:block:slow-bad')).toBe(true);
        expect(await store.get('ug:allow:slow-friend')).toBe(true);

        const late = new ThreatRegistry(['late-bad'], [], new SlowStore());
        expect(await late.isBlacklisted('late-bad')).toBe(true);
    });

    it('persists whitelist via ug:allow:', async () => {
        const store = new MemoryStore();
        const a = new ThreatRegistry([], ['friend'], store);
        const b = new ThreatRegistry([], [], store);
        expect(await store.get('ug:allow:friend')).toBe(true);
        expect(await b.isWhitelisted('friend')).toBe(true);

        await a.block('friend');
        expect(await b.isWhitelisted('friend')).toBe(false);
        expect(await b.isBlacklisted('friend')).toBe(true);
        expect(await store.get('ug:allow:friend')).toBeUndefined();

        await a.allow('friend');
        expect(await store.get('ug:allow:friend')).toBe(true);
        expect(await store.get('ug:block:friend')).toBeUndefined();
        expect(await b.isWhitelisted('friend')).toBe(true);
    });
});

describe('CacheManager and SemanticRateLimiter on SharedStore', () => {
    it('shares cache and rate-limit buckets through RedisSharedStore', async () => {
        const client = new FakeRedisClient();
        const store = new RedisSharedStore({ client });
        const cacheA = new CacheManager(60_000, 50, store);
        const cacheB = new CacheManager(60_000, 50, store);
        await cacheA.set('hit', allowDecision());
        expect((await cacheB.get('hit'))?.source).toBe('CACHE');
        expect((await cacheB.get('hit'))?.allowed).toBe(true);

        const rlA = new SemanticRateLimiter({
            windowMs: 60_000,
            maxRequestsPerWindow: 2,
            campaignIpThreshold: 10,
            store
        });
        const rlB = new SemanticRateLimiter({
            windowMs: 60_000,
            maxRequestsPerWindow: 2,
            campaignIpThreshold: 10,
            store
        });
        expect(await rlA.check('GET:/x:generic', '1.1.1.1')).toBe('ALLOWED');
        expect(await rlB.check('GET:/x:generic', '1.1.1.1')).toBe('ALLOWED');
        expect(await rlA.check('GET:/x:generic', '1.1.1.1')).toBe('RATE_LIMITED');
    });

    it('keeps both IPs when two limiters sadd concurrently', async () => {
        const store = new MemoryStore();
        const rlA = new SemanticRateLimiter({
            windowMs: 60_000,
            maxRequestsPerWindow: 100,
            campaignIpThreshold: 2,
            store
        });
        const rlB = new SemanticRateLimiter({
            windowMs: 60_000,
            maxRequestsPerWindow: 100,
            campaignIpThreshold: 2,
            store
        });
        const [a, b] = await Promise.all([
            rlA.check('GET:/recon:admin', '10.0.0.1'),
            rlB.check('GET:/recon:admin', '10.0.0.2')
        ]);
        expect([a, b].every(r => r === 'ALLOWED' || r === 'CAMPAIGN_DETECTED')).toBe(true);
        expect((await store.smembers('ug:rl:ips:GET:/recon:admin')).sort()).toEqual([
            '10.0.0.1',
            '10.0.0.2'
        ]);
        expect(await rlA.check('GET:/recon:admin', '10.0.0.3')).toBe('CAMPAIGN_DETECTED');
    });
});

describe('RequestFingerprinter shared store', () => {
    it('persists counts via ug:fp:', async () => {
        const store = new MemoryStore();
        const a = new RequestFingerprinter(100, store);
        const b = new RequestFingerprinter(100, store);
        const headers = { 'user-agent': 'bot/1' };
        const first = await a.fingerprint(headers, 'GET', '/p', 'body');
        expect(first.seenBefore).toBe(false);
        expect(first.occurrences).toBe(1);
        expect(await store.get(`ug:fp:${first.fingerprint}`)).toBe(1);

        const second = await b.fingerprint(headers, 'GET', '/p', 'body');
        expect(second.fingerprint).toBe(first.fingerprint);
        expect(second.seenBefore).toBe(true);
        expect(second.occurrences).toBe(2);
    });
});
