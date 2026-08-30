import { SharedStore } from '../types/store';

/**
 * Floor-at-zero DECR. Reads a raw integer or a JSON number. Writes a raw
 * integer so a later Redis `INCR` still works. Missing / non-numeric → 0.
 *
 * ioredis and node-redis both expose `eval`; this package does not call
 * `defineCommand`.
 */
export const REDIS_DECR_LUA = `
local raw = redis.call('GET', KEYS[1])
if not raw then
  redis.call('SET', KEYS[1], '0')
  return 0
end
local v = tonumber(raw)
if not v then
  v = tonumber((string.gsub(raw, '^"(.*)"$', '%1')))
end
if not v or v <= 0 then
  redis.call('SET', KEYS[1], '0')
  return 0
end
v = v - 1
redis.call('SET', KEYS[1], tostring(v))
return v
`.trim();

/**
 * Compare-and-swap on the JSON-encoded value {@link RedisSharedStore.set} writes.
 * ARGV[1] = expected JSON, ARGV[2] = next JSON, ARGV[3] = ttlMs (0 = no PX).
 */
export const REDIS_CAS_LUA = `
local cur = redis.call('GET', KEYS[1])
if cur == ARGV[1] then
  local ttl = tonumber(ARGV[3])
  if ttl and ttl > 0 then
    redis.call('SET', KEYS[1], ARGV[2], 'PX', ttl)
  else
    redis.call('SET', KEYS[1], ARGV[2])
  end
  return 1
end
return 0
`.trim();

/**
 * Duck-typed Redis client. No `redis` / `ioredis` dependency — inject yours.
 *
 * Methods may return values or Promises; {@link RedisSharedStore} awaits either.
 *
 * **ioredis** (command names this adapter calls):
 * - `get(key)` → `string | null`
 * - `set(key, value, 'PX', ms)` — millisecond TTL
 * - `set(key, value, 'PX', ms, 'NX')` — SET NX with TTL (`setNX`)
 * - `set(key, value, 'NX')` — SET NX, no expiry
 * - `set(key, value)` — no expiry
 * - `del(key)`
 * - `incr(key)` → `number`
 * - `sadd(key, member)` → added count
 * - `smembers(key)` → `string[]`
 * - `pexpire(key, ms)` / `pttl(key)` — set TTL only when the key has none
 * - `eval(script, numKeys, key, ...args)` — required for {@link RedisSharedStore.decr}
 *   and {@link RedisSharedStore.cas} (ioredis already has this; no `defineCommand`)
 *
 * **node-redis v4** uses camelCase (`sAdd`, `sMembers`, `pExpire`, `pTTL`)
 * and `set(key, value, { PX, NX })`. `eval` takes `{ keys, arguments }`. Wrap it:
 * ```ts
 * {
 *   get: (k) => client.get(k),
 *   set: (k, v, mode?, ms?, flag?) => {
 *     const opts: Record<string, unknown> = {};
 *     if (mode === 'PX' && ms) opts.PX = ms;
 *     if (mode === 'NX' || flag === 'NX') opts.NX = true;
 *     return Object.keys(opts).length ? client.set(k, v, opts) : client.set(k, v);
 *   },
 *   del: (k) => client.del(k),
 *   incr: (k) => client.incr(k),
 *   sadd: (k, m) => client.sAdd(k, m),
 *   smembers: (k) => client.sMembers(k),
 *   pexpire: (k, ms) => client.pExpire(k, ms),
 *   pttl: (k) => client.pTTL(k),
 *   eval: (script, numKeys, ...args) => client.eval(script, {
 *     keys: args.slice(0, numKeys).map(String),
 *     arguments: args.slice(numKeys).map(String)
 *   })
 * }
 * ```
 *
 * SharedStore is **Promise-based**. Pass ioredis / node-redis clients directly
 * (ioredis already matches this shape; node-redis needs the wrap above).
 */
export interface RedisStoreClient {
    get(key: string): unknown;
    set(key: string, value: string, mode?: 'PX' | 'NX', ms?: number, flag?: 'NX'): unknown;
    del(key: string): unknown;
    incr(key: string): unknown;
    sadd(key: string, member: string): unknown;
    smembers(key: string): unknown;
    pexpire(key: string, ms: number): unknown;
    pttl(key: string): unknown;
    expire?(key: string, seconds: number): unknown;
    /**
     * ioredis-style EVAL. Required for `decr` and `cas`.
     * `eval(script, numKeys, key1, …, arg1, …)`
     */
    eval?(script: string, numKeys: number, ...args: Array<string | number>): unknown;
}

export interface RedisSharedStoreOptions {
    client: RedisStoreClient;
}

/**
 * SharedStore adapter that speaks Redis commands through an injected client.
 * Scalar values are JSON-encoded. Set members (`sadd`) are raw strings.
 * First `incr` / `sadd` on a key applies TTL when given; later writes do not
 * slide that window.
 *
 * `decr` and `cas` run as Lua via `client.eval` so GET+SET is not a race.
 * ioredis and node-redis already implement `eval` — this adapter does not
 * call `defineCommand`.
 */
export class RedisSharedStore implements SharedStore {
    private client: RedisStoreClient;

    constructor(opts: RedisSharedStoreOptions) {
        if (!opts?.client) {
            throw new Error('RedisSharedStore requires { client }');
        }
        this.client = opts.client;
    }

    async get<T = unknown>(key: string): Promise<T | undefined> {
        const raw = await this.client.get(key);
        if (raw == null || raw === '') return undefined;
        if (typeof raw !== 'string') {
            throw new Error(
                `RedisSharedStore: client.get(${key}) returned unexpected type ${typeof raw}`
            );
        }
        try {
            return JSON.parse(raw) as T;
        } catch {
            return raw as T;
        }
    }

    async set<T = unknown>(key: string, value: T, ttlMs?: number): Promise<void> {
        const payload = JSON.stringify(value);
        if (ttlMs !== undefined && ttlMs > 0) {
            await this.client.set(key, payload, 'PX', ttlMs);
            return;
        }
        await this.client.set(key, payload);
    }

    async incr(key: string, ttlMs?: number): Promise<number> {
        const raw = await this.client.incr(key);
        const n = Number(raw);
        if (!Number.isFinite(n)) {
            throw new Error(`RedisSharedStore: client.incr(${key}) returned ${String(raw)}`);
        }
        if (n === 1 && ttlMs !== undefined && ttlMs > 0) {
            await this.client.set(key, JSON.stringify(1), 'PX', ttlMs);
        }
        return n;
    }

    /**
     * Atomic floor-at-zero decrement via Lua ({@link REDIS_DECR_LUA}).
     * Requires `client.eval` (ioredis / node-redis already have it).
     */
    async decr(key: string): Promise<number> {
        const raw = await this.evalScript(REDIS_DECR_LUA, key);
        const n = Number(raw);
        if (!Number.isFinite(n)) {
            throw new Error(`RedisSharedStore: decr(${key}) returned ${String(raw)}`);
        }
        return n;
    }

    async setNX<T = unknown>(key: string, value: T, ttlMs?: number): Promise<boolean> {
        const payload = JSON.stringify(value);
        const raw = ttlMs !== undefined && ttlMs > 0
            ? await this.client.set(key, payload, 'PX', ttlMs, 'NX')
            : await this.client.set(key, payload, 'NX');
        return raw === 'OK' || raw === true;
    }

    /**
     * Atomic compare-and-swap via Lua ({@link REDIS_CAS_LUA}).
     * GET then SET in JS is not used — that would race.
     * Requires `client.eval`.
     */
    async cas<T = unknown>(key: string, expected: T, next: T, ttlMs?: number): Promise<boolean> {
        const raw = await this.evalScript(
            REDIS_CAS_LUA,
            key,
            JSON.stringify(expected),
            JSON.stringify(next),
            ttlMs !== undefined && ttlMs > 0 ? ttlMs : 0
        );
        return raw === 1 || raw === '1' || raw === true;
    }

    async sadd(key: string, member: string, ttlMs?: number): Promise<number> {
        const raw = await this.client.sadd(key, member);
        const added = Number(raw);
        if (ttlMs !== undefined && ttlMs > 0) {
            const remaining = Number(await this.client.pttl(key));
            // -2 missing, -1 no TTL, >= 0 remaining ms. Only expire when unset.
            if (!Number.isFinite(remaining) || remaining < 0) {
                if (this.client.pexpire) {
                    await this.client.pexpire(key, ttlMs);
                } else if (this.client.expire) {
                    await this.client.expire(key, Math.ceil(ttlMs / 1000));
                }
            }
        }
        return Number.isFinite(added) ? added : 0;
    }

    async smembers(key: string): Promise<string[]> {
        const raw = await this.client.smembers(key);
        if (!Array.isArray(raw)) return [];
        return raw.map(String);
    }

    async delete(key: string): Promise<void> {
        await this.client.del(key);
    }

    private async evalScript(
        script: string,
        key: string,
        ...args: Array<string | number>
    ): Promise<unknown> {
        if (typeof this.client.eval !== 'function') {
            throw new Error(
                'RedisSharedStore.decr/cas require client.eval ' +
                '(ioredis and node-redis already provide it; wrap node-redis — see ENTERPRISE.md). ' +
                'This adapter does not call defineCommand.'
            );
        }
        return this.client.eval(script, 1, key, ...args);
    }
}
