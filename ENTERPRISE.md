# Urano Guard — enterprise rollout notes

This package is a **local-first, heuristic WAF SDK**. It is useful in front of APIs, webhooks, and LLM apps. It is **not** a network WAF, a CDN, or a model-based LLM firewall.

Read this before you turn on `block_threats` in production.

## What this is not

- **Not a replacement for a network WAF or API gateway.** Put Guard *behind* TLS termination and your edge WAF (or next to the app). It does not terminate TLS, do bot JS challenges, or absorb volumetric DDoS.
- **Not a model-based LLM firewall.** Prompt-injection rules are regex and normalization, not a classifier. A determined adversary can still phrase around them. Pair with your own remote agent if you need a model in the loop ([CUSTOM_AGENT.md](CUSTOM_AGENT.md)).
- **Not a compliance certification.** `failClosed`, audit lines, and Prometheus scrapes help you operate responsibly. They do not make the product “government-grade” or substitute for a risk assessment.

## Week 1: `monitor_only`

Ship with `securityMode: 'monitor_only'` for at least a week.

- Requests are **never blocked**. Decisions still flow to `auditLogger`, EventBus, and metrics.
- Watch false-positive rate on real traffic (support tickets, SQL-looking product text, “act as a travel agent”, etc.).
- Tune `routePolicies` (`/health`, webhooks you already sign) and inspector flags before switching to `block_threats`.

```ts
const guard = createUranoGuard({
    securityMode: 'monitor_only',
    trustProxy: false,
    auditLogger: 'json',
    metrics: createPrometheusMetrics()
});
```

## `trustProxy`

Default is **`false`**. `X-Forwarded-For` and `x-user-id` are ignored unless you opt in.

Only set `trustProxy: true` when a reverse proxy you control strips or overwrites those headers. If the client can set them, attackers choose their own identity (bypass blacklist, poison rate-limit buckets).

## failClosed vs failOpen

| Mode | Default | Remote timeout / bad JSON / adapter throw |
|---|---|---|
| `failOpen: true` (default) | yes | Request **continues**. Local heuristics still ran. |
| `failClosed: true` | no | Request is **blocked** (remote) or the adapter returns 5xx (throw). |

Use **fail-open** for availability-first APIs. Use **fail-closed** when a missed remote verdict is worse than downtime (regulated review queues, admin actions). They cannot both be `true`.

`failOpen: false` is treated as fail-closed. Circuit-open skips also block when fail-closed is on.

Local inspectors still run first. Fail-closed does not disable them.

## Audit and PII

```ts
createUranoGuard({
    auditLogger: (event) => siem.write(event)
    // or auditLogger: 'json'  → one JSON object per line on stdout
});
```

Each event has: `requestId`, `action`, `allowed`, `riskScore`, `threatCategories`, `path`, `method`, `source`, `latencyMs`.

Guard **does not** put raw body, cookies, or `Authorization` on the audit event. Do not log `req.body` yourself next to the audit line. Allowed traffic can still be PII-masked via `inspectors.piiDataMasking` (cards, emails, phones, common key prefixes) — that is not a substitute for a DLP product.

## Prometheus

Zero extra runtime dependencies. Attach the in-process exporter and scrape it:

```ts
import { createUranoGuard, createPrometheusMetrics } from '@uranotools/urano-guard';

const metrics = createPrometheusMetrics();
const guard = createUranoGuard({ metrics });

app.get('/metrics', guard.metricsHandler());
// or: const text = guard.prometheus();
```

Counters include blocks/allows, threat hits, inspector hits, remote agent success/failure/latency, and circuit state. This is **not** an OpenTelemetry SDK and does not export traces.

## Shared store / Redis

`MemoryStore` is the default (same process). Cache, semantic rate-limit, ReplayGuard nonces, ThreatRegistry blocks/allowlist, fingerprint counts, and circuit-breaker state all go through `SharedStore`:

`get` / `set` / `delete` / `incr` / `decr` / `setNX` / `cas` / `sadd` / `smembers` + TTL.

Methods return Promises — `MemoryStore` resolves immediately. A custom `SharedStore` must implement **all** of those methods (including `decr` and `cas`).

That is enough for a single Node instance. For several processes, inject a store. `RedisSharedStore` speaks Redis commands but does **not** depend on `redis` or `ioredis` — pass your client (Promises are awaited):

```ts
import { createUranoGuard, RedisSharedStore } from '@uranotools/urano-guard';
import Redis from 'ioredis';

const client = new Redis(process.env.REDIS_URL);
const store = new RedisSharedStore({ client });

const guard = createUranoGuard({
    store,
    blockedIdentifiers: ['1.2.3.4']
});
await guard.ready(); // seeds written before listen(); inspect() also waits
```

ioredis already exposes `get` / `set` / `del` / `incr` / `sadd` / `smembers` / `pexpire` / `pttl` / `eval` as Promises, including `set(key, value, 'PX', ms, 'NX')`. `decr` and `cas` run as Lua through `eval` (no `defineCommand`). node-redis v4 uses camelCase, `set(key, value, { PX, NX })`, and `eval(script, { keys, arguments })` — wrap it:

```ts
const store = new RedisSharedStore({
    client: {
        get: (key) => client.get(key),
        set: (key, value, mode, ms, flag) => {
            const opts: Record<string, unknown> = {};
            if (mode === 'PX' && ms) opts.PX = ms;
            if (mode === 'NX' || flag === 'NX') opts.NX = true;
            return Object.keys(opts).length ? client.set(key, value, opts) : client.set(key, value);
        },
        del: (key) => client.del(key),
        incr: (key) => client.incr(key),
        sadd: (key, member) => client.sAdd(key, member),
        smembers: (key) => client.sMembers(key),
        pexpire: (key, ms) => client.pExpire(key, ms),
        pttl: (key) => client.pTTL(key),
        eval: (script, numKeys, ...args) => client.eval(script, {
            keys: args.slice(0, numKeys).map(String),
            arguments: args.slice(numKeys).map(String)
        })
    }
});
```

Without `eval`, `RedisSharedStore.decr` / `cas` throw. ioredis can be passed as `{ client }` with no wrap.

Scalar values are JSON-encoded. Set members (`ug:rl:ips:`) are raw strings. Prefixes: `ug:cache:`, `ug:rl:count:`, `ug:rl:ips:`, `ug:nonce:`, `ug:block:`, `ug:allow:`, `ug:fp:`, `ug:cb:`, `ug:agent:`. `ttlMs <= 0` means no expiry (permanent blocks / allowlist / circuit keys).

**MemoryStore LRU pin** — `maxEntries` evicts only unpinned keys. Pinned prefixes (never evicted): `ug:cb:`, `ug:nonce:`, `ug:rl:` (counts + IP sets), `ug:block:`, `ug:allow:`, `ug:fp:`, `ug:agent:` (agent memory). Decision-cache keys (`ug:cache:`) **may** still evict. Pinned writes can push `store.size` above `maxEntries`. See `PINNED_STORE_PREFIXES` / `isPinnedStoreKey`. Pinning is MemoryStore-only; Redis uses its own `maxmemory-policy`.

Do not share one `MemoryStore` across unrelated apps on the same host and expect isolation beyond those key prefixes.

**How the former races work now**

- **ReplayGuard nonces** — `setNX` (`ug:nonce:`). The second concurrent claim fails; that request is `REPLAY_DETECTED`.
- **Semantic rate-limit IPs** — `sadd` + `smembers` (`ug:rl:ips:`). Concurrent writers keep both members. TTL is applied only when `PTTL` says the key has no expiry (window does not slide). Counts stay on `incr` (`ug:rl:count:`).
- **Circuit breaker** — with a store, state lives at `ug:cb:state` / `failures` / `lastFailure` / `probeSuccesses`. CLOSED success decays failures with atomic `decr` (floored at 0). OPEN→HALF_OPEN is a single-winner `cas('OPEN', 'HALF_OPEN')`. HALF_OPEN still takes a cluster-wide probe lock via `setNX` (`ug:cb:probeLock`). Without a store, the breaker stays in-process (existing tests / single instance).
- **ThreatRegistry seeds** — constructor writes are awaited internally. `isBlacklisted` / `isWhitelisted` wait for `ready()`. `block` / `unblock` / `allow` already await. Optional `await guard.ready()` before `listen()` if another process may read Redis first.

**Remaining limits** (honest leftovers)

- **Redis maxmemory** — MemoryStore pin does not apply to Redis. A `volatile-lru` / `allkeys-lru` policy can still drop `ug:cb:` / nonces / blocks. Prefer `noeviction` (or a dedicated DB) if those keys must survive.
- **HALF_OPEN probe lock TTL** — if a process dies mid-probe, the lock expires after `max(recoveryTimeMs, 5000)` and another instance may probe. That is intentional recovery, not a second simultaneous probe on a healthy locker.
- **Pinned MemoryStore growth** — nonces, blocks, and IP sets are never LRU-evicted, so a long-lived process can grow past `maxEntries`. TTL still expires keys; Redis does not have this in-process cap.
- **Custom `SharedStore` implementations** must add `setNX`, `sadd`, `smembers`, `decr`, and `cas`. Redis clients that only wrapped `get`/`set`/`del`/`incr` need the extra commands **and** `eval` (node-redis wrap above).

## BYO remote agent

The local WAF is the in-process perimeter. The **agent** is the parallel layer: any HTTPS endpoint you operate (same host, another VPC, an LLM, a SOC service). Guard POSTs schema 1.0 and maps the verdict. A first hop can stay small (`payload.include`); the agent may `NEED` extra fields, and Guard sends **one** follow-up of `need ∩ payload.onRequest` only. `response.include` declares which extras (`analysis` / `report` / …) land on the decision. Guard does not generate reports and does not put them on the audit event.

There is no hosted “Urano Cloud” requirement. You choose payload fields, auth, and `invokeWhen`. See [CUSTOM_AGENT.md](CUSTOM_AGENT.md).

If you enable fail-closed, that endpoint is on the availability path. Budget `timeoutMs`, watch `urano_guard_remote_agent_failure_total`, and keep the circuit breaker on.

## Honest limits

- Detection is regex + light normalization. Corpus coverage is still small. This is not a model-based LLM firewall.
- No traces/spans. OTel is optional counters via an injected Meter (`createOpenTelemetryMetrics`); this package does not ship an OTLP exporter.
- No distributed audit ledger, no managed SOC, no full SIEM product. `createHttpAuditSink` is a webhook POST of the safe `AuditEvent`.
- Circuit breaker state is shared when you inject a store. Leftovers are listed under Shared store (Redis maxmemory, probe-lock TTL, pinned MemoryStore growth).
- Identity (`senderId`, IP) is only as trustworthy as `trustProxy`.
- `monitor_only` week 1 is the recommended path. Turning on `failClosed` + `block_threats` on day one will page you.

## OpenTelemetry

Optional `MetricsExporter` that talks to an injected OpenTelemetry **Meter**. This package does **not** depend on `@opentelemetry/api` or `@opentelemetry/sdk-metrics`. You create the Meter in your app and pass it in.

```ts
import { createUranoGuard, createOpenTelemetryMetrics } from '@uranotools/urano-guard';
// In your app (you install the SDK):
// import { metrics } from '@opentelemetry/api';
// const meter = metrics.getMeter('urano-guard');

const metrics = createOpenTelemetryMetrics({ meter });
const guard = createUranoGuard({ metrics });
```

Counter names match Prometheus: `urano_guard_request_blocked_total`, `urano_guard_request_allowed_total`, `urano_guard_threat_detected_total`, `urano_guard_inspector_hits_total`, `urano_guard_remote_agent_success_total`, `urano_guard_remote_agent_failure_total`, plus skipped/latency/circuit when the Meter exposes `createHistogram` / `createGauge` or `createObservableGauge`.

This is **not** a traces/spans SDK. See `examples/otel-metrics.ts`.

## HTTP audit sink

`createHttpAuditSink` POSTs each `AuditEvent` as JSON to a SIEM or webhook you operate. The call is fire-and-forget with a timeout; network errors are swallowed so audit never breaks the request. Optional `onError` is for your own metrics — if it throws, that is swallowed too.

The JSON body is the same safe `AuditEvent` (`requestId`, `action`, `allowed`, `riskScore`, `threatCategories`, `path`, `method`, `source`, `latencyMs`). Guard **does not** put raw body, cookies, or `Authorization` on the event.

```ts
import { createUranoGuard, createHttpAuditSink } from '@uranotools/urano-guard';

const guard = createUranoGuard({
    auditLogger: createHttpAuditSink({
        url: process.env.SIEM_URL,
        headers: { 'X-Webhook-Key': process.env.SIEM_TOKEN || '' },
        timeoutMs: 2000
    })
});
```

Zero extra runtime dependencies (`fetch` is built in on Node 18+). See `examples/http-audit-sink.ts`.
