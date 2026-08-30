# Changelog

## 1.2.0 (unreleased)

Not published yet. `package.json` stays at **1.1.0** until you tag this release.

### Features

- **Async `SharedStore`**: `get` / `set` / `incr` / `decr` / `delete` / `setNX` / `cas` / `sadd` / `smembers` return Promises. `MemoryStore` resolves immediately. Cache, semantic rate-limit, ReplayGuard nonces, ThreatRegistry blocks/allowlist, fingerprint counts, and circuit-breaker state go through the store. `guard.block` / `unblock` are Promises.
- **Atomic store primitives**: `setNX` (ReplayGuard nonces, circuit HALF_OPEN probe lock), `sadd` + `smembers` (rate-limit unique IPs; TTL set only when the key has no expiry), `decr` (CLOSED failure decay, floored at 0), `cas` (OPEN→HALF_OPEN single-winner).
- **MemoryStore LRU pin**: prefixes `ug:cb:`, `ug:nonce:`, `ug:rl:`, `ug:block:`, `ug:allow:`, `ug:fp:` are never evicted. `ug:cache:` may still evict. See `PINNED_STORE_PREFIXES`.
- **Shared circuit breaker**: when a store is injected, OPEN / HALF_OPEN / CLOSED and the in-flight probe lock live at `ug:cb:`. OPEN→HALF_OPEN is `cas`; CLOSED success uses `decr`; HALF_OPEN still allows a **single** cluster-wide probe (`SET NX`). Without a store, behavior stays in-process.
- **ThreatRegistry seeds**: constructor writes `ug:block:` / `ug:allow:` and tracks the Promise. `isBlacklisted` / `isWhitelisted` await it. Optional `await registry.ready()` / `await guard.ready()` if another process may read Redis before the first request.
- **`RedisSharedStore`**: talks Redis `GET`/`SET PX|NX`/`DEL`/`INCR`/`SADD`/`SMEMBERS`/`PEXPIRE`/`PTTL` plus Lua `EVAL` for `decr`/`cas` through an injected client. No `ioredis` / `redis` dependency — pass yours. Scalar values are JSON-encoded; set members are raw strings. node-redis v4 needs a thin wrap including `eval` (see [ENTERPRISE.md](ENTERPRISE.md)). Does not call `defineCommand`.
- **HTTP audit sink**: `createHttpAuditSink({ url })` POSTs the safe `AuditEvent` (no body, cookies, or Authorization) to a webhook you operate. Fire-and-forget; failures are swallowed.
- **Config validation** at construct time (`remoteAgent.url`, timeouts, inspector flags, `failClosed` vs `failOpen`). Throws `ConfigValidationError`.
- **`failClosed`** (default `false`). Remote/adapter evaluation errors **block** instead of allow. `failOpen` remains the default opposite.
- **Structured audit log**: `auditLogger` callback or `'json'` line writer. Events include requestId, action, riskScore, threat categories, path, method, source, latencyMs. Never logs raw body, cookies, or Authorization.
- **Prometheus scrape** with no extra runtime deps: `createPrometheusMetrics()`, `guard.prometheus()`, `guard.metricsHandler()`.
- **Corpus extras**: more attack/benign fixtures. New local rules `SUDO_MODE_JAILBREAK`, `AIM_JAILBREAK`, `CMD_PATH_TRAVERSAL`. Bounded HTML-entity decode before heuristics.
- **Agent analysis / report passthrough**: remote JSON may include `analysis` / `agentAnalysis` and `report` / `agentReport`. Copied onto `SecurityDecision`. Guard does not author reports; they stay off the audit line.
- **Agent NEED + declared extras**: first hop sends `payload.include` plus `capabilities.canDisclose`. Agent may return `{ verdict: "NEED", need: ["body"] }`; Guard does **one** follow-up with `need ∩ payload.onRequest` only. `response.include` declares which extras (`reason` / `threats` / `analysis` / `report`) land on the decision. Verdict/score always apply.
- **Agent skills catalog**: `remoteAgent.skills.catalog` — named `provide` functions your app implements (logs, chunks, tenant lookup). Agent NEEDs `{ name, args }`; Guard runs only declared names and returns `skillResults` / `deniedSkills` on the same follow-up. Results clipped at `maxResultBytes`. No built-in log shipper.
- **`maxFollowUps`** (1–4, default 1): extra NEED hops after the first POST.
- **Agent memory**: `remoteAgent.memory` writes `remember` / `memory` to `ug:agent:mem:` and sends it on the next inspect for that key.
- **Async investigate**: `investigateAsync.enabled` — a verdict plus `investigate: true` returns now (`investigationPending`); report/NEED continue in the background (`onComplete`, EventBus `agentInvestigationComplete`).

### Docs

- [ENTERPRISE.md](ENTERPRISE.md): store API (`setNX`, `sadd`, `smembers`, `decr`, `cas`), pinned LRU prefixes, ioredis / node-redis wrap + `eval`, shared circuit CAS/decr, seed `ready()`, leftover limits (Redis maxmemory, probe-lock TTL, pinned MemoryStore growth).
- Product framing: local **WAF** (evolves on the request path) + connectable **agent** (analysis and reports on any HTTPS URL). [CUSTOM_AGENT.md](CUSTOM_AGENT.md), [README.md](README.md) — removed the “99% of probes” claim.

## 1.1.0

### Features

- Configurable **BYO remote agent** (`remoteAgent`): payload `include`/`extra`, Bearer/header/HMAC, `invokeWhen`, response mapping. See [CUSTOM_AGENT.md](CUSTOM_AGENT.md).
- Text **normalization** before heuristics (NFKC, zero-width strip, optional leet for prompt rules) and SQL comment stripping (`UN/**/ION`).
- Split inspectors: SQL, command injection, XSS; plus JWT tampering and GraphQL abuse.
- Inspection surface: body + query + path + allowlisted headers.
- Route policies, `trustProxy`, quarantine TTL, Hono adapter, injectable logger, EventBus metrics.
- Attack/benign **corpus tests**. Runnable demo: [examples/README.md](examples/README.md).

### Breaking / behavior changes (from 1.0.x)

- `trustProxy` defaults to `false`. `X-Forwarded-For` / `x-user-id` are ignored unless enabled.
- Block responses hide `riskScore` / `reason` unless `exposeDecisionDetails: true`.
- `sqlAndCommands` still enables SQL + command + XSS; prefer the new flags.
- Circuit breaker HALF_OPEN allows a **single** in-flight probe.
- Cache keys hash the full body (no 100-character prefix).

### Migration

`agentWebhookUrl` + `apiKey` still send the legacy `{ sender, content, path, method }` payload. Set `remoteAgent.payload` or `buildPayload` to use schema 1.0.

## 1.0.0

Initial public SDK: local inspectors, Express/Fastify/Edge/HTTP adapters, optional remote webhook.
