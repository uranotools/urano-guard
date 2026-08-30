# AGENTS.md — Urano Guard

Instructions for humans and AI coding agents (Cursor, Copilot, Windsurf, Codex, Aider, etc.) contributing to this repository.

**ES:** SDK local-first de inspección de amenazas (`@uranotools/urano-guard`). Lee este archivo antes de editar. Documentación profunda en los enlaces de abajo.

**EN:** Local-first threat-inspection SDK. Read this file before editing. Deep docs are linked below.

---

## What this is

A **TypeScript WAF middleware** that inspects HTTP-like requests **in process** with regex + normalization heuristics. Parallel plus: a **connectable agent** (`remoteAgent.url` → any HTTPS endpoint) that returns a verdict and may attach `analysis` / `report` onto `SecurityDecision`. Optional cluster state: an injected **Redis client** (this package does **not** depend on `ioredis` / `redis`). The WAF evolves locally; the agent is where models, SOC logic, and report generation live.

```
Adapter (Express / Fastify / Hono / Edge / HTTP)
  → UranoGuard.inspect()
    → Evaluator pipeline (cheap → expensive)
      1. ThreatRegistry allow / block
      2. ReplayGuard (nonce + timestamp)
      3. RequestFingerprinter
      4. SemanticRateLimiter
      5. CacheManager
      6. Local inspectors (prompt, SQLi, XSS, JWT, GraphQL, …)
      7. Remote agent + CircuitBreaker (optional)
      8. PII mask on allow
    → SecurityDecision { allowed, riskScore, reason, sanitizedBody }
```

Block threshold is typically **riskScore ≥ 60**. `securityMode` controls whether that blocks (`block_threats`), never blocks (`monitor_only`), always blocks unknown (`strict_zero_trust`), or delays (`quarantine`).

## What this is not

Do **not** describe or market this as:

- A network / CDN WAF, TLS terminator, or DDoS absorber
- A model-based LLM firewall or classifier
- A SIEM product (HTTP audit sink is a webhook POST)
- “Government-grade”, “99% of attacks”, or a compliance certification

Honest limits: [ENTERPRISE.md](ENTERPRISE.md).

---

## Repo map

```
src/
  index.ts              Public exports — append-only; no silent renames
  core/                 Pipeline + cluster primitives
    UranoGuard.ts       Orchestrator: createUranoGuard(), ready(), block()
    Evaluator.ts        Ordered inspection pipeline
    CircuitBreaker.ts   CLOSED / OPEN / HALF_OPEN (store-backed if store set)
    ReplayGuard.ts      setNX(ug:nonce:)
    SemanticRateLimiter.ts  incr + sadd IP sets
    ThreatRegistry.ts   ug:block: / ug:allow: (await seeds)
    CacheManager.ts     ug:cache: (LRU may evict)
    RequestFingerprinter.ts  ug:fp:
    RemoteAgentClient.ts
    SharedStore.ts      MemoryStore + PINNED_STORE_PREFIXES
    RedisSharedStore.ts Duck-typed Redis; Lua for decr/cas
    HttpAuditSink.ts    Fire-and-forget POST of safe AuditEvent
    PrometheusMetrics.ts / OpenTelemetryMetrics.ts  Injected, no SDK dep
    HoneypotRouter.ts   Tarpit + honey tokens on block
    routePolicy.ts      Per-path inspector / mode overrides
    validateConfig.ts   Throws ConfigValidationError at construct
    failPolicy.ts       failOpen vs failClosed
  inspectors/           One class per threat family + ruleEngine.ts
  adapters/             Normalize HTTP → GuardRequestContext
  types/                config, context, threat, store, audit, remoteAgent
  utils/                inspectText (normalize), crypto, identity, mtls
tests/
  fixtures/attacks/     Must BLOCK (score ≥ 60)
  fixtures/benign/      Must ALLOW
examples/               Runnable snippets, not the library API
```

**Docs (read the one that matches the change):**

| File | When |
|---|---|
| [README.md](README.md) | Public install / capabilities |
| [DEV_README.md](DEV_README.md) | Extending inspectors / adapters / config |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Pipeline diagrams, golden rules |
| [ENTERPRISE.md](ENTERPRISE.md) | Store, Redis, circuit CAS, audit, failClosed |
| [CUSTOM_AGENT.md](CUSTOM_AGENT.md) | Remote webhook contract 1.0 |
| [CHANGELOG.md](CHANGELOG.md) | User-facing deltas |
| [CONTRIBUTING.md](CONTRIBUTING.md) | PR / release process |
| [SECURITY.md](SECURITY.md) | Vulnerability reports |

---

## Hard rules (do not violate)

1. **Zero runtime npm dependencies.** `dependencies` in `package.json` must stay empty. Redis, OpenTelemetry Meter, and SIEM clients are **injected**. Duck-type their APIs; do not `import 'ioredis'`.
2. **No ReDoS.** Inspectors run on the request hot path. Bounded quantifiers, no nested `.*` / `.+` that can explode. Prefer `normalizeInspectionText` + linear scans (`decodeHtmlEntitiesBounded`) over clever regex.
3. **Fail-open by default.** Remote timeout / bad JSON / adapter throw must not take down the host unless the user set `failClosed`. Local inspectors still run first.
4. **Do not log secrets.** Audit events never include raw body, cookies, or `Authorization`. Same for examples and tests.
5. **Honest docs.** If you add a feature, document what it is **and** what it is not. Do not inflate ARCHITECTURE mermaid or README badges beyond the code.
6. **Public API is `src/index.ts`.** Export new symbols there. Do not rename or remove exports without a CHANGELOG breaking note.
7. **Store contract is complete.** A custom `SharedStore` must implement **every** method: `get`, `set`, `incr`, `decr`, `delete`, `setNX`, `cas`, `sadd`, `smembers`. All return `Promise`.
8. **Pinned MemoryStore prefixes** (`PINNED_STORE_PREFIXES` in `src/types/store.ts`): `ug:cb:`, `ug:nonce:`, `ug:rl:`, `ug:block:`, `ug:allow:`, `ug:fp:`. LRU may evict only `ug:cache:`. New Guard keys that must survive pressure belong on that list.
9. **`trustProxy` defaults to `false`.** Do not treat `X-Forwarded-For` / `x-user-id` as identity unless the user opted in.
10. **403 responses hide `riskScore` / `reason`** unless `exposeDecisionDetails: true`.
11. **Do not edit `.cursor/plans`.** Do not add `Co-authored-by: Cursor` or similar trailers unless the human asked.
12. **Do not bump `package.json` version** unless the human asked to release. Unpublished work goes under **1.2.0 (unreleased)** in CHANGELOG. Current published line is **1.1.0**.

---

## Version policy

| File | Rule |
|---|---|
| `package.json` `version` | Stays **1.1.0** until a human ships 1.2.0 |
| `CHANGELOG.md` | New work → `## 1.2.0 (unreleased)` |
| README “What’s new” | 1.1 is shipped; 1.2 is upcoming / unreleased |

Do not invent 1.3 / 1.4 version numbers.

---

## Commands

Node **≥ 18** locally. CI matrix is **20 and 22** (Vite 6 dropped 18 for the test runner).

```bash
npm install
npm test                 # vitest run --config vitest.config.mjs
npm run test:watch
npm run typecheck        # tsc --noEmit
npm run lint             # eslint src --ext .ts
npm run build
```

Always use `--config vitest.config.mjs` (the `.ts` config breaks CJS load on CI). After any behavioral change run **all three**: test, typecheck, lint.

---

## Request path (types)

Adapters build a `GuardRequestContext` (`src/types/context.ts`): `ip`, `method`, `path`, `headers`, `body`, optional `query`, `senderId`, `timestamp`.

Inspectors read text via `collectInspectionText(context)` then `normalizeInspectionText` (NFKC, zero-width strip, optional leet for prompts, homoglyph fold, bounded HTML-entity decode). SQL rules also use `stripSqlComments`.

Return `ThreatIncident | ThreatIncident[] | null` from `InspectorBase.inspect`. Use existing `ThreatCategory` values or `'CUSTOM'`. Score ≥ 60 is what the corpus treats as a block.

Register extras with `guard.registerInspector(inspector)` — it is wired. Built-in inspectors are constructed from `config.inspectors` flags in `UranoGuard`.

---

## How to add a detection rule

1. Add a `DetectionRule` to the relevant inspector (e.g. `PromptInjectionInspector.ts`). Give it a **stable `name`** (`SUDO_MODE_JAILBREAK` style).
2. Keep the regex ReDoS-safe. Reset `lastIndex` is already done in `matchRules`.
3. Add at least one attack fixture in `tests/fixtures/attacks/*.json` with a unique `id`.
4. If the pattern could false-positive on chat/product text, add a benign case in `tests/fixtures/benign/chat.json`.
5. Run `npm test`. Corpus cases with score ≥ 60 must block; benign must allow.

JWT / GraphQL fixtures live in `tests/fixtures/attacks/jwt-graphql.json` and are enabled in a dedicated describe in `tests/corpus.test.ts`.

Do **not** add a new inspector class for a single regex if it belongs in an existing family.

---

## How to add an inspector

1. Extend `InspectorBase` in `src/inspectors/`.
2. Construct it from `UranoGuard` when the matching `config.inspectors.*` flag is on (add the flag in `src/types/config.ts` + `validateConfig.ts`).
3. Export the class from `src/index.ts`.
4. Unit test in `tests/inspectors.test.ts` + corpus fixtures.
5. Document the flag in DEV_README / CHANGELOG (unreleased).

```ts
export class ExampleInspector extends InspectorBase {
    readonly name = 'ExampleInspector';
    readonly enabled: boolean;
    constructor(enabled = true) { super(); this.enabled = enabled; }
    inspect(context: GuardRequestContext): ThreatIncident[] | null {
        if (!this.enabled) return null;
        return matchRules(context, collectInspectionText(context), RULES, 'thr_ex');
    }
}
```

---

## How to add an adapter

1. Extend `AdapterBase` in `src/adapters/`.
2. Map framework request → `GuardRequestContext` (honor `trustProxy` via `pickClientIp` / `pickSenderId`).
3. Call `this.guard.inspect(ctx)`. On deny: 403 without details unless `exposeDecisionDetails`. On throw: fail-open or fail-closed via `isFailClosed`.
4. Export + wire a convenience method on `UranoGuard` if the others have one (`express()`, `hono()`, …).
5. Test the adapter; add an example only if it shows a new pattern.

---

## How to change the store / circuit

Read [ENTERPRISE.md](ENTERPRISE.md) first.

- Cluster-safe writes: `incr` / `decr` / `setNX` / `cas` / `sadd` — **not** get-then-set.
- Redis `decr` / `cas` use `client.eval` + `REDIS_DECR_LUA` / `REDIS_CAS_LUA`. MemoryStore must match the semantics.
- Circuit: OPEN→HALF_OPEN is `cas`; CLOSED success is `decr`; probe is `setNX(ug:cb:probeLock)`.
- Seeds: `ThreatRegistry` awaits constructor writes; `inspect()` waits. Optional `await guard.ready()`.
- node-redis v4 needs a thin wrap (`set` PX/NX, `sAdd`, `pExpire`, `eval`). Document wraps in ENTERPRISE.md, do not add a redis dependency.

---

## Tests

| File | Covers |
|---|---|
| `tests/corpus.test.ts` | Attack / benign JSON fixtures |
| `tests/inspectors.test.ts` | Per-inspector rules |
| `tests/store.test.ts` | MemoryStore + Redis duck + pin / setNX / cas |
| `tests/circuitBreaker.test.ts` | Shared + local breaker |
| `tests/enterprise.test.ts` | validateConfig, failClosed, audit, metrics |
| `tests/httpAudit.test.ts` | SIEM webhook sink |
| `tests/remoteAgent.test.ts` | BYO agent contract |
| `tests/helpers.ts` | `ctx()` factory — use it |

Mock `fetch` / Redis clients in unit tests. Do not require a live Redis.

---

## Public surface (do not break casually)

`createUranoGuard`, `UranoGuard`, `registerInspector`, `ready()`, `block` / `unblock`, adapters, inspectors, `MemoryStore`, `RedisSharedStore`, `createHttpAuditSink`, `createPrometheusMetrics`, `createOpenTelemetryMetrics`, `validateConfig`, store pin helpers, `normalizeInspectionText`.

Types ship via `export *` from `src/types/*`.

---

## Style

- TypeScript, no new runtime deps, ESM-shaped `exports` in package.json (compiled CJS `dist/`).
- Match existing naming: `ug:` key prefixes, `thr_` incident ids, `SCREAMING_RULE_NAMES`.
- Prefer small files over new abstraction layers.
- Comments: JSDoc on **public** APIs only. No narrating comments.
- Examples stay copy-paste runnable (`examples/`). Update `examples/README.md` when you add one.

---

## PR checklist (agents)

- [ ] Behavior covered by a test (corpus and/or unit)
- [ ] `npm test` && `npm run typecheck` && `npm run lint`
- [ ] `src/index.ts` updated if you added a public symbol
- [ ] CHANGELOG **1.2.0 (unreleased)** if user-visible
- [ ] ENTERPRISE.md / CUSTOM_AGENT.md / DEV_README.md if the matching contract changed
- [ ] No version bump, no commit unless the human asked
- [ ] No overselling in README
