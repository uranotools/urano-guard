# Contributing to `@uranotools/urano-guard`

Guía para aportar al SDK: cómo funciona el pipeline, qué APIs puedes usar o extender, y cómo integrar las piezas de store, audit, métricas y reglas que ya existen.

Si trabajas con un **IDE con IA**, empieza también por [AGENTS.md](AGENTS.md) (mapa del repo, reglas duras, checklist de PR). Contrato de producción y Redis: [ENTERPRISE.md](ENTERPRISE.md). Webhook remoto: [CUSTOM_AGENT.md](CUSTOM_AGENT.md). Diagramas: [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Table of contents

1. [Code of Conduct](#code-of-conduct)
2. [Cómo aportar](#cómo-aportar)
3. [Setup](#setup)
4. [Lógica del sistema](#lógica-del-sistema)
5. [APIs públicas (usar / modificar)](#apis-públicas-usar--modificar)
6. [Añadir una regla de detección](#añadir-una-regla-de-detección)
7. [Añadir un inspector](#añadir-un-inspector)
8. [Añadir un adaptador](#añadir-un-adaptador)
9. [Store, Redis y circuit breaker](#store-redis-y-circuit-breaker)
10. [Audit, métricas y EventBus](#audit-métricas-y-eventbus)
11. [Agente remoto (BYO)](#agente-remoto-byo)
12. [Tests y corpus](#tests-y-corpus)
13. [Estándares](#estándares)
14. [Checklist de PR](#checklist-de-pr)
15. [Release](#release)

---

## Code of Conduct

Este proyecto sigue el [Contributor Covenant](CODE_OF_CONDUCT.md).

Vulnerabilidades o bypasses reales: [SECURITY.md](SECURITY.md), no un issue público con el payload explotable.

---

## Cómo aportar

| Tipo | Qué abrir | Qué incluir |
|---|---|---|
| Falso positivo (tráfico legítimo bloqueado) | Issue — Threat Rule / Bypass | Payload sanitizado, regla/`inspector`, veredicto esperado vs real |
| Bypass (ataque que pasa) | Issue o [SECURITY.md](SECURITY.md) | Misma ficha; no publiques un exploit listo para copiar |
| Nueva familia de amenaza | Issue — New Inspector Proposal | Por qué no cabe en un inspector existente |
| Feature / store / adapter | Issue + PR | Test + CHANGELOG **1.2.0 (unreleased)** |

No subas `package.json` de versión salvo que el mantenedor pida publicar. El trabajo inédito va en CHANGELOG como **1.2.0 (unreleased)**. La línea publicada hoy es **1.1.0**.

---

## Setup

Node **≥ 18** en local. CI corre **20 y 22**.

```bash
git clone https://github.com/uranotools/urano-guard.git
cd urano-guard
npm install
npm run typecheck
npm run lint
npm test
npm run build
```

`npm test` usa `vitest run --config vitest.config.mjs`. No uses un `vitest.config.ts` CJS: rompe CI (`ERR_REQUIRE_ESM`).

Demos: [examples/README.md](examples/README.md) (`chat-app.ts`, `redis-store.ts`, `http-audit-sink.ts`, Prometheus, OTel).

---

## Lógica del sistema

Urano Guard es un **middleware in-process**. No es un WAF de red, ni un firewall de modelo, ni un SIEM.

```
HTTP (Express / Fastify / Hono / Edge / Node http)
        │
        ▼
  Adapter  ──►  GuardRequestContext  (ip, method, path, headers, body, query, senderId)
        │
        ▼
  UranoGuard.inspect()
        │
        ▼
  Evaluator (barato → caro)
        1. ThreatRegistry     whitelist / blacklist     ug:allow:  ug:block:
        2. ReplayGuard        nonce + timestamp         ug:nonce:  (setNX)
        3. Fingerprinter      repetición de cliente     ug:fp:
        4. SemanticRateLimit  campaña multi-IP          ug:rl:count:  ug:rl:ips: (sadd)
        5. CacheManager       veredicto reciente        ug:cache:  (LRU puede evictar)
        6. Inspectores        regex + normalizeInspectionText
        7. Remote agent       webhook BYO + CircuitBreaker   ug:cb:  (cas / decr / setNX)
        8. PII mask           solo si la petición se permite
        │
        ▼
  SecurityDecision { allowed, riskScore, action, reason, threats, sanitizedBody }
        │
        ├── EventBus (threatDetected / requestBlocked / requestAllowed / honeyTokenAccessed)
        ├── auditLogger (sin body, cookies ni Authorization)
        └── Adapter: 403 (sin score) | honeypot | next()
```

**Umbral de bloqueo:** `riskScore ≥ 60` (el corpus lo trata como BLOCK).

**`securityMode`**

| Modo | Efecto |
|---|---|
| `block_threats` | Bloquea si el score supera el umbral |
| `monitor_only` | Nunca bloquea; sí emite audit / EventBus / métricas. Recomendado la primera semana |
| `strict_zero_trust` | Más agresivo con desconocidos |
| `quarantine` | Retrasa en vez de 403 inmediato (`quarantineTtlMs`) |

**Fail-open vs fail-closed:** por defecto un timeout del agente remoto **no tumba** la API (`failOpen: true`). Con `failClosed: true` ese error bloquea (o el adapter responde 5xx). Los inspectores locales corren igual. No puedes poner ambos a `true`.

**`trustProxy`:** default `false`. Sin proxy propio que pise headers, `X-Forwarded-For` / `x-user-id` no son identidad.

**403:** no filtra `riskScore` ni `reason` salvo `exposeDecisionDetails: true`.

---

## APIs públicas (usar / modificar)

Todo lo público sale de `src/index.ts`. Si añades un símbolo, expórtalo ahí. No renombres ni borres exports sin nota de breaking en CHANGELOG.

### Orquestador

| API | Qué hace | Cuándo tocarla |
|---|---|---|
| `createUranoGuard(config)` | Factory. Valida config (`ConfigValidationError`) | Punto de entrada |
| `guard.inspect(ctx)` | Pipeline completo | Tests y adapters |
| `guard.ready()` | Espera seeds `ug:block:` / `ug:allow:` en el store | Antes de `listen()` con Redis |
| `guard.registerInspector(i)` | Añade un inspector extra **en caliente** | Plugins del consumidor o tests |
| `guard.block(id, ttlMs?)` | Blacklist (`Promise`) | SOC / honeypot |
| `guard.unblock(id)` | Quita el block (`Promise`) | |
| `guard.express()` / `fastify()` / `hono()` / `edge()` / `http()` | Middleware del framework | No reimplementes el adapter si ya existe |
| `guard.prometheus()` / `guard.metricsHandler()` | Texto Prometheus | Solo si `metrics` es `createPrometheusMetrics()` |
| `guard.eventBus.on(...)` | Telemetría | Integrar Datadog / Slack |
| `guard.registry` | `ThreatRegistry` | Seeds y allow/block |
| `guard.store` | `SharedStore` inyectado o `MemoryStore` | Cluster |
| `guard.honeypot` | Tarpit + honey tokens (si está en config) | Defensa activa |

### Config que ya existe (`UranoGuardConfig`)

Flags de inspectores: `promptInjection`, `maliciousUrls`, `sqlAndCommands` (sigue encendiendo SQL+CMD+XSS), `sqlInjection`, `commandInjection`, `xss`, `botFuzzing`, `piiDataMasking`, `paddingEvasion`, `jwtTampering`, `graphqlAbuse`, `maliciousUrlsAllowHosts`.

Subsistemas: `circuitBreaker`, `replayGuard`, `semanticRateLimit`, `fingerprinting`, `honeypot`, `routePolicies`, `remoteAgent`, `store`, `auditLogger`, `metrics`, `logger`, `failOpen` / `failClosed`, `blockedIdentifiers`, `whitelistedIdentifiers`.

`routePolicies`: por path/método puedes `skip: true`, cambiar `securityMode` o apagar inspectores (`/health`, webhooks ya firmados).

### Inspectores built-in

| Clase | Detecta | Dónde editar reglas |
|---|---|---|
| `PromptInjectionInspector` | Jailbreaks, DAN, ChatML, sudo/AIM | `INJECTION_RULES` en el mismo archivo |
| `SqlInjectionInspector` | SQLi (tras `stripSqlComments`) | Reglas del archivo |
| `CommandInjectionInspector` | OS / path traversal | Incluye `CMD_PATH_TRAVERSAL` |
| `XssInspector` | script / handlers (texto ya puede ir entity-decoded) | |
| `MaliciousUrlInspector` | IP/TLD/shortener/phishing | Allowlist por host |
| `BotFuzzingInspector` | UA scanner + probes | |
| `PaddingEvasionInspector` | Exploit al final/medio de bodies grandes | |
| `JwtTamperingInspector` | `alg: none`, kid traversal | |
| `GraphqlAbuseInspector` | Introspection, depth, batching | |
| `PiiDataMasker` | Enmascara en allow (no es DLP) | |

Texto de inspección: `collectInspectionText` → `normalizeInspectionText` (NFKC, zero-width, homoglyph, decode HTML acotado, `leet` opcional en prompts). Usa `matchRules` (`ruleEngine.ts`) en vez de un `RegExp` suelto.

### Store

| Método | Semántica | Lo usa |
|---|---|---|
| `get` / `set` / `delete` | KV + TTL | Cache, registry, circuit |
| `incr` | Atómico | Rate-limit counts |
| `decr` | Atómico, suelo 0 | Circuit CLOSED (decay de fallos) |
| `setNX` | Set solo si no existe | Replay nonce, probe lock |
| `cas` | Compare-and-swap | OPEN → HALF_OPEN |
| `sadd` / `smembers` | Set; TTL solo si la key no tiene expiry | IPs del rate limit |

Implementaciones: `MemoryStore` (default, LRU con pins) y `RedisSharedStore` (cliente inyectado, **cero dep Redis**). Prefijos y pins: `PINNED_STORE_PREFIXES` / `isPinnedStoreKey` en `src/types/store.ts`.

### Observabilidad

| Factory | Qué es | Qué no es |
|---|---|---|
| `createHttpAuditSink({ url })` | POST fire-and-forget del `AuditEvent` seguro | Un SIEM |
| `auditLogger: 'json'` | Una línea JSON por decisión a stdout | |
| `createPrometheusMetrics()` | Contadores in-process | OTel |
| `createOpenTelemetryMetrics({ meter })` | Contadores sobre un Meter que **tú** creas | SDK OTLP / traces |

### Utilidades que debes reutilizar (no reescribir)

`normalizeInspectionText`, `decodeHtmlEntitiesBounded`, `stripSqlComments`, `collectInspectionText`, `pickClientIp`, `pickSenderId`, `verifyHmacSignature`, `signHmac`, `sha256Hex`, `isFailClosed`, `validateConfig`, `toAuditEvent`, `matchRoutePath`, `resolveRoutePolicy`.

---

## Añadir una regla de detección

Casi nunca hace falta una clase nueva. Si el patrón es de la misma familia (otro jailbreak, otro SQLi), añade un `DetectionRule`:

1. Edita el inspector (ej. `src/inspectors/PromptInjectionInspector.ts`).
2. Nombre estable en `SCREAMING_SNAKE`: `SUDO_MODE_JAILBREAK`, `AIM_JAILBREAK`.
3. Regex **anti-ReDoS**: cuantificadores acotados, nada de `.*` anidados. `matchRules` ya hace `lastIndex = 0`.
4. Ataque en `tests/fixtures/attacks/*.json` (`id` único). JWT/GraphQL van en `jwt-graphql.json` (describe propio en `corpus.test.ts`).
5. Si puede picar texto de producto/chat, añade un caso en `tests/fixtures/benign/chat.json`.
6. `npm test`. Ataques: `allowed === false` y score ≥ 60. Benignos: allow.

```ts
{
  pattern: /\b(?:enter|enable|activate)\s+sudo\s+mode\b/i,
  name: 'SUDO_MODE_JAILBREAK',
  category: 'PROMPT_INJECTION',
  severity: 'CRITICAL',
  riskScore: 85,
  summary: 'AI directive override attempt'
}
```

---

## Añadir un inspector

Solo si es **otra familia** (otra `ThreatCategory` o un protocolo distinto).

1. Clase en `src/inspectors/` que extienda `InspectorBase`.
2. Flag en `InspectorFlags` (`src/types/config.ts`) y validación en `validateConfig.ts` si aplica.
3. Instáncialo en `UranoGuard` (array `defaultInspectors`).
4. `export` en `src/index.ts`.
5. Tests en `tests/inspectors.test.ts` + fixtures de corpus.
6. Nota en CHANGELOG (1.2.0 unreleased) y una línea en DEV_README.

```ts
import { InspectorBase } from './InspectorBase';
import { collectInspectionText } from '../utils/inspectText';
import { DetectionRule, matchRules } from './ruleEngine';

export class ExampleInspector extends InspectorBase {
    readonly name = 'ExampleInspector';
    readonly enabled: boolean;

    constructor(enabled = true) {
        super();
        this.enabled = enabled;
    }

    inspect(context) {
        if (!this.enabled) return null;
        return matchRules(context, collectInspectionText(context), RULES, 'thr_ex');
    }
}

// En la app consumidora, sin fork:
guard.registerInspector(new ExampleInspector());
```

`inspect` puede ser sync o `Promise`. Devuelve `ThreatIncident | ThreatIncident[] | null`. Categorías: usa las de `src/types/threat.ts` o `'CUSTOM'`.

---

## Añadir un adaptador

1. Extiende `AdapterBase` en `src/adapters/`.
2. `normalizeRequest` → `GuardRequestContext`. Identidad con `pickClientIp` / `pickSenderId` y `this.trustProxy()`.
3. `inspect` + `dispatchBlock` / `handleBlock`. 403 sin detalles salvo `exposeDecisionDetails`. Errores: `this.failClosed()`.
4. Método de conveniencia en `UranoGuard` (`express()`, `hono()`, …).
5. Export + test de adapter. Ejemplo en `examples/` solo si enseña un patrón nuevo; actualiza `examples/README.md`.

No copies honeypot/403 a mano: `dispatchBlock` ya encadena `onBlock`, redirect y honeypot.

---

## Store, Redis y circuit breaker

Lee [ENTERPRISE.md](ENTERPRISE.md) antes de tocar estas piezas.

**Integrar Redis (app consumidora, no en este package):**

```ts
import { createUranoGuard, RedisSharedStore } from '@uranotools/urano-guard';
import Redis from 'ioredis';

const store = new RedisSharedStore({ client: new Redis(process.env.REDIS_URL) });
const guard = createUranoGuard({ store, blockedIdentifiers: ['1.2.3.4'] });
await guard.ready();
```

ioredis entra directo. node-redis v4 necesita el wrap de ENTERPRISE (`sAdd`, `PX`/`NX`, `eval`).

**Si modificas el store en este repo:**

- Implementa el método **nuevo** en `SharedStore` (types), `MemoryStore` y `RedisSharedStore` con la **misma** semántica.
- Escrituras de cluster: `incr` / `decr` / `setNX` / `cas` / `sadd`. **Prohibido** get-then-set en el hot path.
- Redis `decr` / `cas` van por `eval` + `REDIS_DECR_LUA` / `REDIS_CAS_LUA`. No uses `defineCommand`.
- Keys nuevas que no deban morir por LRU: añádelas a `PINNED_STORE_PREFIXES`. `ug:cache:` sigue siendo evictable.
- Circuit: OPEN→HALF_OPEN = `cas`; éxito CLOSED = `decr`; un solo probe = `setNX(ug:cb:probeLock)`.
- Tests en `tests/store.test.ts` y `tests/circuitBreaker.test.ts`. Mock del cliente Redis; no exijas Redis real.

`MemoryStore` pin **no** aplica a Redis (`maxmemory-policy`). Documéntalo; no finjas que el adapter “pinea” en Redis.

---

## Audit, métricas y EventBus

**Audit (consumidor):**

```ts
createUranoGuard({
    auditLogger: createHttpAuditSink({
        url: process.env.SIEM_URL,
        headers: { 'X-Webhook-Key': process.env.SIEM_TOKEN || '' },
        timeoutMs: 2000
    })
    // o: auditLogger: 'json'
    // o: auditLogger: (event) => siem.write(event)
});
```

Campos del evento: `requestId`, `action`, `allowed`, `riskScore`, `threatCategories`, `path`, `method`, `source`, `latencyMs`. **Nunca** body, cookies ni `Authorization`. Si cambias `toAuditEvent`, mantén esa promesa y cubre `tests/httpAudit.test.ts` / `tests/enterprise.test.ts`.

**EventBus** (ya cableado desde `inspect`):

```ts
guard.eventBus.on('threatDetected', ({ threat, req }) => { /* ... */ });
guard.eventBus.on('requestBlocked', ({ decision, req }) => { /* ... */ });
guard.eventBus.on('requestAllowed', ({ decision, req }) => { /* ... */ });
guard.eventBus.on('honeyTokenAccessed', ({ token, req }) => { /* ... */ });
guard.eventBus.on('agentInvestigationComplete', ({ requestId, req, decision }) => { /* informe async */ });
```

Los listeners no deben tirar el request: `EventBus.emit` traga errores y los manda al logger.

**Métricas:** inyecta `createPrometheusMetrics()` o `createOpenTelemetryMetrics({ meter })`, o un `MetricsExporter` propio (`increment` / `observe` / `gauge`). Este paquete no instala `@opentelemetry/*`.

---

## Agente remoto (BYO)

El WAF es la capa local. El **agente** es el plus paralelo: cualquier HTTPS que tú operes (misma máquina, otra VPC, un LLM, un SOC). Contrato, `include` / `extra`, HMAC, `invokeWhen`, `analysis` / `report`: [CUSTOM_AGENT.md](CUSTOM_AGENT.md).

El agente puede devolver `analysis` y `report`. Guard los copia a `decision.agentAnalysis` / `decision.agentReport`. **No** los genera ni los mete en el audit. Tu app los manda a tickets / Slack.

Al tocar el cliente:

- `RemoteAgentClient` + `resolveRemoteAgentConfig` + `shouldInvokeRemoteWithRange`.
- El circuit breaker **comparte estado** si hay `store`; si no, es por proceso.
- Tests en `tests/remoteAgent.test.ts`. Ejemplo: `examples/custom-agent-server.ts`.
- `agentWebhookUrl` + `apiKey` siguen el payload legacy. Schema 1.0 es `remoteAgent.payload`.

---

## Tests y corpus

| Archivo | Qué cubre |
|---|---|
| `tests/corpus.test.ts` | Fixtures JSON ataque / benigno |
| `tests/inspectors.test.ts` | Reglas por inspector |
| `tests/store.test.ts` | Memory + Redis duck, pin, setNX, cas, decr |
| `tests/circuitBreaker.test.ts` | Breaker local y compartido |
| `tests/enterprise.test.ts` | validateConfig, failClosed, audit, Prometheus |
| `tests/httpAudit.test.ts` | Sink HTTP |
| `tests/remoteAgent.test.ts` | Contrato del webhook |
| `tests/replayAndCache.test.ts` | Nonce / cache |
| `tests/helpers.ts` | Usa `ctx()` para armar un `GuardRequestContext` |

Mockea `fetch` y el cliente Redis. No pidas un Redis en CI.

Tras un cambio de comportamiento: `npm test && npm run typecheck && npm run lint`.

---

## Estándares

1. **Cero dependencias de runtime.** `package.json` → `dependencies` vacío. Redis, Meter OTel y SIEM se inyectan.
2. **Hot path ≤ unos ms.** Regex auditadas contra ReDoS. Prefiere normalize + scan lineal.
3. **Fail-open por defecto.** Un throw en el agente no tumba el host salvo `failClosed`.
4. **Docs honestos.** Nada de “99%”, “Government”, “SIEM product”, “model WAF”.
5. **JSDoc solo en API pública.** Sin comentarios narrativos.
6. **Prefijos:** keys `ug:…`, incidentes `thr_…`, reglas `SCREAMING_SNAKE`.
7. No edites `.cursor/plans`. No añadas trailers `Co-authored-by: Cursor` salvo que el autor lo pida.

---

## Checklist de PR

- [ ] Test de corpus y/o unitario del comportamiento
- [ ] `npm test` && `npm run typecheck` && `npm run lint`
- [ ] Símbolo nuevo exportado en `src/index.ts`
- [ ] CHANGELOG **1.2.0 (unreleased)** si es visible al usuario
- [ ] ENTERPRISE / CUSTOM_AGENT / DEV_README si cambió ese contrato
- [ ] `examples/README.md` si añadiste un example
- [ ] Sin bump de versión salvo release pedida
- [ ] README sin claims inflados

Plantilla: [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md).

---

## Release

Solo mantenedores, cuando se acuerde publicar **1.2.0** (o el semver que toque):

1. Sube `version` en `package.json`.
2. Cierra la sección de CHANGELOG (quita “unreleased”).
3. `npm test`, `npm run lint`, `npm run build`.
4. Commit, tag `vX.Y.Z`, push del tag.
5. GitHub Release de ese tag — [publish.yml](.github/workflows/publish.yml) corre lint, tests y `npm publish --access public --provenance`.

No publiques a mano salvo que no haga falta provenance.
