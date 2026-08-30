# @uranotools/urano-guard — DEV_README: Extensibilidad e Infraestructura Avanzada

> Guía para desarrolladores que quieren extender, personalizar o contribuir al SDK de seguridad Urano Guard.

Contrato de producción / Redis: [ENTERPRISE.md](ENTERPRISE.md). Agente (análisis + reportes): [CUSTOM_AGENT.md](CUSTOM_AGENT.md). PRs: [CONTRIBUTING.md](CONTRIBUTING.md). IDEs con IA: [AGENTS.md](AGENTS.md).

---

## 📐 Arquitectura de Capas

```
┌────────────────────────────────────────────────────────────┐
│                    Petición Entrante                       │
└──────────────────────────┬─────────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────────┐
│                ADAPTADORES (ingress layer)                  │
│   Express │ Fastify │ Hono │ Edge │ Http (Node nativo)     │
│   ─ Normaliza la petición a GuardRequestContext ─          │
└──────────────────────────┬─────────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────────┐
│                  UranoGuard (orquestador)                   │
│  Instancia y conecta todos los subsistemas                 │
└──────────────────────────┬─────────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────────┐
│                  Evaluator (pipeline central)               │
│                                                            │
│  1. Whitelist / Blacklist check          (ThreatRegistry)  │
│  2. Anti-Replay                          (ReplayGuard)     │
│  3. Behavioral Fingerprinting            (RequestFinger.)  │
│  4. Semantic Rate Limiting               (SemanticRateL.)  │
│  5. LRU Decision Cache                   (CacheManager)    │
│  6. Local Heuristic Inspectors           (InspectorBase[]) │
│     ├─ PromptInjectionInspector                           │
│     ├─ MaliciousUrlInspector                              │
│     ├─ Sql / Command / XSS inspectors                     │
│     ├─ BotFuzzingInspector                                │
│     ├─ JwtTamperingInspector / GraphqlAbuseInspector      │
│     └─ PaddingEvasionInspector          (anti-evasion)    │
│  7. Agente remoto (cualquier HTTPS)      (Circuit Breaker) │
│     + analysis / report → decision.agentAnalysis/Report    │
│  8. Verdict Consolidation                                  │
│                                                            │
│  Store (MemoryStore | RedisSharedStore | el tuyo)          │
│  Audit (json | callback | createHttpAuditSink)             │
│  Métricas (Prometheus | OTel Meter inyectado)              │
└──────────────────────────┬─────────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────────┐
│              Defensa Activa (opcional)                      │
│         HoneypotRouter: Tarpit + Honey-Tokens              │
└──────────────────────────┬─────────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────────┐
│              EventBus: onThreatDetected, onBlock, ...       │
└────────────────────────────────────────────────────────────┘
```

---

## 🔩 Módulos del Núcleo (src/core/)

### UranoGuard
Orquestador. `createUranoGuard(config)` valida con `validateConfig` (lanza `ConfigValidationError`).

| Método | Uso |
|---|---|
| `inspect(ctx)` | Pipeline completo |
| `ready()` | Espera seeds `ug:block:` / `ug:allow:` (útil con Redis antes de `listen()`) |
| `registerInspector(i)` | Inspector extra en caliente |
| `block(id, ttlMs?)` / `unblock(id)` | Promises — van al store |
| `express()` / `fastify()` / `hono()` / `edge()` / `http()` | Adapters |
| `prometheus()` / `metricsHandler()` | Scrape si `metrics` es `createPrometheusMetrics()` |
| `eventBus.on(...)` | `threatDetected`, `requestBlocked`, `requestAllowed`, `honeyTokenAccessed` |

### Evaluator
Pipeline barato → caro. Consolida local + remoto. Un `ALLOW` remoto **no** deshace un `BLOCK` local salvo `monitor_only`. Copia `agentAnalysis` / `agentReport` del agente a la decisión.

### SharedStore (`MemoryStore` / `RedisSharedStore`)
Todo el estado de cluster pasa por aquí (Promesas). Default: `MemoryStore` (mismo proceso). Varios procesos: inyecta `RedisSharedStore` con **tu** cliente (este package no depende de `ioredis` / `redis`).

Métodos: `get` / `set` / `delete` / `incr` / `decr` / `setNX` / `cas` / `sadd` / `smembers`.

Prefijos: `ug:cache:`, `ug:rl:`, `ug:nonce:`, `ug:block:`, `ug:allow:`, `ug:fp:`, `ug:cb:`. `PINNED_STORE_PREFIXES` no los evicta el LRU de MemoryStore (`ug:cache:` sí). Detalle y wrap de node-redis: [ENTERPRISE.md](ENTERPRISE.md).

```ts
import { createUranoGuard, RedisSharedStore } from '@uranotools/urano-guard';
import Redis from 'ioredis';

const store = new RedisSharedStore({ client: new Redis(process.env.REDIS_URL) });
const guard = createUranoGuard({ store, blockedIdentifiers: ['1.2.3.4'] });
await guard.ready();
```

### CircuitBreaker
**Patrón tri-estado:** CLOSED → OPEN → HALF_OPEN → CLOSED.
- Abre si el agente supera `latencyThresholdMs` o `failureThreshold` fallos.
- En OPEN el Evaluator se queda en inspección local.
- Con `store`: estado en `ug:cb:`. OPEN→HALF_OPEN es `cas`; decay de fallos es `decr`; un solo probe cluster-wide es `setNX(ug:cb:probeLock)`. Sin store, sigue in-process.

```ts
circuitBreaker: {
    enabled: true,
    latencyThresholdMs: 800,   // ms máximos del agente remoto
    failureThreshold: 5,        // fallos antes de abrir
    recoveryTimeMs: 30_000      // tiempo de recuperación
}
```

### ReplayGuard
Ventana de tiempo (`x-urano-timestamp`) + nonce (`x-urano-nonce`) con `setNX(ug:nonce:)`. El segundo claim concurrente es `REPLAY_DETECTED`. `strict: true` bloquea si faltan cabeceras.

```ts
replayGuard: {
    enabled: true,
    timestampWindowMs: 300_000,  // 5 min de tolerancia
    strict: true                  // bloquear si falta nonce/timestamp
}
```

### SemanticRateLimiter
Rate limiting por **intención semántica** en lugar de IP fuente. Detecta campañas de reconocimiento distribuido donde cada IP envía pocas peticiones pero con el mismo patrón de sondeo.

- Clave: método + path normalizado + palabra de reconocimiento.
- Conteos: `incr(ug:rl:count:)`. IPs distintas: `sadd` / `smembers` (`ug:rl:ips:`), TTL que no se desliza.
- `CAMPAIGN_DETECTED` cuando N IPs comparten el patrón.

```ts
semanticRateLimit: {
    enabled: true,
    windowMs: 60_000,
    maxRequestsPerWindow: 60,
    campaignIpThreshold: 20      // IPs distintas con mismo patrón = campaña
}
```

### RequestFingerprinter
Genera **fingerprints de comportamiento** basados en User-Agent, cabeceras de negociación y estructura de petición.
Detecta al mismo atacante aunque cambie de IP (rotación de proxies/Tor).

```ts
fingerprinting: {
    enabled: true,
    suspiciousThreshold: 10      // veces que un fingerprint activa el bloqueo
}
```

### HoneypotRouter
**Defensa activa** contra atacantes confirmados. No responde con 403 inmediato (que enseña al atacante), sino que:
1. **Tarpit**: retarda la respuesta N ms para desperdiciar los recursos del bot.
2. **Honey-tokens**: responde con datos falsos pero rastreables. Si el atacante usa esos datos en peticiones futuras, se detecta automáticamente.

```ts
honeypot: {
    tarpitEnabled: true,
    tarpitDelayMs: 4_000,
    honeyTokensEnabled: true,
    onHoneyTokenAccessed: (token, ctx) => soc.alert(token, ctx)
}
```

### CacheManager
Veredictos en `ug:cache:` (el LRU de MemoryStore **sí** puede evictar estas keys). `cacheTtlMs`. Hash SHA-256 del body completo.

### ThreatRegistry
Allow/block en `ug:allow:` / `ug:block:`. Seeds del constructor se esperan (`inspect` ya espera; opcional `await guard.ready()`). `block` / `unblock` son Promises.

### EventBus
`threatDetected`, `requestBlocked`, `requestAllowed`, `honeyTokenAccessed`. Los listeners no deben tirar el request.

### Audit
`auditLogger: 'json' | (event) => void | createHttpAuditSink({ url })`. Evento seguro: `requestId`, `action`, `allowed`, `riskScore`, `threatCategories`, `path`, `method`, `source`, `latencyMs`. **Nunca** body, cookies, `Authorization`, ni `agentReport`.

```ts
createUranoGuard({
    auditLogger: createHttpAuditSink({
        url: process.env.SIEM_URL,
        headers: { 'X-Webhook-Key': process.env.SIEM_TOKEN || '' }
    })
});
```

### Métricas
- `createPrometheusMetrics()` → `guard.prometheus()` / `guard.metricsHandler()`.
- `createOpenTelemetryMetrics({ meter })` — tú creas el Meter; este package no instala `@opentelemetry/*`.
- O un `MetricsExporter` propio (`increment` / `observe` / `gauge`).

No hay traces/spans.

### failOpen / failClosed
Default fail-open: timeout o JSON inválido del agente no tumba la API. `failClosed: true` bloquea (o el adapter responde 5xx). Mutuamente excluyentes. Los inspectores locales corren igual. `trustProxy` default `false`.

---

## 🔍 Inspectores (src/inspectors/)

| Inspector | Detecta | Score |
|-----------|---------|-------|
| PromptInjectionInspector | Inyección de prompts en LLMs | 85 |
| MaliciousUrlInspector | URLs sospechosas (IP/TLD/shortener=45, phishing=70) | 45–70 |
| SqlInjectionInspector | SQLi clásica | 85–90 |
| CommandInjectionInspector | OS / xp_cmdshell | 90 |
| XssInspector | script / javascript: / event handlers | 70–80 |
| BotFuzzingInspector | Scanner UA + path probe / entropy (no JWT/JSON solo) | 65 |
| **PaddingEvasionInspector** | Código malicioso oculto al final/medio de payloads grandes | 92 |
| JwtTamperingInspector | `alg: none`, kid traversal | 80–90 |
| GraphqlAbuseInspector | Introspection, depth, batching | 65–70 |

Texto: `collectInspectionText` → `normalizeInspectionText` (NFKC, zero-width, homoglyph, decode HTML acotado; `leet` en prompts). SQL: `stripSqlComments`. Reglas nuevas recientes: `SUDO_MODE_JAILBREAK`, `AIM_JAILBREAK`, `CMD_PATH_TRAVERSAL`. Corpus: `tests/fixtures/attacks/` y `benign/`.

### Agregar un inspector personalizado

```ts
import { InspectorBase, GuardRequestContext, ThreatIncident } from '@uranotools/urano-guard';

export class MiInspector extends InspectorBase {
    readonly name = 'MiInspector';

    inspect(context: GuardRequestContext): ThreatIncident | null {
        if (context.body?.includes('malicious_pattern')) {
            return {
                id: `thr_custom_${Date.now()}`,
                category: 'CUSTOM',
                severity: 'HIGH',
                riskScore: 75,
                summary: 'Patrón personalizado detectado.',
                detectedAt: new Date().toISOString(),
                sender: context.ip
            };
        }
        return null;
    }
}

const guard = createUranoGuard({ ... });
guard.registerInspector(new MiInspector());
```

---

## 🔌 Adaptadores (src/adapters/)

| Adaptador | Framework / Runtime |
|-----------|---------------------|
| ExpressAdapter | Express.js (middleware) |
| FastifyAdapter | Fastify (hook preHandler) |
| EdgeAdapter | Cloudflare Workers, Vercel Edge |
| HttpAdapter | Node.js http/https nativo |
| HonoAdapter | Hono (`guard.hono()`) |

### Agregar un adaptador personalizado

```ts
import { AdapterBase, GuardRequestContext } from '@uranotools/urano-guard';

export class HapiAdapter extends AdapterBase {
    middleware() {
        return {
            method: 'preHandler' as any,
            assign: 'security',
            handler: async (request: any) => {
                const ctx: GuardRequestContext = {
                    ip: request.info.remoteAddress,
                    method: request.method.toUpperCase(),
                    path: request.path,
                    headers: request.headers,
                    body: request.payload,
                    senderId: request.auth?.credentials?.id,
                    timestamp: new Date().toISOString()
                };
                return this.guard.inspect(ctx);
            }
        };
    }
}
```

---

## 🛡️ Utilidades de Seguridad (src/utils/)

### crypto.ts
- `verifyHmacSignature`, `signHmac`, `sha256Hex`, `randomToken`.

### inspectText.ts
- `collectInspectionText`, `normalizeInspectionText`, `stripSqlComments`, `decodeHtmlEntitiesBounded`, `stringifySafe`.

### identity.ts
- `pickClientIp`, `pickSenderId` — respetan `trustProxy`.

### mtls.ts
- `createMtlsAgent`, `extractClientCertCN`, `validateClientCert`.

---

## ⚙️ Configuración Completa de Referencia

```ts
import {
    createUranoGuard,
    createHttpAuditSink,
    createPrometheusMetrics,
    RedisSharedStore
} from '@uranotools/urano-guard';

const guard = createUranoGuard({
    securityMode: 'block_threats', // empieza con monitor_only en prod
    trustProxy: false,
    exposeDecisionDetails: false,
    failOpen: true,
    // failClosed: false,
    maxBodyBytes: 256 * 1024,

    // store: new RedisSharedStore({ client }),
    auditLogger: createHttpAuditSink({ url: process.env.SIEM_URL }),
    metrics: createPrometheusMetrics(),
    // crowdsec: { url: process.env.CROWDSEC_LAPI, apiKey: process.env.CROWDSEC_KEY },

    remoteAgent: {
        url: process.env.AGENT_URL, // omitir = 100% local
        timeoutMs: 1500,
        invokeWhen: 'local_clean',
        auth: { type: 'bearer', token: process.env.AGENT_TOKEN },
        payload: {
            include: ['method', 'path', 'body', 'localThreats'],
            extra: { app: 'api' }
        }
    },

    circuitBreaker: {
        enabled: true,
        latencyThresholdMs: 800,
        failureThreshold: 5,
        recoveryTimeMs: 30_000
    },

    replayGuard: {
        enabled: true,
        timestampWindowMs: 300_000,
        strict: true
    },

    semanticRateLimit: {
        enabled: true,
        windowMs: 60_000,
        maxRequestsPerWindow: 60,
        campaignIpThreshold: 20
    },

    fingerprinting: {
        enabled: true,
        suspiciousThreshold: 10
    },

    honeypot: {
        tarpitEnabled: true,
        tarpitDelayMs: 4_000,
        honeyTokensEnabled: true,
        onHoneyTokenAccessed: (token, ctx) => console.warn('Atacante regresó:', token, ctx)
    },

    routePolicies: [
        { path: '/health', method: 'GET', skip: true }
    ],

    enableCache: true,
    cacheTtlMs: 60_000,
    blockedIdentifiers: [],
    whitelistedIdentifiers: [],

    inspectors: {
        promptInjection: true,
        maliciousUrls: true,
        sqlAndCommands: true, // enciende SQL + CMD + XSS
        sqlInjection: true,
        commandInjection: true,
        xss: true,
        botFuzzing: true,
        piiDataMasking: true,
        paddingEvasion: true,
        jwtTampering: true,
        graphqlAbuse: true,
        maliciousUrlsAllowHosts: ['api.internal.example']
    },

    onThreatDetected: (threat, req) => soc.log(threat),
    onBlock: (decision, req) => {
        if (decision.agentReport) soc.ticket(decision.agentReport);
    }
});

await guard.ready();
```

El agente puede devolver `analysis` y `report` → `decision.agentAnalysis` / `decision.agentReport` si están en `response.include`. `NEED` + `onRequest` / skills; `maxFollowUps` (1–4); `memory` en el store; `investigateAsync` para no bloquear el request. EventBus: `agentInvestigationComplete`. Contrato: [CUSTOM_AGENT.md](CUSTOM_AGENT.md).

---

## 📦 Publicación y Distribución

```bash
npm test
npm run typecheck
npm run lint
npm run build
```

Publicar: bump en `package.json`, CHANGELOG, tag `vX.Y.Z` y GitHub Release (`publish.yml` hace `npm publish --provenance`). No publiques a mano salvo que no haga falta provenance. Hoy `package.json` está en **1.2.1**.

---

## 🗺️ Hoja de Ruta de Extensiones

| Feature | Estado |
|---------|--------|
| Inspectores (prompt, URL, SQL/CMD/XSS, bot, padding, JWT, GraphQL) | ✅ Listo |
| CircuitBreaker (in-process + store `cas`/`decr`/`setNX`) | ✅ Listo |
| ReplayGuard (`setNX`), SemanticRateLimiter (`sadd`), fingerprints | ✅ Listo |
| SharedStore / MemoryStore pin / RedisSharedStore | ✅ 1.2.1 |
| `failClosed`, validateConfig, audit + `createHttpAuditSink` | ✅ 1.2.1 |
| Prometheus + OTel Meter inyectado | ✅ 1.2.1 |
| Agente BYO + passthrough `analysis` / `report` | ✅ Listo |
| Adaptador Hono | ✅ Listo |
| Adaptador AWS API Gateway | 🔜 Planeado |
| Plantillas / multi-sink de reportes (lado agente) | 🔜 El agente, no este package |
