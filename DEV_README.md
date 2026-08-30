# @uranotools/urano-guard — DEV_README: Extensibilidad e Infraestructura Avanzada

> Guía para desarrolladores que quieren extender, personalizar o contribuir al SDK de seguridad Urano Guard.

---

## 📐 Arquitectura de Capas

```
┌────────────────────────────────────────────────────────────┐
│                    Petición Entrante                       │
└──────────────────────────┬─────────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────────┐
│                ADAPTADORES (ingress layer)                  │
│   ExpressAdapter │ FastifyAdapter │ EdgeAdapter │ HttpAdapter│
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
│  7. Remote AI Agent (BYO webhook)        (Circuit Breaker) │
│  8. Verdict Consolidation                                  │
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
Orquestador principal. Instanciar con `createUranoGuard(config)` o `new UranoGuard(config)`.

### Evaluator
Pipeline de evaluación multi-etapa. Integra todos los sistemas de defensa en orden de menor a mayor costo computacional.

### CircuitBreaker
**Patrón tri-estado:** CLOSED → OPEN → HALF_OPEN → CLOSED.
- Abre automáticamente si el agente remoto supera `latencyThresholdMs` o alcanza `failureThreshold` fallos.
- En estado OPEN, el Evaluator usa exclusivamente inspección local (sin penalizar latencia).
- Sana automáticamente tras `recoveryTimeMs` con una sonda HALF_OPEN.

```ts
circuitBreaker: {
    enabled: true,
    latencyThresholdMs: 800,   // ms máximos del agente remoto
    failureThreshold: 5,        // fallos antes de abrir
    recoveryTimeMs: 30_000      // tiempo de recuperación
}
```

### ReplayGuard
Protección anti-replay mediante **ventana de tiempo** (timestamp) + **nonce cache** (LRU 20k entradas).
- Requiere cabeceras: `x-urano-timestamp` (epoch ms) y `x-urano-nonce` (UUID único).
- Modo `strict: true` bloquea peticiones sin cabeceras; modo normal solo alerta.

```ts
replayGuard: {
    enabled: true,
    timestampWindowMs: 300_000,  // 5 min de tolerancia
    strict: true                  // bloquear si falta nonce/timestamp
}
```

### SemanticRateLimiter
Rate limiting por **intención semántica** en lugar de IP fuente. Detecta campañas de reconocimiento distribuido donde cada IP envía pocas peticiones pero con el mismo patrón de sondeo.

- La clave semántica se construye de: método + path normalizado + palabra clave de reconocimiento.
- `CAMPAIGN_DETECTED`: cuando N IPs distintas comparten el mismo patrón → bloqueo global del patrón.

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
LRU en memoria de veredictos. Latencia < 1ms en cache hit. Configurable con `cacheTtlMs`.

### ThreatRegistry
Blacklist / Whitelist en memoria con operaciones O(1). Populable en tiempo de ejecución vía `guard.block(id)` y `guard.unblock(id)`.

### EventBus
Bus de eventos pub/sub interno. Emite: `threatDetected`, `requestBlocked`, `requestAllowed`, `honeyTokenAccessed`.

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
- `verifyHmacSignature(payload, secret, signature)`: Valida firma `x-hub-signature-256`.

### mtls.ts
- `createMtlsAgent(config)`: Crea un agente HTTPS con certificado cliente para comunicación mTLS.
- `extractClientCertCN(req)`: Extrae el CN del certificado presentado por el cliente.
- `validateClientCert(req, allowedCNs)`: Verifica que el CN del cliente esté en la lista permitida.

---

## ⚙️ Configuración Completa de Referencia

```ts
import { createUranoGuard } from '@uranotools/urano-guard';

const guard = createUranoGuard({
    // Agente remoto BYO — ver CUSTOM_AGENT.md
    remoteAgent: {
        url: process.env.AGENT_URL,
        timeoutMs: 1500,
        failOpen: true,
        invokeWhen: 'local_clean',
        auth: { type: 'bearer', token: process.env.AGENT_TOKEN },
        payload: {
            include: ['method', 'path', 'body', 'localThreats'],
            extra: { app: 'api' }
        }
    },

    // Modo operativo
    securityMode: 'block_threats', // | 'strict_zero_trust' | 'monitor_only' | 'quarantine'

    // Circuit Breaker (NUEVO)
    circuitBreaker: {
        enabled: true,
        latencyThresholdMs: 800,
        failureThreshold: 5,
        recoveryTimeMs: 30_000
    },

    // Anti-Replay (NUEVO)
    replayGuard: {
        enabled: true,
        timestampWindowMs: 300_000,
        strict: true
    },

    // Semantic Rate Limiting (NUEVO)
    semanticRateLimit: {
        enabled: true,
        windowMs: 60_000,
        maxRequestsPerWindow: 60,
        campaignIpThreshold: 20
    },

    // Fingerprinting (NUEVO)
    fingerprinting: {
        enabled: true,
        suspiciousThreshold: 10
    },

    // Honeypot / Tarpit (NUEVO)
    honeypot: {
        tarpitEnabled: true,
        tarpitDelayMs: 4_000,
        honeyTokensEnabled: true,
        onHoneyTokenAccessed: (token, ctx) => console.warn('Atacante regresó:', token, ctx)
    },

    // Caché
    enableCache: true,
    cacheTtlMs: 60_000,

    // Inspectores
    inspectors: {
        promptInjection: true,
        maliciousUrls: true,
        sqlAndCommands: true,
        botFuzzing: true,
        piiDataMasking: true,
        paddingEvasion: true     // NUEVO
    },

    // Callbacks
    onThreatDetected: (threat, req) => soc.log(threat),
    onBlock: (decision, req) => metrics.increment('blocked'),
});
```

---

Agente propio (no Urano Cloud): contrato, campos `include`, HMAC y `invokeWhen` están en [CUSTOM_AGENT.md](CUSTOM_AGENT.md).

---

## 📦 Publicación y Distribución

```bash
# Compilar
npm run build

# Publicar en npm (o registro privado)
npm publish --access public

# En el proyecto consumidor
npm install @uranotools/urano-guard
```

---

## 🗺️ Hoja de Ruta de Extensiones

| Feature | Estado |
|---------|--------|
| PromptInjectionInspector | ✅ Listo |
| MaliciousUrlInspector | ✅ Listo |
| InjectionSqlCmdInspector | ✅ Listo |
| BotFuzzingInspector | ✅ Listo |
| PaddingEvasionInspector | ✅ Listo |
| CircuitBreaker (tri-estado) | ✅ Listo |
| ReplayGuard (Nonce + Timestamp) | ✅ Listo |
| SemanticRateLimiter (campaña) | ✅ Listo |
| RequestFingerprinter (comportamiento) | ✅ Listo |
| HoneypotRouter (Tarpit + HoneyTokens) | ✅ Listo |
| mTLS utilities | ✅ Listo |
| Inspector de GraphQL introspection | ✅ Listo |
| Inspector de JWT tampering | ✅ Listo |
| Adaptador Hono | ✅ Listo |
| Agente remoto BYO (CUSTOM_AGENT.md) | ✅ Listo |
| Adaptador para AWS API Gateway | 🔜 Planeado |
| Dashboard SOC en tiempo real | 🔜 Planeado |
