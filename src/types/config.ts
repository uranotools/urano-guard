import { ThreatIncident } from './threat';
import { GuardRequestContext, SecurityDecision } from './context';

export type SecurityMode = 'block_threats' | 'monitor_only' | 'strict_zero_trust' | 'quarantine';
export type DefaultAction = 'block' | 'monitor' | 'quarantine' | 'allow';

export type ThreatCallback = (threat: ThreatIncident, reqCtx: GuardRequestContext) => void | Promise<void>;
export type BlockHandler = (decision: SecurityDecision, reqCtx: GuardRequestContext) => any | Promise<any>;
export type RedirectHandler = (decision: SecurityDecision, reqCtx: GuardRequestContext) => string | Promise<string>;

export interface UranoGuardConfig {
    // ─── Conexión con Agente Urano ─────────────────────────────────────────
    /** URL del Webhook del Agente Urano (Cloud o Local en puerto 6274) */
    agentWebhookUrl?: string;
    /** Token / API Key de autenticación con el Webhook de Urano */
    apiKey?: string;
    /** Secreto HMAC para validar firmas entrantes (x-hub-signature-256) */
    incomingSecret?: string;
    /** Timeout en ms para la consulta con el Agente Urano (default: 1500ms) */
    timeoutMs?: number;
    /** Si true, en caso de fallo del servidor de Urano se permite el paso (default: true) */
    failOpen?: boolean;

    // ─── Modo de Operación ─────────────────────────────────────────────────
    /** Modo de seguridad del Gateway */
    securityMode?: SecurityMode;
    /** Acción predeterminada al detectar una amenaza */
    defaultAction?: DefaultAction;

    // ─── Caché LRU ────────────────────────────────────────────────────────
    /** Habilita caché en memoria de veredictos recientes para latencia < 1ms (default: true) */
    enableCache?: boolean;
    /** Tiempo de vida de la caché en ms (default: 60000 = 1 min) */
    cacheTtlMs?: number;

    // ─── Listas de Control ────────────────────────────────────────────────
    /** Lista de IPs o identificadores en lista negra permanente */
    blockedIdentifiers?: string[];
    /** Lista de IPs o identificadores en lista blanca permanente */
    whitelistedIdentifiers?: string[];

    // ─── Inspectores Locales ──────────────────────────────────────────────
    inspectors?: {
        promptInjection?: boolean;
        maliciousUrls?: boolean;
        sqlAndCommands?: boolean;
        botFuzzing?: boolean;
        piiDataMasking?: boolean;
        /** Habilita detección de Padding Evasion en payloads grandes (default: true) */
        paddingEvasion?: boolean;
    };

    // ─── Circuit Breaker ─────────────────────────────────────────────────
    circuitBreaker?: {
        /** Habilita el Circuit Breaker adaptativo (default: true) */
        enabled?: boolean;
        /** Latencia máxima en ms que activa el circuit breaker (default: 800) */
        latencyThresholdMs?: number;
        /** Número de fallos consecutivos antes de abrir el circuito (default: 5) */
        failureThreshold?: number;
        /** Tiempo en ms hasta intentar recuperación (default: 30000) */
        recoveryTimeMs?: number;
    };

    // ─── Anti-Replay ─────────────────────────────────────────────────────
    replayGuard?: {
        /** Habilita la protección anti-replay (default: false, requiere cabeceras x-urano-timestamp y x-urano-nonce) */
        enabled?: boolean;
        /** Ventana de tolerancia de tiempo en ms (default: 300000 = 5 min) */
        timestampWindowMs?: number;
        /** Si true, BLOQUEA peticiones sin timestamp/nonce; si false, solo ALERTA (default: false) */
        strict?: boolean;
    };

    // ─── Semantic Rate Limiting ───────────────────────────────────────────
    semanticRateLimit?: {
        /** Habilita el rate limiting semántico (default: false) */
        enabled?: boolean;
        /** Ventana de tiempo en ms (default: 60000) */
        windowMs?: number;
        /** Máximo de requests por ventana por clave semántica (default: 60) */
        maxRequestsPerWindow?: number;
        /** Umbral de IPs distintas para detectar campaña coordinada (default: 20) */
        campaignIpThreshold?: number;
    };

    // ─── Honeypot & Tarpit ────────────────────────────────────────────────
    honeypot?: {
        /** Habilita el Tarpit (retarda la respuesta al atacante) (default: false) */
        tarpitEnabled?: boolean;
        /** Retardo artificial en ms para el atacante (default: 4000) */
        tarpitDelayMs?: number;
        /** Genera honey-tokens rastreables en respuestas falsas (default: false) */
        honeyTokensEnabled?: boolean;
        /** Callback cuando un atacante regresa con un honey-token */
        onHoneyTokenAccessed?: (token: string, context: any) => void;
    };

    // ─── Fingerprinting de Atacantes ──────────────────────────────────────
    fingerprinting?: {
        /** Habilita el rastreo de comportamiento de atacantes entre requests (default: false) */
        enabled?: boolean;
        /** Número de veces que un fingerprint debe aparecer para considerarse amenaza (default: 10) */
        suspiciousThreshold?: number;
    };

    // ─── Callbacks de Ciclo de Vida ───────────────────────────────────────
    onThreatDetected?: ThreatCallback;
    onBlock?: BlockHandler;
    onRedirect?: RedirectHandler;
}
