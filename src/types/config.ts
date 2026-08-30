import { ThreatIncident } from './threat';
import { GuardRequestContext, SecurityDecision } from './context';
import { GuardLogger, MetricsExporter } from './logger';
import { RemoteAgentConfig } from './remoteAgent';
import { AuditLogger } from './audit';
import { SharedStore } from './store';
import { CrowdSecConfig } from './crowdsec';

export type SecurityMode = 'block_threats' | 'monitor_only' | 'strict_zero_trust' | 'quarantine';
export type DefaultAction = 'block' | 'monitor' | 'quarantine' | 'allow';

export type ThreatCallback = (threat: ThreatIncident, reqCtx: GuardRequestContext) => void | Promise<void>;
export type BlockHandler = (decision: SecurityDecision, reqCtx: GuardRequestContext) => any | Promise<any>;
export type RedirectHandler = (decision: SecurityDecision, reqCtx: GuardRequestContext) => string | Promise<string>;

export interface InspectorFlags {
    promptInjection?: boolean;
    maliciousUrls?: boolean;
    sqlAndCommands?: boolean;
    sqlInjection?: boolean;
    commandInjection?: boolean;
    xss?: boolean;
    botFuzzing?: boolean;
    piiDataMasking?: boolean;
    paddingEvasion?: boolean;
    jwtTampering?: boolean;
    graphqlAbuse?: boolean;
    maliciousUrlsAllowHosts?: string[];
}

export interface RoutePolicy {
    path: string;
    method?: string;
    skip?: boolean;
    securityMode?: SecurityMode;
    inspectors?: InspectorFlags;
}

export interface UranoGuardConfig {
    agentWebhookUrl?: string;
    apiKey?: string;
    incomingSecret?: string;
    timeoutMs?: number;
    /** Default true. Opposite of failClosed. Remote/adapter errors allow the request. */
    failOpen?: boolean;
    /**
     * Default false. When true, remote-agent and adapter evaluation errors BLOCK
     * instead of allowing. Mutually exclusive with failOpen: true.
     */
    failClosed?: boolean;

    remoteAgent?: RemoteAgentConfig;

    securityMode?: SecurityMode;
    defaultAction?: DefaultAction;
    exposeDecisionDetails?: boolean;
    trustProxy?: boolean;
    maxBodyBytes?: number;
    quarantineTtlMs?: number;

    enableCache?: boolean;
    cacheTtlMs?: number;

    blockedIdentifiers?: string[];
    whitelistedIdentifiers?: string[];

    inspectors?: InspectorFlags;
    routePolicies?: RoutePolicy[];

    circuitBreaker?: {
        enabled?: boolean;
        latencyThresholdMs?: number;
        failureThreshold?: number;
        recoveryTimeMs?: number;
        probeSuccessThreshold?: number;
    };

    replayGuard?: {
        enabled?: boolean;
        timestampWindowMs?: number;
        strict?: boolean;
    };

    semanticRateLimit?: {
        enabled?: boolean;
        windowMs?: number;
        maxRequestsPerWindow?: number;
        campaignIpThreshold?: number;
    };

    honeypot?: {
        tarpitEnabled?: boolean;
        tarpitDelayMs?: number;
        honeyTokensEnabled?: boolean;
        onHoneyTokenAccessed?: (token: string, context: any) => void;
    };

    fingerprinting?: {
        enabled?: boolean;
        suspiciousThreshold?: number;
    };

    logger?: GuardLogger;
    metrics?: MetricsExporter;
    /**
     * Structured audit sink. Pass a function or `'json'` for JSON-lines on stdout.
     * Events never include raw body, cookies, or Authorization.
     */
    auditLogger?: AuditLogger | 'json';
    /** Shared cache + rate-limit store. Defaults to in-process MemoryStore. */
    store?: SharedStore;
    /**
     * Optional CrowdSec LAPI. Off unless set. Bouncer API key is only
     * required when you use `url` (CrowdSec’s protocol). Inject `lookup` to avoid it.
     */
    crowdsec?: CrowdSecConfig;

    onThreatDetected?: ThreatCallback;
    onBlock?: BlockHandler;
    onRedirect?: RedirectHandler;
}
