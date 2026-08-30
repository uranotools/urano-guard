import { ThreatIncident } from './threat';
import { GuardRequestContext, SecurityDecision } from './context';
import { GuardLogger, MetricsExporter } from './logger';
import { RemoteAgentConfig } from './remoteAgent';

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
    failOpen?: boolean;

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

    onThreatDetected?: ThreatCallback;
    onBlock?: BlockHandler;
    onRedirect?: RedirectHandler;
}
