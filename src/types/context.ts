import { ThreatIncident } from './threat';

export interface GuardRequestContext {
    ip: string;
    method: string;
    path: string;
    headers: Record<string, string | string[] | undefined>;
    query: Record<string, any>;
    body: any;
    rawBody?: string;
    senderId?: string;
    timestamp: number;
}

/**
 * Optional structured report produced by a **remote agent**, not by Guard.
 * Attach it to tickets, Slack, or a SOC queue. Do not render `markdown` as
 * trusted HTML without sanitizing.
 */
export interface RemoteAgentReport {
    title?: string;
    summary?: string;
    severity?: string;
    findings?: unknown[];
    markdown?: string;
    extra?: Record<string, unknown>;
}

export interface SecurityDecision {
    allowed: boolean;
    action: 'ALLOW' | 'BLOCK' | 'REDIRECT' | 'QUARANTINE' | 'MONITOR';
    riskScore: number; // 0 - 100
    threats: ThreatIncident[];
    reason?: string;
    redirectUrl?: string;
    sanitizedBody?: any;
    latencyMs: number;
    source: 'CACHE' | 'LOCAL_INSPECTOR' | 'REMOTE_AGENT' | 'FALLBACK';
    /** Free-text analysis from the remote agent (passthrough). */
    agentAnalysis?: string;
    /** Structured report from the remote agent (passthrough). */
    agentReport?: RemoteAgentReport;
    /** Sync hop returned; a background investigate is still running. */
    investigationPending?: boolean;
}