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
}