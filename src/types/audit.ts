import { SecurityDecision } from './context';
import { ThreatCategory } from './threat';

/**
 * Structured audit record. Must never include raw body, cookies, or Authorization.
 */
export interface AuditEvent {
    requestId: string;
    action: SecurityDecision['action'];
    allowed: boolean;
    riskScore: number;
    threatCategories: ThreatCategory[];
    path: string;
    method: string;
    source: SecurityDecision['source'];
    latencyMs: number;
}

export type AuditLogger = (event: AuditEvent) => void;

export function createJsonLineAuditLogger(write: (line: string) => void = console.info): AuditLogger {
    return (event) => {
        write(JSON.stringify({
            ts: new Date().toISOString(),
            type: 'urano_guard.audit',
            requestId: event.requestId,
            action: event.action,
            allowed: event.allowed,
            riskScore: event.riskScore,
            threatCategories: event.threatCategories,
            path: event.path,
            method: event.method,
            source: event.source,
            latencyMs: event.latencyMs
        }));
    };
}

export function resolveAuditLogger(auditLogger?: AuditLogger | 'json'): AuditLogger | undefined {
    if (!auditLogger) return undefined;
    if (auditLogger === 'json') return createJsonLineAuditLogger();
    return auditLogger;
}

export function toAuditEvent(
    requestId: string,
    method: string,
    path: string,
    decision: SecurityDecision
): AuditEvent {
    const categories = new Set<ThreatCategory>();
    for (const threat of decision.threats) {
        categories.add(threat.category);
    }
    return {
        requestId,
        action: decision.action,
        allowed: decision.allowed,
        riskScore: decision.riskScore,
        threatCategories: [...categories],
        path,
        method,
        source: decision.source,
        latencyMs: decision.latencyMs
    };
}
