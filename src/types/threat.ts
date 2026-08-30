export type ThreatSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type ThreatCategory =
    | 'PROMPT_INJECTION'
    | 'MALICIOUS_URL'
    | 'BOT_FUZZING'
    | 'SQL_CMD_INJECTION'
    | 'SQL_INJECTION'
    | 'COMMAND_INJECTION'
    | 'XSS'
    | 'JWT_TAMPERING'
    | 'GRAPHQL_ABUSE'
    | 'PII_EXPOSURE'
    | 'BLACKLISTED'
    | 'REMOTE_AGENT_VERDICT'
    | 'CUSTOM';

export interface ThreatIncident {
    id: string;
    category: ThreatCategory;
    severity: ThreatSeverity;
    riskScore: number;
    summary: string;
    matchedPattern?: string;
    detectedAt: string;
    sender?: string;
    details?: any;
}

export function newIncidentId(prefix: string): string {
    return `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}
