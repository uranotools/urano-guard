export type ThreatSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type ThreatCategory = 
    | 'PROMPT_INJECTION'
    | 'MALICIOUS_URL'
    | 'BOT_FUZZING'
    | 'SQL_CMD_INJECTION'
    | 'PII_EXPOSURE'
    | 'BLACKLISTED'
    | 'REMOTE_AGENT_VERDICT'
    | 'CUSTOM';

export interface ThreatIncident {
    id: string;
    category: ThreatCategory;
    severity: ThreatSeverity;
    riskScore: number; // 0 - 100
    summary: string;
    matchedPattern?: string;
    detectedAt: string;
    sender?: string;
    details?: any;
}