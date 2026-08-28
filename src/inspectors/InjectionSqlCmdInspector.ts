import { InspectorBase } from './InspectorBase';
import { GuardRequestContext } from '../types/context';
import { ThreatIncident } from '../types/threat';

const EXPLOIT_RULES = [
    { pattern: /;\s*(DROP|DELETE|ALTER|TRUNCATE)\s+TABLE/i, name: 'SQLI_DESTRUCTIVE' },
    { pattern: /UNION\s+SELECT\s+.*\s+FROM/i, name: 'SQLI_UNION_SELECT' },
    { pattern: /<script[\s\S]*?>[\s\S]*?<\/script>/i, name: 'XSS_SCRIPT_TAG' },
    { pattern: /\b(sudo|chmod\s+777|rm\s+-rf|\/etc\/shadow|\/etc\/passwd)\b/i, name: 'OS_COMMAND_INJECTION' }
];

export class InjectionSqlCmdInspector extends InspectorBase {
    readonly name = 'InjectionSqlCmdInspector';
    readonly enabled: boolean;

    constructor(enabled = true) {
        super();
        this.enabled = enabled;
    }

    inspect(context: GuardRequestContext): ThreatIncident | null {
        if (!this.enabled) return null;
        const text = typeof context.body === 'string' ? context.body : JSON.stringify(context.body || '');

        for (const rule of EXPLOIT_RULES) {
            if (rule.pattern.test(text)) {
                return {
                    id: `thr_exp_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
                    category: 'SQL_CMD_INJECTION',
                    severity: 'CRITICAL',
                    riskScore: 90,
                    summary: `Intento de inyección de código o exploit SQL/OS (${rule.name})`,
                    matchedPattern: rule.pattern.toString(),
                    detectedAt: new Date().toISOString(),
                    sender: context.senderId || context.ip
                };
            }
        }
        return null;
    }
}