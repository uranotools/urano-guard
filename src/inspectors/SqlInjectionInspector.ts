import { InspectorBase } from './InspectorBase';
import { GuardRequestContext } from '../types/context';
import { ThreatIncident } from '../types/threat';
import { collectInspectionText, stripSqlComments } from '../utils/inspectText';
import { DetectionRule, matchRules } from './ruleEngine';

const SQL_RULES: DetectionRule[] = [
    { pattern: /;\s*(DROP|DELETE|ALTER|TRUNCATE)\s+TABLE\b/i, name: 'SQLI_DESTRUCTIVE', category: 'SQL_INJECTION', severity: 'CRITICAL', riskScore: 90, summary: 'SQL injection attempt' },
    { pattern: /UNION\s+SELECT\s[\s\S]{0,200}\sFROM\b/i, name: 'SQLI_UNION_SELECT', category: 'SQL_INJECTION', severity: 'CRITICAL', riskScore: 90, summary: 'SQL injection attempt' },
    { pattern: /('\s*OR\s+'?1'?\s*=\s*'?1)|(\bOR[\s+]+1[\s+]*=[\s+]*1\b)/i, name: 'SQLI_OR_TAUTOLOGY', category: 'SQL_INJECTION', severity: 'HIGH', riskScore: 85, summary: 'SQL injection attempt' },
    { pattern: /\bSLEEP\s*\(\s*\d{1,4}\s*\)/i, name: 'SQLI_SLEEP', category: 'SQL_INJECTION', severity: 'HIGH', riskScore: 85, summary: 'SQL injection attempt' },
    { pattern: /\b(xp_cmdshell|information_schema)\b/i, name: 'SQLI_SYS', category: 'SQL_INJECTION', severity: 'HIGH', riskScore: 88, summary: 'SQL injection attempt' }
];

export class SqlInjectionInspector extends InspectorBase {
    readonly name = 'SqlInjectionInspector';
    readonly enabled: boolean;

    constructor(enabled = true) {
        super();
        this.enabled = enabled;
    }

    inspect(context: GuardRequestContext): ThreatIncident[] | null {
        if (!this.enabled) return null;
        const hits = matchRules(context, stripSqlComments(collectInspectionText(context)), SQL_RULES, 'thr_sql');
        return hits.length ? hits : null;
    }
}
