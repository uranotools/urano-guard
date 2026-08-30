import { InspectorBase } from './InspectorBase';
import { GuardRequestContext } from '../types/context';
import { ThreatIncident } from '../types/threat';
import { collectInspectionText } from '../utils/inspectText';
import { DetectionRule, matchRules } from './ruleEngine';

const CMD_RULES: DetectionRule[] = [
    { pattern: /(?:^|[\s;|&`"'])(?:sudo|chmod\s+777|rm\s+-rf|\/etc\/shadow|\/etc\/passwd)\b/i, name: 'OS_COMMAND_INJECTION', category: 'COMMAND_INJECTION', severity: 'CRITICAL', riskScore: 90, summary: 'OS command injection attempt' },
    { pattern: /\bxp_cmdshell\b/i, name: 'XP_CMDSHELL', category: 'COMMAND_INJECTION', severity: 'CRITICAL', riskScore: 90, summary: 'OS command injection attempt' }
];

export class CommandInjectionInspector extends InspectorBase {
    readonly name = 'CommandInjectionInspector';
    readonly enabled: boolean;

    constructor(enabled = true) {
        super();
        this.enabled = enabled;
    }

    inspect(context: GuardRequestContext): ThreatIncident[] | null {
        if (!this.enabled) return null;
        const hits = matchRules(context, collectInspectionText(context), CMD_RULES, 'thr_cmd');
        return hits.length ? hits : null;
    }
}
