import { InspectorBase } from './InspectorBase';
import { GuardRequestContext } from '../types/context';
import { ThreatIncident } from '../types/threat';
import { collectInspectionText } from '../utils/inspectText';
import { DetectionRule, matchRules } from './ruleEngine';

const CMD_RULES: DetectionRule[] = [
    { pattern: /(?:^|[\s;|&`"'])(?:sudo|chmod\s+777|rm\s+-rf|\/etc\/shadow|\/etc\/passwd)\b/i, name: 'OS_COMMAND_INJECTION', category: 'COMMAND_INJECTION', severity: 'CRITICAL', riskScore: 90, summary: 'OS command injection attempt' },
    { pattern: /\bxp_cmdshell\b/i, name: 'XP_CMDSHELL', category: 'COMMAND_INJECTION', severity: 'CRITICAL', riskScore: 90, summary: 'OS command injection attempt' },
    { pattern: /\bpowershell\b[\s\S]{0,40}-(?:enc(?:odedcommand)?|e)\b/i, name: 'POWERSHELL_ENCODED', category: 'COMMAND_INJECTION', severity: 'CRITICAL', riskScore: 88, summary: 'OS command injection attempt' },
    { pattern: /\b(?:wget|curl)\b[\s\S]{0,80}\|\s*(?:ba)?sh\b/i, name: 'CURL_PIPE_SHELL', category: 'COMMAND_INJECTION', severity: 'CRITICAL', riskScore: 90, summary: 'OS command injection attempt' },
    { pattern: /\bnc\s+-e\s+\/bin\/(?:ba)?sh\b/i, name: 'NC_REVERSE_SHELL', category: 'COMMAND_INJECTION', severity: 'CRITICAL', riskScore: 90, summary: 'OS command injection attempt' },
    { pattern: /(?:\.\.[\\/]){2,}(?:[\w.-]{1,32}[\\/]){0,8}(?:etc[\\/]hosts|windows[\\/]win\.ini|proc[\\/]self|web\.config|\.aws[\\/]credentials|id_rsa)\b/i, name: 'CMD_PATH_TRAVERSAL', category: 'COMMAND_INJECTION', severity: 'CRITICAL', riskScore: 88, summary: 'OS command injection attempt' }
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
