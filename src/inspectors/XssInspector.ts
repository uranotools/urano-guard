import { InspectorBase } from './InspectorBase';
import { GuardRequestContext } from '../types/context';
import { ThreatIncident } from '../types/threat';
import { collectInspectionText } from '../utils/inspectText';
import { DetectionRule, matchRules } from './ruleEngine';

const XSS_RULES: DetectionRule[] = [
    { pattern: /<script\b[\s\S]{0,2000}?>/i, name: 'XSS_SCRIPT_TAG', category: 'XSS', severity: 'HIGH', riskScore: 80, summary: 'Cross-site scripting attempt' },
    { pattern: /javascript\s*:/i, name: 'XSS_JAVASCRIPT_URI', category: 'XSS', severity: 'HIGH', riskScore: 70, summary: 'Cross-site scripting attempt' },
    { pattern: /vbscript\s*:/i, name: 'XSS_VBSCRIPT_URI', category: 'XSS', severity: 'HIGH', riskScore: 70, summary: 'Cross-site scripting attempt' },
    { pattern: /data:text\/html/i, name: 'XSS_DATA_HTML', category: 'XSS', severity: 'HIGH', riskScore: 75, summary: 'Cross-site scripting attempt' },
    { pattern: /\bon(?:error|load|click|mouseover|focus|pointerdown|pointerover|animationstart)\s*=/i, name: 'XSS_EVENT_HANDLER', category: 'XSS', severity: 'HIGH', riskScore: 70, summary: 'Cross-site scripting attempt' }
];

export class XssInspector extends InspectorBase {
    readonly name = 'XssInspector';
    readonly enabled: boolean;

    constructor(enabled = true) {
        super();
        this.enabled = enabled;
    }

    inspect(context: GuardRequestContext): ThreatIncident[] | null {
        if (!this.enabled) return null;
        const hits = matchRules(context, collectInspectionText(context), XSS_RULES, 'thr_xss');
        return hits.length ? hits : null;
    }
}
