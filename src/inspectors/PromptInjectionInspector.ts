import { InspectorBase } from './InspectorBase';
import { GuardRequestContext } from '../types/context';
import { ThreatIncident } from '../types/threat';
import { collectInspectionText, normalizeInspectionText } from '../utils/inspectText';
import { DetectionRule, matchRules } from './ruleEngine';

const INJECTION_RULES: DetectionRule[] = [
    { pattern: /ignore\s+(all\s+)?(previous|prior)\s+instructions/i, name: 'IGNORE_PREVIOUS_INSTRUCTIONS', category: 'PROMPT_INJECTION', severity: 'CRITICAL', riskScore: 85, summary: 'AI directive override attempt' },
    { pattern: /desatiende\s+(todas\s+las\s+)?instrucciones\s+(previas|anteriores)/i, name: 'DESATIENDE_REGLAS', category: 'PROMPT_INJECTION', severity: 'CRITICAL', riskScore: 85, summary: 'AI directive override attempt' },
    { pattern: /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|prompts)/i, name: 'DISREGARD_RULES', category: 'PROMPT_INJECTION', severity: 'CRITICAL', riskScore: 85, summary: 'AI directive override attempt' },
    { pattern: /forget\s+(all\s+)?(your\s+)?(instructions|rules|guidelines)/i, name: 'FORGET_RULES', category: 'PROMPT_INJECTION', severity: 'CRITICAL', riskScore: 85, summary: 'AI directive override attempt' },
    { pattern: /olvida\s+(tus\s+)?(instrucciones|reglas)/i, name: 'OLVIDA_REGLAS', category: 'PROMPT_INJECTION', severity: 'CRITICAL', riskScore: 85, summary: 'AI directive override attempt' },
    { pattern: /you\s+are\s+now\s+(DAN|unfiltered|jailbroken|developer\s+mode)/i, name: 'JAILBREAK_ROLEPLAY', category: 'PROMPT_INJECTION', severity: 'CRITICAL', riskScore: 85, summary: 'AI directive override attempt' },
    { pattern: /\bDAN\b[\s\S]{0,40}\b(jailbreak|unfiltered)/i, name: 'DAN_JAILBREAK', category: 'PROMPT_INJECTION', severity: 'CRITICAL', riskScore: 85, summary: 'AI directive override attempt' },
    { pattern: /developer\s+mode\s+(enabled|on)/i, name: 'DEV_MODE', category: 'PROMPT_INJECTION', severity: 'HIGH', riskScore: 80, summary: 'AI directive override attempt' },
    { pattern: /system\s*prompt\s*override/i, name: 'PROMPT_OVERRIDE', category: 'PROMPT_INJECTION', severity: 'CRITICAL', riskScore: 85, summary: 'AI directive override attempt' },
    { pattern: /reveal\s+(your\s+)?(system\s+instructions|internal\s+prompt)/i, name: 'PROMPT_LEAK_REQUEST', category: 'PROMPT_INJECTION', severity: 'CRITICAL', riskScore: 85, summary: 'AI directive override attempt' },
    { pattern: /<\|system\|>/i, name: 'SYSTEM_TAG', category: 'PROMPT_INJECTION', severity: 'HIGH', riskScore: 80, summary: 'AI directive override attempt' },
    { pattern: /<\/(?:instructions|system)>/i, name: 'CLOSE_INSTRUCTION_TAG', category: 'PROMPT_INJECTION', severity: 'HIGH', riskScore: 80, summary: 'AI directive override attempt' },
    { pattern: /\b(base64|rot13|hex)\s+decode\s+this\s+command\b/i, name: 'OBFUSCATION_BYPASS', category: 'PROMPT_INJECTION', severity: 'HIGH', riskScore: 75, summary: 'AI directive override attempt' },
    { pattern: /exec\s*\(\s*["'`][\s\S]{0,200}["'`]/i, name: 'EVAL_EXEC_INJECTION', category: 'PROMPT_INJECTION', severity: 'HIGH', riskScore: 80, summary: 'AI directive override attempt' },
    { pattern: /override\s+(the\s+)?system\s+prompt/i, name: 'OVERRIDE_SYSTEM_PROMPT', category: 'PROMPT_INJECTION', severity: 'CRITICAL', riskScore: 85, summary: 'AI directive override attempt' },
    { pattern: /act\s+as\s+(an?\s+)?(unfiltered|jailbroken|dan|evil|unrestricted)\b/i, name: 'ACT_AS_JAILBREAK', category: 'PROMPT_INJECTION', severity: 'CRITICAL', riskScore: 85, summary: 'AI directive override attempt' },
    { pattern: /\b(llm|model|gpt)\s+jailbreak\b|\bjailbreak\s+(mode|the\s+(model|ai|llm))\b/i, name: 'JAILBREAK_MODE', category: 'PROMPT_INJECTION', severity: 'HIGH', riskScore: 80, summary: 'AI directive override attempt' }
];

export class PromptInjectionInspector extends InspectorBase {
    readonly name = 'PromptInjectionInspector';
    readonly enabled: boolean;

    constructor(enabled = true) {
        super();
        this.enabled = enabled;
    }

    inspect(context: GuardRequestContext): ThreatIncident[] | null {
        if (!this.enabled) return null;
        const text = collectInspectionText(context);
        const leet = normalizeInspectionText(text, { leet: true });
        const seen = new Set<string>();
        const hits = [
            ...matchRules(context, text, INJECTION_RULES, 'thr_inj'),
            ...matchRules(context, leet, INJECTION_RULES, 'thr_inj')
        ].filter(hit => {
            const key = hit.matchedPattern || hit.summary;
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
        });
        return hits.length ? hits : null;
    }
}
