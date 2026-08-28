import { InspectorBase } from './InspectorBase';
import { GuardRequestContext } from '../types/context';
import { ThreatIncident } from '../types/threat';

const INJECTION_RULES = [
    { pattern: /ignore\s+(all\s+)?(previous|prior)\s+instructions/i, name: 'IGNORE_PREVIOUS_INSTRUCTIONS' },
    { pattern: /desatiende\s+(todas\s+las\s+)?instrucciones\s+(previas|anteriores)/i, name: 'DESATIENDE_REGLAS' },
    { pattern: /you\s+are\s+now\s+(DAN|unfiltered|jailbroken|developer\s+mode)/i, name: 'JAILBREAK_ROLEPLAY' },
    { pattern: /system\s*prompt\s*override/i, name: 'PROMPT_OVERRIDE' },
    { pattern: /reveal\s+(your\s+)?(system\s+instructions|internal\s+prompt)/i, name: 'PROMPT_LEAK_REQUEST' },
    { pattern: /\b(base64|rot13|hex)\s+decode\s+this\s+command\b/i, name: 'OBFUSCATION_BYPASS' },
    { pattern: /exec\s*\(\s*["'`].*["'`]/i, name: 'EVAL_EXEC_INJECTION' }
];

export class PromptInjectionInspector extends InspectorBase {
    readonly name = 'PromptInjectionInspector';
    readonly enabled: boolean;

    constructor(enabled = true) {
        super();
        this.enabled = enabled;
    }

    inspect(context: GuardRequestContext): ThreatIncident | null {
        if (!this.enabled) return null;
        const text = typeof context.body === 'string' 
            ? context.body 
            : JSON.stringify(context.body || '') + ' ' + (context.rawBody || '');

        for (const rule of INJECTION_RULES) {
            if (rule.pattern.test(text)) {
                return {
                    id: `thr_inj_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
                    category: 'PROMPT_INJECTION',
                    severity: 'CRITICAL',
                    riskScore: 85,
                    summary: `Intento de manipulación de directivas AI (${rule.name})`,
                    matchedPattern: rule.pattern.toString(),
                    detectedAt: new Date().toISOString(),
                    sender: context.senderId || context.ip
                };
            }
        }
        return null;
    }
}