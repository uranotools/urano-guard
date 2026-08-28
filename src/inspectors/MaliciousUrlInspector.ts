import { InspectorBase } from './InspectorBase';
import { GuardRequestContext } from '../types/context';
import { ThreatIncident } from '../types/threat';

const URL_RULES = [
    { pattern: /https?:\/\/(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::\d+)?/i, name: 'RAW_IP_URL' },
    { pattern: /https?:\/\/[^\s/$.?#].[^\s]*\.(xyz|top|work|click|loan|gq|cf|tk|buzz|rest|fit|link)\b/i, name: 'HIGH_RISK_TLD' },
    { pattern: /(bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|ow\.ly)\//i, name: 'PUBLIC_URL_SHORTENER' },
    { pattern: /https?:\/\/.*(login|verify|secure|update|auth|bank).*\.(?!com|org|net|edu|gob|gov)[a-zA-Z0-9-]+\.[a-zA-Z]{2,}/i, name: 'TYPOSQUATTING_PHISHING' }
];

export class MaliciousUrlInspector extends InspectorBase {
    readonly name = 'MaliciousUrlInspector';
    readonly enabled: boolean;

    constructor(enabled = true) {
        super();
        this.enabled = enabled;
    }

    inspect(context: GuardRequestContext): ThreatIncident | null {
        if (!this.enabled) return null;
        const text = typeof context.body === 'string' ? context.body : JSON.stringify(context.body || '');

        for (const rule of URL_RULES) {
            if (rule.pattern.test(text)) {
                return {
                    id: `thr_url_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
                    category: 'MALICIOUS_URL',
                    severity: 'HIGH',
                    riskScore: 70,
                    summary: `URL sospechosa o posible enlace de phishing (${rule.name})`,
                    matchedPattern: rule.pattern.toString(),
                    detectedAt: new Date().toISOString(),
                    sender: context.senderId || context.ip
                };
            }
        }
        return null;
    }
}