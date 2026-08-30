import { InspectorBase } from './InspectorBase';
import { GuardRequestContext } from '../types/context';
import { ThreatIncident, newIncidentId } from '../types/threat';
import { collectInspectionText } from '../utils/inspectText';

interface UrlRule {
    pattern: RegExp;
    name: string;
    riskScore: number;
}

const URL_RULES: UrlRule[] = [
    { pattern: /https?:\/\/(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::\d{1,5})?/i, name: 'RAW_IP_URL', riskScore: 45 },
    { pattern: /https?:\/\/[^\s/$.?#].[^\s]{0,200}\.(xyz|top|work|click|loan|gq|cf|tk|buzz|rest|fit|link)\b/i, name: 'HIGH_RISK_TLD', riskScore: 45 },
    { pattern: /(bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|ow\.ly)\//i, name: 'PUBLIC_URL_SHORTENER', riskScore: 45 },
    { pattern: /https?:\/\/[^\s]{0,80}(login|verify|secure|update|auth|bank)[^\s]{0,80}\.(?!com|org|net|edu|gob|gov)[a-z0-9-]{1,63}\.[a-z]{2,}/i, name: 'TYPOSQUATTING_PHISHING', riskScore: 70 }
];

function hostFromMatch(text: string, index: number): string | null {
    const slice = text.slice(index, index + 256);
    const match = slice.match(/https?:\/\/([^/\s:?#]+)/i);
    return match ? match[1].toLowerCase() : null;
}

export class MaliciousUrlInspector extends InspectorBase {
    readonly name = 'MaliciousUrlInspector';
    readonly enabled: boolean;
    private allowHosts: Set<string>;

    constructor(enabled = true, allowHosts: string[] = []) {
        super();
        this.enabled = enabled;
        this.allowHosts = new Set(allowHosts.map(h => h.toLowerCase()));
    }

    inspect(context: GuardRequestContext): ThreatIncident[] | null {
        if (!this.enabled) return null;
        const text = collectInspectionText(context);
        const incidents: ThreatIncident[] = [];

        for (const rule of URL_RULES) {
            rule.pattern.lastIndex = 0;
            const match = rule.pattern.exec(text);
            if (!match) continue;
            const host = hostFromMatch(text, match.index);
            if (host && this.isAllowed(host)) continue;
            incidents.push({
                id: newIncidentId('thr_url'),
                category: 'MALICIOUS_URL',
                severity: rule.riskScore >= 70 ? 'HIGH' : 'MEDIUM',
                riskScore: rule.riskScore,
                summary: `Suspicious URL or possible phishing link (${rule.name})`,
                matchedPattern: rule.pattern.toString(),
                detectedAt: new Date().toISOString(),
                sender: context.senderId || context.ip
            });
        }
        return incidents.length ? incidents : null;
    }

    private isAllowed(host: string): boolean {
        if (this.allowHosts.has(host)) return true;
        for (const allowed of this.allowHosts) {
            if (host === allowed || host.endsWith(`.${allowed}`)) return true;
        }
        return false;
    }
}
