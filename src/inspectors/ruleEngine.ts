import { GuardRequestContext } from '../types/context';
import { ThreatCategory, ThreatIncident, ThreatSeverity, newIncidentId } from '../types/threat';
import { normalizeInspectionText } from '../utils/inspectText';

export interface DetectionRule {
    pattern: RegExp;
    name: string;
    category: ThreatCategory;
    severity: ThreatSeverity;
    riskScore: number;
    summary: string;
}

export function matchRules(
    context: GuardRequestContext,
    text: string,
    rules: DetectionRule[],
    idPrefix: string
): ThreatIncident[] {
    const incidents: ThreatIncident[] = [];
    const normalized = normalizeInspectionText(text);
    for (const rule of rules) {
        rule.pattern.lastIndex = 0;
        if (rule.pattern.test(normalized) || rule.pattern.test(text)) {
            incidents.push({
                id: newIncidentId(idPrefix),
                category: rule.category,
                severity: rule.severity,
                riskScore: rule.riskScore,
                summary: `${rule.summary} (${rule.name})`,
                matchedPattern: rule.pattern.toString(),
                detectedAt: new Date().toISOString(),
                sender: context.senderId || context.ip
            });
        }
    }
    return incidents;
}
