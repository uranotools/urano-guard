import { InspectorBase } from './InspectorBase';
import { GuardRequestContext } from '../types/context';
import { ThreatIncident, newIncidentId } from '../types/threat';
import { normalizeInspectionText, stringifySafe } from '../utils/inspectText';

const TAIL_SCAN_BYTES = 4096;
const HEAD_SCAN_BYTES = 4096;
const PADDING_THRESHOLD = 8192;
const RANDOM_SAMPLE_SIZE = 2048;

const INJECTION_TAIL_PATTERNS = [
    /ignore\s+(all\s+)?(previous|prior)\s+instructions/i,
    /;\s*(DROP|DELETE|ALTER)\s+TABLE\b/i,
    /UNION\s+SELECT\s[\s\S]{0,200}FROM\b/i,
    /\/etc\/(shadow|passwd)/i,
    /exec\s*\(/i,
    /<script\b[\s\S]{0,2000}?>/i
];

export class PaddingEvasionInspector extends InspectorBase {
    readonly name = 'PaddingEvasionInspector';
    readonly enabled: boolean;

    constructor(enabled = true) {
        super();
        this.enabled = enabled;
    }

    inspect(context: GuardRequestContext): ThreatIncident[] | null {
        if (!this.enabled) return null;

        const raw = context.rawBody || (typeof context.body === 'string' ? context.body : stringifySafe(context.body));
        if (raw.length <= PADDING_THRESHOLD) return null;

        const tail = raw.slice(-TAIL_SCAN_BYTES);
        const midStart = Math.max(HEAD_SCAN_BYTES, Math.floor(raw.length / 2) - RANDOM_SAMPLE_SIZE / 2);
        const mid = raw.slice(midStart, midStart + RANDOM_SAMPLE_SIZE);
        const tailNorm = normalizeInspectionText(tail);
        const midNorm = normalizeInspectionText(mid);

        const incidents: ThreatIncident[] = [];
        for (const pattern of INJECTION_TAIL_PATTERNS) {
            pattern.lastIndex = 0;
            const inTail = pattern.test(tail) || pattern.test(tailNorm);
            pattern.lastIndex = 0;
            const inMid = pattern.test(mid) || pattern.test(midNorm);
            if (!inTail && !inMid) continue;
            const location = inTail ? 'TAIL' : 'MIDDLE';
            incidents.push({
                id: newIncidentId('thr_pad'),
                category: 'PROMPT_INJECTION',
                severity: 'CRITICAL',
                riskScore: 92,
                summary: `Padding evasion detected in ${location} of payload (${raw.length} bytes).`,
                matchedPattern: pattern.toString(),
                detectedAt: new Date().toISOString(),
                sender: context.senderId || context.ip,
                details: {
                    totalPayloadBytes: raw.length,
                    detectedLocation: location,
                    tailSample: tail.slice(0, 200)
                }
            });
        }
        return incidents.length ? incidents : null;
    }
}
