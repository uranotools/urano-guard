import { InspectorBase } from './InspectorBase';
import { GuardRequestContext } from '../types/context';
import { ThreatIncident, newIncidentId } from '../types/threat';
import { headerValue } from '../utils/inspectText';

function decodeSegment(segment: string): Record<string, unknown> | null {
    try {
        const padded = segment.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(segment.length / 4) * 4, '=');
        const json = Buffer.from(padded, 'base64').toString('utf8');
        return JSON.parse(json);
    } catch {
        return null;
    }
}

export class JwtTamperingInspector extends InspectorBase {
    readonly name = 'JwtTamperingInspector';
    readonly enabled: boolean;

    constructor(enabled = true) {
        super();
        this.enabled = enabled;
    }

    inspect(context: GuardRequestContext): ThreatIncident[] | null {
        if (!this.enabled) return null;
        const auth = headerValue(context.headers, 'authorization');
        if (!auth.toLowerCase().startsWith('bearer ')) return null;
        const token = auth.slice(7).trim();
        if (!token) return null;

        const parts = token.split('.');
        const incidents: ThreatIncident[] = [];

        if (parts.length < 2 || parts.length > 3) {
            incidents.push(this.hit(context, 'JWT_MALFORMED', 80, 'Malformed JWT structure'));
            return incidents;
        }

        const header = decodeSegment(parts[0]);
        if (!header) {
            incidents.push(this.hit(context, 'JWT_HEADER_INVALID', 80, 'JWT header is not valid JSON'));
            return incidents;
        }

        const alg = String(header.alg || '').toLowerCase();
        if (!alg || alg === 'none') {
            incidents.push(this.hit(context, 'JWT_ALG_NONE', 90, 'JWT algorithm none / missing'));
        }
        if (alg.startsWith('hs') && header.kid && /[\\/]/.test(String(header.kid))) {
            incidents.push(this.hit(context, 'JWT_KID_TRAVERSAL', 85, 'JWT kid path traversal / algorithm confusion indicator'));
        }

        return incidents.length ? incidents : null;
    }

    private hit(context: GuardRequestContext, name: string, score: number, summary: string): ThreatIncident {
        return {
            id: newIncidentId('thr_jwt'),
            category: 'JWT_TAMPERING',
            severity: score >= 85 ? 'CRITICAL' : 'HIGH',
            riskScore: score,
            summary: `${summary} (${name})`,
            detectedAt: new Date().toISOString(),
            sender: context.senderId || context.ip
        };
    }
}
