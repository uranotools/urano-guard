import { InspectorBase } from './InspectorBase';
import { GuardRequestContext } from '../types/context';
import { ThreatIncident, newIncidentId } from '../types/threat';
import { stringifySafe } from '../utils/inspectText';

const DEFAULT_MAX_DEPTH = 12;
const DEFAULT_MAX_BATCH = 8;

function queryDepth(query: string): number {
    let depth = 0;
    let max = 0;
    for (const char of query) {
        if (char === '{') {
            depth++;
            if (depth > max) max = depth;
        } else if (char === '}') {
            depth = Math.max(0, depth - 1);
        }
    }
    return max;
}

export class GraphqlAbuseInspector extends InspectorBase {
    readonly name = 'GraphqlAbuseInspector';
    readonly enabled: boolean;
    private maxDepth: number;
    private maxBatch: number;

    constructor(enabled = true, opts?: { maxDepth?: number; maxBatch?: number }) {
        super();
        this.enabled = enabled;
        this.maxDepth = opts?.maxDepth ?? DEFAULT_MAX_DEPTH;
        this.maxBatch = opts?.maxBatch ?? DEFAULT_MAX_BATCH;
    }

    inspect(context: GuardRequestContext): ThreatIncident[] | null {
        if (!this.enabled) return null;
        const body = context.body;
        const incidents: ThreatIncident[] = [];

        if (Array.isArray(body) && body.length > this.maxBatch) {
            incidents.push(this.hit(context, 'GRAPHQL_BATCHING', 70, `GraphQL batch size ${body.length} exceeds ${this.maxBatch}`));
        }

        const operations = Array.isArray(body) ? body : [body];
        for (const op of operations) {
            const query = typeof op === 'string'
                ? op
                : (op && typeof op === 'object' ? String(op.query || op.mutation || '') : '');
            const blob = query || stringifySafe(op);
            if (/\b__schema\b/.test(blob) || /\b__type\b/.test(blob)) {
                incidents.push(this.hit(context, 'GRAPHQL_INTROSPECTION', 65, 'GraphQL introspection probe detected'));
            }
            if (query && queryDepth(query) > this.maxDepth) {
                incidents.push(this.hit(context, 'GRAPHQL_DEPTH', 70, `GraphQL query depth exceeds ${this.maxDepth}`));
            }
        }

        return incidents.length ? incidents : null;
    }

    private hit(context: GuardRequestContext, name: string, score: number, summary: string): ThreatIncident {
        return {
            id: newIncidentId('thr_gql'),
            category: 'GRAPHQL_ABUSE',
            severity: 'HIGH',
            riskScore: score,
            summary: `${summary} (${name})`,
            detectedAt: new Date().toISOString(),
            sender: context.senderId || context.ip
        };
    }
}
