import { GuardRequestContext } from '../types/context';
import { ThreatIncident } from '../types/threat';

export type InspectorResult = ThreatIncident | ThreatIncident[] | null;

export abstract class InspectorBase {
    abstract readonly name: string;
    abstract readonly enabled: boolean;

    abstract inspect(context: GuardRequestContext): Promise<InspectorResult> | InspectorResult;
}

export function flattenIncidents(result: InspectorResult): ThreatIncident[] {
    if (!result) return [];
    return Array.isArray(result) ? result : [result];
}
