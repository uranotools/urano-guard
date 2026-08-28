import { GuardRequestContext } from '../types/context';
import { ThreatIncident } from '../types/threat';

export abstract class InspectorBase {
    abstract readonly name: string;
    abstract readonly enabled: boolean;

    abstract inspect(context: GuardRequestContext): Promise<ThreatIncident | null> | ThreatIncident | null;
}