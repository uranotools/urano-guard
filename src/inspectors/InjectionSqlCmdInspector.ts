import { InspectorBase, flattenIncidents } from './InspectorBase';
import { GuardRequestContext } from '../types/context';
import { ThreatIncident } from '../types/threat';
import { SqlInjectionInspector } from './SqlInjectionInspector';
import { CommandInjectionInspector } from './CommandInjectionInspector';
import { XssInspector } from './XssInspector';

/** @deprecated Prefer SqlInjectionInspector, CommandInjectionInspector and XssInspector. */
export class InjectionSqlCmdInspector extends InspectorBase {
    readonly name = 'InjectionSqlCmdInspector';
    readonly enabled: boolean;
    private sql: SqlInjectionInspector;
    private cmd: CommandInjectionInspector;
    private xss: XssInspector;

    constructor(enabled = true) {
        super();
        this.enabled = enabled;
        this.sql = new SqlInjectionInspector(enabled);
        this.cmd = new CommandInjectionInspector(enabled);
        this.xss = new XssInspector(enabled);
    }

    inspect(context: GuardRequestContext): ThreatIncident[] | null {
        if (!this.enabled) return null;
        const hits = [
            ...flattenIncidents(this.sql.inspect(context)),
            ...flattenIncidents(this.cmd.inspect(context)),
            ...flattenIncidents(this.xss.inspect(context))
        ];
        return hits.length ? hits : null;
    }
}
