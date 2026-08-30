import { UranoGuard } from '../core/UranoGuard';
import { isFailClosed } from '../core/failPolicy';
import { GuardRequestContext, SecurityDecision } from '../types/context';

export interface BlockResponseWriter {
    json(status: number, body: unknown): any;
    redirect(url: string): any;
}

export abstract class AdapterBase {
    protected guard: UranoGuard;

    constructor(guard: UranoGuard) {
        this.guard = guard;
    }

    abstract normalizeRequest(rawReq: any): GuardRequestContext | Promise<GuardRequestContext>;
    abstract handleBlock(rawRes: any, decision: SecurityDecision, reqCtx: GuardRequestContext): any;

    protected trustProxy(): boolean {
        return this.guard.config.trustProxy === true;
    }

    protected failClosed(): boolean {
        return isFailClosed(this.guard.config);
    }

    protected async dispatchBlock(
        writer: BlockResponseWriter,
        decision: SecurityDecision,
        reqCtx: GuardRequestContext
    ): Promise<any> {
        if (this.guard.config.onBlock) {
            return this.guard.config.onBlock(decision, reqCtx);
        }

        if (decision.action === 'REDIRECT') {
            if (this.guard.config.onRedirect) {
                const url = await this.guard.config.onRedirect(decision, reqCtx);
                return writer.redirect(url);
            }
            if (decision.redirectUrl) return writer.redirect(decision.redirectUrl);
        }

        if (this.guard.honeypot) {
            const hp = await this.guard.honeypot.decide(decision.threats[0]?.category || 'CUSTOM', decision.riskScore);
            if (hp.strategy === 'HONEY_RESPONSE' && hp.fakeBody) {
                return writer.json(200, hp.fakeBody);
            }
        }

        const expose = this.guard.config.exposeDecisionDetails === true;
        const body = expose
            ? {
                error: 'FORBIDDEN_BY_CYBER_GUARD',
                message: decision.reason || 'Request blocked by Urano security policy.',
                riskScore: decision.riskScore,
                incidentId: decision.threats[0]?.id
            }
            : {
                error: 'FORBIDDEN_BY_CYBER_GUARD',
                message: 'Request blocked by security policy.'
            };

        return writer.json(403, body);
    }
}
