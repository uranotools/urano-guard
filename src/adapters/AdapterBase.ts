import { UranoGuard } from '../core/UranoGuard';
import { GuardRequestContext, SecurityDecision } from '../types/context';

export abstract class AdapterBase {
    protected guard: UranoGuard;

    constructor(guard: UranoGuard) {
        this.guard = guard;
    }

    abstract normalizeRequest(rawReq: any): GuardRequestContext | Promise<GuardRequestContext>;
    abstract handleBlock(rawRes: any, decision: SecurityDecision, reqCtx: GuardRequestContext): any;
}