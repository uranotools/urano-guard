import { AdapterBase } from './AdapterBase';
import { GuardRequestContext, SecurityDecision } from '../types/context';

export class FastifyAdapter extends AdapterBase {
    normalizeRequest(request: any): GuardRequestContext {
        return {
            ip: request.ip || request.headers['x-forwarded-for'] || '127.0.0.1',
            method: request.method || 'GET',
            path: request.url || '/',
            headers: request.headers || {},
            query: request.query || {},
            body: request.body || {},
            senderId: request.headers['x-user-id'] || request.ip,
            timestamp: Date.now()
        };
    }

    handleBlock(reply: any, decision: SecurityDecision, reqCtx: GuardRequestContext): any {
        if (this.guard.config.onBlock) {
            return this.guard.config.onBlock(decision, reqCtx);
        }

        return reply.code(403).send({
            error: 'FORBIDDEN_BY_CYBER_GUARD',
            message: decision.reason || 'Petición bloqueada por las políticas de seguridad de Urano.',
            riskScore: decision.riskScore,
            incidentId: decision.threats[0]?.id
        });
    }

    hook(): (request: any, reply: any) => Promise<void> {
        return async (request: any, reply: any) => {
            const reqCtx = this.normalizeRequest(request);
            const decision = await this.guard.inspect(reqCtx);

            if (!decision.allowed) {
                return this.handleBlock(reply, decision, reqCtx);
            }

            request.uranoGuard = decision;
            if (decision.sanitizedBody) {
                request.body = decision.sanitizedBody;
            }
        };
    }
}