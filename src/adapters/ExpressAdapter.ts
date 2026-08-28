import { AdapterBase } from './AdapterBase';
import { GuardRequestContext, SecurityDecision } from '../types/context';

export class ExpressAdapter extends AdapterBase {
    normalizeRequest(req: any): GuardRequestContext {
        return {
            ip: req.ip || req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '127.0.0.1',
            method: req.method || 'GET',
            path: req.originalUrl || req.url || '/',
            headers: req.headers || {},
            query: req.query || {},
            body: req.body || {},
            rawBody: req.rawBody,
            senderId: req.headers['x-user-id'] || req.headers['x-sender-id'] || req.body?.sender || req.ip,
            timestamp: Date.now()
        };
    }

    handleBlock(res: any, decision: SecurityDecision, reqCtx: GuardRequestContext): any {
        if (this.guard.config.onBlock) {
            return this.guard.config.onBlock(decision, reqCtx);
        }

        return res.status(403).json({
            error: 'FORBIDDEN_BY_CYBER_GUARD',
            message: decision.reason || 'Petición bloqueada por las políticas de seguridad de Urano.',
            riskScore: decision.riskScore,
            incidentId: decision.threats[0]?.id
        });
    }

    middleware(): (req: any, res: any, next: any) => void {
        return async (req: any, res: any, next: any) => {
            try {
                const reqCtx = this.normalizeRequest(req);
                const decision = await this.guard.inspect(reqCtx);

                if (!decision.allowed) {
                    return this.handleBlock(res, decision, reqCtx);
                }

                // Inyectar contexto de decisión en la petición
                req.uranoGuard = decision;
                if (decision.sanitizedBody) {
                    req.body = decision.sanitizedBody;
                }

                next();
            } catch (err: any) {
                if (this.guard.config.failOpen !== false) {
                    console.warn('[UranoGuard Express] Fallo en evaluación, aplicando failOpen: true', err);
                    return next();
                }
                res.status(500).json({ error: 'SECURITY_GATEWAY_ERROR', message: err.message });
            }
        };
    }
}