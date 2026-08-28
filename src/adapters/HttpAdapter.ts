import { AdapterBase } from './AdapterBase';
import { GuardRequestContext, SecurityDecision } from '../types/context';

export class HttpAdapter extends AdapterBase {
    normalizeRequest(req: any): GuardRequestContext {
        return {
            ip: req.socket?.remoteAddress || '127.0.0.1',
            method: req.method || 'GET',
            path: req.url || '/',
            headers: req.headers || {},
            query: {},
            body: req.body || {},
            timestamp: Date.now()
        };
    }

    handleBlock(res: any, decision: SecurityDecision): void {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            error: 'FORBIDDEN_BY_CYBER_GUARD',
            message: decision.reason || 'Blocked by Urano CyberGuard',
            incidentId: decision.threats[0]?.id
        }));
    }

    handler(): (req: any, res: any, next?: () => void) => Promise<boolean> {
        return async (req: any, res: any, next?: () => void) => {
            const reqCtx = this.normalizeRequest(req);
            const decision = await this.guard.inspect(reqCtx);

            if (!decision.allowed) {
                this.handleBlock(res, decision);
                return false;
            }

            if (next) next();
            return true;
        };
    }
}