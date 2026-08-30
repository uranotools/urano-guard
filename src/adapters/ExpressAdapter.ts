import { AdapterBase } from './AdapterBase';
import { GuardRequestContext, SecurityDecision } from '../types/context';
import { firstHeader, pickClientIp, pickSenderId } from '../utils/identity';

export class ExpressAdapter extends AdapterBase {
    normalizeRequest(req: any): GuardRequestContext {
        const headers = req.headers || {};
        const ip = pickClientIp({
            trustProxy: this.trustProxy(),
            socketIp: req.socket?.remoteAddress || req.connection?.remoteAddress,
            forwardedFor: headers['x-forwarded-for'],
            realIp: firstHeader(headers, 'x-real-ip'),
            fallback: req.ip
        });
        return {
            ip,
            method: req.method || 'GET',
            path: req.originalUrl || req.url || '/',
            headers,
            query: req.query || {},
            body: req.body || {},
            rawBody: req.rawBody,
            senderId: pickSenderId({
                trustProxy: this.trustProxy(),
                ip,
                headerUserId: firstHeader(headers, 'x-user-id'),
                headerSenderId: firstHeader(headers, 'x-sender-id')
            }),
            timestamp: Date.now()
        };
    }

    handleBlock(res: any, decision: SecurityDecision, reqCtx: GuardRequestContext): any {
        return this.dispatchBlock({
            json: (status, body) => res.status(status).json(body),
            redirect: (url) => res.redirect(url)
        }, decision, reqCtx);
    }

    middleware(): (req: any, res: any, next: any) => void {
        return async (req: any, res: any, next: any) => {
            try {
                const reqCtx = this.normalizeRequest(req);
                const decision = await this.guard.inspect(reqCtx);

                if (!decision.allowed) {
                    return this.handleBlock(res, decision, reqCtx);
                }

                req.uranoGuard = decision;
                if (decision.sanitizedBody) {
                    req.body = decision.sanitizedBody;
                }
                next();
            } catch (err: any) {
                if (this.guard.config.failOpen !== false) {
                    this.guard.getLogger().warn('Express evaluation failed, failOpen=true', err);
                    return next();
                }
                res.status(500).json({ error: 'SECURITY_GATEWAY_ERROR', message: 'Security gateway error' });
            }
        };
    }
}
