import { AdapterBase } from './AdapterBase';
import { GuardRequestContext, SecurityDecision } from '../types/context';
import { firstHeader, pickClientIp, pickSenderId } from '../utils/identity';

export class FastifyAdapter extends AdapterBase {
    normalizeRequest(request: any): GuardRequestContext {
        const headers = request.headers || {};
        const ip = pickClientIp({
            trustProxy: this.trustProxy(),
            socketIp: request.raw?.socket?.remoteAddress,
            forwardedFor: headers['x-forwarded-for'],
            realIp: firstHeader(headers, 'x-real-ip'),
            fallback: request.ip
        });
        return {
            ip,
            method: request.method || 'GET',
            path: request.url || '/',
            headers,
            query: request.query || {},
            body: request.body || {},
            rawBody: request.rawBody,
            senderId: pickSenderId({
                trustProxy: this.trustProxy(),
                ip,
                headerUserId: firstHeader(headers, 'x-user-id'),
                headerSenderId: firstHeader(headers, 'x-sender-id')
            }),
            timestamp: Date.now()
        };
    }

    handleBlock(reply: any, decision: SecurityDecision, reqCtx: GuardRequestContext): any {
        return this.dispatchBlock({
            json: (status, body) => reply.code(status).send(body),
            redirect: (url) => reply.redirect(url)
        }, decision, reqCtx);
    }

    hook(): (request: any, reply: any) => Promise<void> {
        return async (request: any, reply: any) => {
            try {
                const reqCtx = this.normalizeRequest(request);
                const decision = await this.guard.inspect(reqCtx);

                if (!decision.allowed) {
                    return this.handleBlock(reply, decision, reqCtx);
                }

                request.uranoGuard = decision;
                if (decision.sanitizedBody) {
                    request.body = decision.sanitizedBody;
                }
            } catch (err: any) {
                if (!this.failClosed()) {
                    this.guard.getLogger().warn('Fastify evaluation failed, failOpen=true', err);
                    return;
                }
                reply.code(500).send({ error: 'SECURITY_GATEWAY_ERROR', message: 'Security gateway error' });
            }
        };
    }
}
