import { AdapterBase } from './AdapterBase';
import { GuardRequestContext, SecurityDecision } from '../types/context';
import { pickClientIp, pickSenderId } from '../utils/identity';

export class HonoAdapter extends AdapterBase {
    async normalizeRequest(c: any): Promise<GuardRequestContext> {
        const headerBag: Record<string, string> = {};
        const rawHeaders = typeof c.req.raw?.headers?.forEach === 'function' ? c.req.raw.headers : null;
        if (rawHeaders) {
            rawHeaders.forEach((val: string, key: string) => { headerBag[key] = val; });
        } else if (typeof c.req.header === 'function') {
            for (const name of ['user-agent', 'content-type', 'authorization', 'x-forwarded-for', 'x-real-ip', 'x-user-id', 'x-sender-id', 'accept', 'accept-language', 'origin', 'referer']) {
                const value = c.req.header(name);
                if (value) headerBag[name] = value;
            }
        }

        let body: any = {};
        let rawBody = '';
        const method = c.req.method || 'GET';
        if (method !== 'GET' && method !== 'HEAD') {
            try {
                rawBody = await c.req.text();
                try { body = JSON.parse(rawBody); } catch { body = rawBody; }
            } catch {
                body = {};
            }
        }

        const ip = pickClientIp({
            trustProxy: this.trustProxy(),
            forwardedFor: headerBag['x-forwarded-for'],
            realIp: headerBag['x-real-ip'],
            fallback: '127.0.0.1'
        });

        return {
            ip,
            method,
            path: c.req.path || '/',
            headers: headerBag,
            query: typeof c.req.query === 'function' ? (c.req.query() || {}) : {},
            body,
            rawBody,
            senderId: pickSenderId({
                trustProxy: this.trustProxy(),
                ip,
                headerUserId: headerBag['x-user-id'],
                headerSenderId: headerBag['x-sender-id']
            }),
            timestamp: Date.now()
        };
    }

    handleBlock(c: any, decision: SecurityDecision, reqCtx: GuardRequestContext): any {
        return this.dispatchBlock({
            json: (status, body) => c.json(body, status),
            redirect: (url) => c.redirect(url)
        }, decision, reqCtx);
    }

    middleware() {
        return async (c: any, next: () => Promise<void>) => {
            try {
                const reqCtx = await this.normalizeRequest(c);
                const decision = await this.guard.inspect(reqCtx);
                if (!decision.allowed) {
                    return this.handleBlock(c, decision, reqCtx);
                }
                c.set?.('uranoGuard', decision);
                await next();
            } catch (err: any) {
                if (!this.failClosed()) {
                    this.guard.getLogger().warn('Hono evaluation failed, failOpen=true', err);
                    return next();
                }
                return c.json({ error: 'SECURITY_GATEWAY_ERROR' }, 500);
            }
        };
    }
}
