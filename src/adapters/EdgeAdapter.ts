import { AdapterBase } from './AdapterBase';
import { GuardRequestContext, SecurityDecision } from '../types/context';
import { pickClientIp, pickSenderId } from '../utils/identity';

export class EdgeAdapter extends AdapterBase {
    async normalizeRequest(request: Request): Promise<GuardRequestContext> {
        const url = new URL(request.url);
        const headers: Record<string, string> = {};
        request.headers.forEach((val, key) => { headers[key] = val; });

        let body: any = {};
        let rawBody = '';
        if (request.method !== 'GET' && request.method !== 'HEAD') {
            try {
                rawBody = await request.clone().text();
                body = JSON.parse(rawBody);
            } catch {
                body = rawBody;
            }
        }

        const ip = pickClientIp({
            trustProxy: this.trustProxy(),
            forwardedFor: headers['x-forwarded-for'],
            realIp: headers['x-real-ip'] || headers['cf-connecting-ip'],
            fallback: 'edge'
        });

        return {
            ip,
            method: request.method,
            path: url.pathname,
            headers,
            query: Object.fromEntries(url.searchParams.entries()),
            body,
            rawBody,
            senderId: pickSenderId({
                trustProxy: this.trustProxy(),
                ip,
                headerUserId: headers['x-user-id'],
                headerSenderId: headers['x-sender-id']
            }),
            timestamp: Date.now()
        };
    }

    handleBlock(_res: any, decision: SecurityDecision, reqCtx: GuardRequestContext): any {
        return this.dispatchBlock({
            json: (status, body) => new Response(JSON.stringify(body), {
                status,
                headers: { 'Content-Type': 'application/json' }
            }),
            redirect: (url) => Response.redirect(url, 302)
        }, decision, reqCtx);
    }

    handler(): (request: Request) => Promise<SecurityDecision> {
        return async (request: Request) => {
            try {
                const reqCtx = await this.normalizeRequest(request);
                return await this.guard.inspect(reqCtx);
            } catch (err: any) {
                if (this.guard.config.failOpen !== false) {
                    this.guard.getLogger().warn('Edge evaluation failed, failOpen=true', err);
                    return {
                        allowed: true,
                        action: 'ALLOW',
                        riskScore: 0,
                        threats: [],
                        latencyMs: 0,
                        source: 'FALLBACK'
                    };
                }
                throw err;
            }
        };
    }
}
