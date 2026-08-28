import { AdapterBase } from './AdapterBase';
import { GuardRequestContext, SecurityDecision } from '../types/context';

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

        return {
            ip: headers['cf-connecting-ip'] || headers['x-real-ip'] || headers['x-forwarded-for'] || 'edge',
            method: request.method,
            path: url.pathname,
            headers,
            query: Object.fromEntries(url.searchParams.entries()),
            body,
            rawBody,
            senderId: headers['x-user-id'] || headers['cf-connecting-ip'],
            timestamp: Date.now()
        };
    }

    handleBlock(res: any, decision: SecurityDecision, reqCtx: GuardRequestContext): any {
        return new Response(JSON.stringify({
            error: 'FORBIDDEN_BY_CYBER_GUARD',
            message: decision.reason || 'Blocked by Urano CyberGuard',
            riskScore: decision.riskScore,
            incidentId: decision.threats[0]?.id
        }), {
            status: 403,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    handler(): (request: Request) => Promise<SecurityDecision> {
        return async (request: Request) => {
            const reqCtx = await this.normalizeRequest(request);
            return await this.guard.inspect(reqCtx);
        };
    }
}