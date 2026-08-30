import { AdapterBase } from './AdapterBase';
import { GuardRequestContext, SecurityDecision } from '../types/context';
import { firstHeader, pickClientIp, pickSenderId } from '../utils/identity';

function readRawBody(req: any): Promise<string> {
    if (typeof req.rawBody === 'string') return Promise.resolve(req.rawBody);
    if (typeof req.body === 'string') return Promise.resolve(req.body);
    if (req.body && typeof req.body === 'object' && Object.keys(req.body).length > 0) {
        try {
            return Promise.resolve(JSON.stringify(req.body));
        } catch {
            return Promise.resolve('');
        }
    }
    if (req.readableEnded || req.complete && !req.readable) {
        return Promise.resolve('');
    }
    return new Promise((resolve, reject) => {
        const chunks: Buffer[] = [];
        req.on('data', (chunk: Buffer) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
        req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
        req.on('error', reject);
    });
}

export class HttpAdapter extends AdapterBase {
    async normalizeRequest(req: any): Promise<GuardRequestContext> {
        const headers = req.headers || {};
        const rawBody = await readRawBody(req);
        let body: any = rawBody;
        if (rawBody) {
            try { body = JSON.parse(rawBody); } catch { body = rawBody; }
        } else {
            body = req.body || {};
        }
        const ip = pickClientIp({
            trustProxy: this.trustProxy(),
            socketIp: req.socket?.remoteAddress,
            forwardedFor: headers['x-forwarded-for'],
            realIp: firstHeader(headers, 'x-real-ip')
        });
        return {
            ip,
            method: req.method || 'GET',
            path: req.url || '/',
            headers,
            query: {},
            body,
            rawBody,
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
            json: (status, body) => {
                res.writeHead(status, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(body));
            },
            redirect: (url) => {
                res.writeHead(302, { Location: url });
                res.end();
            }
        }, decision, reqCtx);
    }

    handler(): (req: any, res: any, next?: () => void) => Promise<boolean> {
        return async (req: any, res: any, next?: () => void) => {
            try {
                const reqCtx = await this.normalizeRequest(req);
                const decision = await this.guard.inspect(reqCtx);

                if (!decision.allowed) {
                    await this.handleBlock(res, decision, reqCtx);
                    return false;
                }

                if (decision.sanitizedBody) req.body = decision.sanitizedBody;
                if (next) next();
                return true;
            } catch (err: any) {
                if (!this.failClosed()) {
                    this.guard.getLogger().warn('HTTP evaluation failed, failOpen=true', err);
                    if (next) next();
                    return true;
                }
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'SECURITY_GATEWAY_ERROR' }));
                return false;
            }
        };
    }
}
