import { GuardRequestContext, SecurityDecision } from '../types/context';
import { ThreatIncident, newIncidentId } from '../types/threat';
import { UranoGuardConfig } from '../types/config';
import { GuardLogger, createSilentLogger, MetricsExporter } from '../types/logger';
import {
    RemoteAgentConfig,
    RemoteAgentRequestV1,
    RemoteInvokeWhen,
    RemoteMappedResponse,
    RemotePayloadField
} from '../types/remoteAgent';
import { CircuitBreaker } from './CircuitBreaker';
import { signHmac, verifyHmacSignature } from '../utils/crypto';
import { headerValue, stringifySafe } from '../utils/inspectText';

const SENSITIVE_HEADERS = new Set(['authorization', 'cookie', 'cookie2', 'set-cookie', 'proxy-authorization']);
const DEFAULT_HEADER_ALLOWLIST = ['user-agent', 'content-type', 'accept', 'accept-language'];
const DEFAULT_THREAT_VERDICTS = ['BLOCK', 'DENY', 'CRITICAL_THREAT', 'QUARANTINE'];

export interface LocalAnalysis {
    threats: ThreatIncident[];
    maxRiskScore: number;
}

export function resolveRemoteAgentConfig(config: UranoGuardConfig): RemoteAgentConfig | null {
    const nested = config.remoteAgent || {};
    const url = nested.url || config.agentWebhookUrl;
    if (!url) return null;

    const auth = nested.auth || (
        config.apiKey
            ? { type: 'bearer' as const, token: config.apiKey }
            : config.incomingSecret
                ? { type: 'hmac' as const, hmacSecret: config.incomingSecret, hmacHeader: 'x-urano-signature' }
                : undefined
    );

    return {
        url,
        timeoutMs: nested.timeoutMs ?? config.timeoutMs ?? 1500,
        failOpen: nested.failOpen ?? config.failOpen ?? true,
        invokeWhen: nested.invokeWhen ?? 'local_clean',
        minLocalScoreToInvoke: nested.minLocalScoreToInvoke ?? 30,
        maxLocalScoreToInvoke: nested.maxLocalScoreToInvoke ?? 59,
        headers: nested.headers,
        auth,
        payload: nested.payload,
        response: nested.response,
        buildPayload: nested.buildPayload,
        mapResponse: nested.mapResponse
    };
}

export function shouldInvokeRemoteWithRange(
    invokeWhen: RemoteInvokeWhen | undefined,
    local: LocalAnalysis,
    minScore: number,
    maxScore: number
): boolean {
    const mode = invokeWhen || 'local_clean';
    if (mode === 'always') return true;
    if (mode === 'local_clean') return local.threats.length === 0;
    return local.maxRiskScore >= minScore && local.maxRiskScore <= maxScore;
}

export class RemoteAgentClient {
    private cfg: RemoteAgentConfig;
    private circuitBreaker?: CircuitBreaker;
    private logger: GuardLogger;
    private metrics?: MetricsExporter;
    private securityMode?: string;
    private useLegacyPayload: boolean;

    constructor(opts: {
        config: RemoteAgentConfig;
        circuitBreaker?: CircuitBreaker;
        logger?: GuardLogger;
        metrics?: MetricsExporter;
        securityMode?: string;
        useLegacyPayload?: boolean;
    }) {
        this.cfg = opts.config;
        this.circuitBreaker = opts.circuitBreaker;
        this.logger = opts.logger ?? createSilentLogger();
        this.metrics = opts.metrics;
        this.securityMode = opts.securityMode;
        this.useLegacyPayload = opts.useLegacyPayload === true;
    }

    async query(context: GuardRequestContext, local: LocalAnalysis): Promise<SecurityDecision | null> {
        if (!this.cfg.url) return null;
        if (this.circuitBreaker && !this.circuitBreaker.canCallRemote()) {
            this.logger.warn(`Circuit breaker open — skipping remote agent for ${context.path}`);
            this.metrics?.increment('remoteAgentSkipped', 1, { reason: 'circuit_open' });
            return null;
        }

        const start = Date.now();
        const timeoutMs = this.cfg.timeoutMs ?? 1500;
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

        try {
            const payload = this.buildBody(context, local);
            const bodyStr = JSON.stringify(payload);
            const headers = this.buildHeaders(bodyStr);

            const res = await fetch(this.cfg.url, {
                method: 'POST',
                headers,
                body: bodyStr,
                signal: controller.signal
            });

            clearTimeout(timeoutId);
            const latencyMs = Date.now() - start;
            this.metrics?.observe?.('remoteAgentLatency', latencyMs);

            if (!res.ok) {
                this.circuitBreaker?.recordFailure();
                this.metrics?.increment('remoteAgentFailure', 1, { reason: 'http' });
                return null;
            }

            const rawText = await res.text();
            const hmacSecret = this.cfg.response?.hmacSecret;
            if (hmacSecret) {
                const headerName = this.cfg.response?.hmacHeader || 'x-urano-signature';
                const signature = res.headers.get(headerName) || '';
                if (!verifyHmacSignature(rawText, signature, hmacSecret)) {
                    this.circuitBreaker?.recordFailure();
                    this.metrics?.increment('remoteAgentFailure', 1, { reason: 'bad_hmac' });
                    this.logger.warn('Remote agent response HMAC mismatch');
                    return null;
                }
            }

            let data: unknown;
            try {
                data = JSON.parse(rawText);
            } catch {
                this.circuitBreaker?.recordFailure();
                this.metrics?.increment('remoteAgentFailure', 1, { reason: 'invalid_json' });
                return null;
            }

            this.circuitBreaker?.recordSuccess(latencyMs);
            this.metrics?.increment('remoteAgentSuccess', 1);
            return this.toDecision(data, context, latencyMs);
        } catch (err) {
            clearTimeout(timeoutId);
            this.circuitBreaker?.recordFailure();
            this.metrics?.increment('remoteAgentFailure', 1, { reason: 'network' });
            this.logger.warn('Remote agent request failed', err);
            return null;
        }
    }

    private buildBody(context: GuardRequestContext, local: LocalAnalysis): unknown {
        if (this.cfg.buildPayload) {
            return this.cfg.buildPayload(context, local);
        }
        if (this.useLegacyPayload && !this.cfg.payload) {
            return {
                sender: context.senderId || context.ip,
                content: context.body,
                path: context.path,
                method: context.method
            };
        }

        const include = new Set<RemotePayloadField>(
            this.cfg.payload?.include || [
                'ip', 'senderId', 'method', 'path', 'query', 'body', 'headers', 'localThreats', 'securityMode'
            ]
        );
        const maxBody = this.cfg.payload?.maxBodyBytes ?? 32_768;
        const requestId = newIncidentId('req');

        const request: RemoteAgentRequestV1['request'] = {};
        if (include.has('ip')) request.ip = context.ip;
        if (include.has('senderId')) request.senderId = context.senderId || context.ip;
        if (include.has('method')) request.method = context.method;
        if (include.has('path')) request.path = context.path;
        if (include.has('query')) request.query = context.query;
        if (include.has('body')) request.body = this.truncate(context.body, maxBody);
        if (include.has('rawBody') && context.rawBody) {
            request.rawBody = context.rawBody.length > maxBody ? context.rawBody.slice(0, maxBody) : context.rawBody;
        }
        if (include.has('headers')) {
            request.headers = this.filterHeaders(context.headers);
        }

        const envelope: RemoteAgentRequestV1 = {
            schemaVersion: '1.0',
            source: 'urano-guard',
            requestId,
            request
        };

        if (include.has('localThreats') || include.has('securityMode')) {
            envelope.localAnalysis = {
                threats: include.has('localThreats') ? local.threats : [],
                maxRiskScore: local.maxRiskScore,
                securityMode: include.has('securityMode') ? this.securityMode : undefined
            };
        }

        const extraCfg = this.cfg.payload?.extra;
        if (extraCfg) {
            envelope.extra = typeof extraCfg === 'function' ? extraCfg(context) : extraCfg;
        }

        return envelope;
    }

    private truncate(value: unknown, maxBytes: number): unknown {
        if (typeof value === 'string') {
            return value.length > maxBytes ? value.slice(0, maxBytes) : value;
        }
        const encoded = stringifySafe(value, maxBytes);
        if (!encoded) return value;
        if (encoded.length <= maxBytes) return value;
        return encoded.slice(0, maxBytes);
    }

    private filterHeaders(
        headers: Record<string, string | string[] | undefined> | undefined
    ): Record<string, string> {
        const allow = (this.cfg.payload?.headerAllowlist || DEFAULT_HEADER_ALLOWLIST).map(h => h.toLowerCase());
        const deny = new Set((this.cfg.payload?.headerDenylist || []).map(h => h.toLowerCase()));
        const out: Record<string, string> = {};
        for (const name of allow) {
            if (deny.has(name)) continue;
            if (SENSITIVE_HEADERS.has(name) && !allow.includes(name)) continue;
            const value = headerValue(headers, name);
            if (value) out[name] = value;
        }
        return out;
    }

    private buildHeaders(bodyStr: string): Record<string, string> {
        const headers: Record<string, string> = {
            'Content-Type': 'application/json',
            ...(this.cfg.headers || {})
        };
        const auth = this.cfg.auth;
        if (auth?.type === 'bearer' && auth.token) {
            headers.Authorization = `Bearer ${auth.token}`;
        } else if (auth?.type === 'header' && auth.headerName && auth.headerValue) {
            headers[auth.headerName] = auth.headerValue;
        } else if (auth?.type === 'hmac' && auth.hmacSecret) {
            headers[auth.hmacHeader || 'x-urano-signature'] = signHmac(bodyStr, auth.hmacSecret, auth.algorithm || 'sha256');
        }
        return headers;
    }

    private toDecision(data: unknown, context: GuardRequestContext, latencyMs: number): SecurityDecision {
        if (this.cfg.mapResponse) {
            const mapped = this.cfg.mapResponse(data);
            return this.fromMapped(mapped, context, latencyMs);
        }

        const rec = (data && typeof data === 'object') ? data as Record<string, any> : {};
        const fields = this.cfg.response || {};
        const allowedField = fields.allowedField || 'allowed';
        const verdictField = fields.verdictField || 'verdict';
        const scoreField = fields.riskScoreField || 'riskScore';
        const reasonField = fields.reasonField || 'reason';
        const actionField = fields.actionField || 'action';
        const threatVerdicts = (fields.threatVerdicts || DEFAULT_THREAT_VERDICTS).map(v => v.toUpperCase());

        const verdict = String(rec[verdictField] ?? '').toUpperCase();
        let allowed: boolean;
        if (typeof rec[allowedField] === 'boolean') {
            allowed = rec[allowedField];
        } else if (verdict) {
            allowed = !threatVerdicts.includes(verdict) && verdict !== 'MONITOR';
            if (verdict === 'ALLOW' || verdict === 'OK') allowed = true;
            if (verdict === 'MONITOR') allowed = true;
        } else {
            allowed = Number(rec[scoreField] || 0) < 60;
        }

        const riskScore = Number(rec[scoreField]);
        const score = Number.isFinite(riskScore) ? riskScore : (allowed ? 0 : 80);
        const action = this.normalizeAction(rec[actionField], verdict, allowed);
        const reason = rec[reasonField];

        const threats: ThreatIncident[] = Array.isArray(rec.threats)
            ? rec.threats
            : (!allowed ? [{
                id: newIncidentId('thr_rem'),
                category: 'REMOTE_AGENT_VERDICT',
                severity: score >= 80 ? 'CRITICAL' : 'HIGH',
                riskScore: score,
                summary: reason || 'Blocked by remote security agent',
                detectedAt: new Date().toISOString(),
                sender: context.senderId || context.ip
            }] : []);

        return {
            allowed,
            action,
            riskScore: score,
            threats,
            reason,
            latencyMs,
            source: 'REMOTE_AGENT'
        };
    }

    private fromMapped(mapped: RemoteMappedResponse, context: GuardRequestContext, latencyMs: number): SecurityDecision {
        return {
            allowed: mapped.allowed,
            action: mapped.action || (mapped.allowed ? 'ALLOW' : 'BLOCK'),
            riskScore: mapped.riskScore,
            threats: mapped.threats || (!mapped.allowed ? [{
                id: newIncidentId('thr_rem'),
                category: 'REMOTE_AGENT_VERDICT',
                severity: 'HIGH',
                riskScore: mapped.riskScore,
                summary: mapped.reason || 'Blocked by remote security agent',
                detectedAt: new Date().toISOString(),
                sender: context.senderId || context.ip
            }] : []),
            reason: mapped.reason,
            latencyMs,
            source: 'REMOTE_AGENT'
        };
    }

    private normalizeAction(
        raw: unknown,
        verdict: string,
        allowed: boolean
    ): SecurityDecision['action'] {
        const value = String(raw || verdict || '').toUpperCase();
        if (value === 'QUARANTINE') return 'QUARANTINE';
        if (value === 'REDIRECT') return 'REDIRECT';
        if (value === 'MONITOR') return 'MONITOR';
        if (value === 'BLOCK' || value === 'DENY' || value === 'CRITICAL_THREAT') return 'BLOCK';
        return allowed ? 'ALLOW' : 'BLOCK';
    }
}
