import { GuardRequestContext, RemoteAgentReport, SecurityDecision } from '../types/context';
import { ThreatIncident, newIncidentId } from '../types/threat';
import { UranoGuardConfig } from '../types/config';
import { GuardLogger, createSilentLogger, MetricsExporter } from '../types/logger';
import {
    REMOTE_PAYLOAD_FIELDS,
    AgentInvestigationComplete,
    RemoteAgentConfig,
    RemoteAgentRequestV1,
    RemoteAgentSkillRequest,
    RemoteAgentSkillResult,
    RemoteDeclaredResponseField,
    RemoteInvokeWhen,
    RemoteMappedResponse,
    RemotePayloadField
} from '../types/remoteAgent';
import { SharedStore } from '../types/store';
import { CircuitBreaker } from './CircuitBreaker';
import { isFailClosed } from './failPolicy';
import { signHmac, verifyHmacSignature } from '../utils/crypto';
import { headerValue, stringifySafe } from '../utils/inspectText';

const SENSITIVE_HEADERS = new Set(['authorization', 'cookie', 'cookie2', 'set-cookie', 'proxy-authorization']);
const DEFAULT_HEADER_ALLOWLIST = ['user-agent', 'content-type', 'accept', 'accept-language'];
const DEFAULT_THREAT_VERDICTS = ['BLOCK', 'DENY', 'CRITICAL_THREAT', 'QUARANTINE'];

function pickAgentNarrative(rec: Record<string, any>): {
    agentAnalysis?: string;
    agentReport?: RemoteAgentReport;
} {
    let agentAnalysis: string | undefined;
    if (typeof rec.analysis === 'string') agentAnalysis = rec.analysis;
    else if (typeof rec.agentAnalysis === 'string') agentAnalysis = rec.agentAnalysis;
    else if (rec.analysis && typeof rec.analysis === 'object' && typeof rec.analysis.summary === 'string') {
        agentAnalysis = rec.analysis.summary;
    }

    const raw = rec.report ?? rec.agentReport;
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
        return { agentAnalysis };
    }

    const agentReport: RemoteAgentReport = {
        title: typeof raw.title === 'string' ? raw.title : undefined,
        summary: typeof raw.summary === 'string' ? raw.summary : undefined,
        severity: typeof raw.severity === 'string' ? raw.severity : undefined,
        findings: Array.isArray(raw.findings) ? raw.findings : undefined,
        markdown: typeof raw.markdown === 'string' ? raw.markdown : undefined,
        extra: raw.extra && typeof raw.extra === 'object' && !Array.isArray(raw.extra)
            ? raw.extra as Record<string, unknown>
            : undefined
    };

    return { agentAnalysis, agentReport };
}

export interface LocalAnalysis {
    threats: ThreatIncident[];
    maxRiskScore: number;
}

type ConverseOk =
    | { ok: true; pendingInvestigate: false; data: unknown }
    | {
        ok: true;
        pendingInvestigate: true;
        data: unknown;
        requestId: string;
        sent: Set<RemotePayloadField>;
        hopsUsed: number;
    };
type ConverseFail = { ok: false; reason: string };
type ConverseResult = ConverseOk | ConverseFail;

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
        failOpen: nested.failOpen ?? (config.failClosed ? false : (config.failOpen ?? true)),
        failClosed: nested.failClosed ?? config.failClosed ?? (nested.failOpen === false || config.failOpen === false),
        invokeWhen: nested.invokeWhen ?? 'local_clean',
        minLocalScoreToInvoke: nested.minLocalScoreToInvoke ?? 30,
        maxLocalScoreToInvoke: nested.maxLocalScoreToInvoke ?? 59,
        headers: nested.headers,
        auth,
        payload: nested.payload,
        skills: nested.skills,
        memory: nested.memory,
        investigateAsync: nested.investigateAsync,
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
    private store?: SharedStore;
    private onInvestigateComplete?: (event: AgentInvestigationComplete) => void | Promise<void>;

    constructor(opts: {
        config: RemoteAgentConfig;
        circuitBreaker?: CircuitBreaker;
        logger?: GuardLogger;
        metrics?: MetricsExporter;
        securityMode?: string;
        useLegacyPayload?: boolean;
        store?: SharedStore;
        onInvestigateComplete?: (event: AgentInvestigationComplete) => void | Promise<void>;
    }) {
        this.cfg = opts.config;
        this.circuitBreaker = opts.circuitBreaker;
        this.logger = opts.logger ?? createSilentLogger();
        this.metrics = opts.metrics;
        this.securityMode = opts.securityMode;
        this.useLegacyPayload = opts.useLegacyPayload === true;
        this.store = opts.store;
        this.onInvestigateComplete = opts.onInvestigateComplete;
    }

    async query(context: GuardRequestContext, local: LocalAnalysis): Promise<SecurityDecision | null> {
        if (!this.cfg.url) return null;
        if (this.circuitBreaker && !(await this.circuitBreaker.canCallRemote())) {
            this.logger.warn(`Circuit breaker open — skipping remote agent for ${context.path}`);
            this.metrics?.increment('remoteAgentSkipped', 1, { reason: 'circuit_open' });
            return this.unavailable(context, 'circuit_open', 0);
        }

        const start = Date.now();
        const timeoutMs = this.cfg.timeoutMs ?? 1500;
        const result = await this.converse(context, local, {
            timeoutMs,
            phase: 'sync',
            checkCircuit: false
        });
        if (!result.ok) {
            return this.unavailable(context, result.reason, Date.now() - start);
        }

        if (result.pendingInvestigate) {
            const decision = this.toDecision(result.data, context, Date.now() - start);
            decision.investigationPending = true;
            void this.runInvestigate(context, local, result);
            return decision;
        }

        await this.circuitBreaker?.recordSuccess(Date.now() - start);
        this.metrics?.increment('remoteAgentSuccess', 1);
        return this.toDecision(result.data, context, Date.now() - start);
    }

    private async runInvestigate(
        context: GuardRequestContext,
        local: LocalAnalysis,
        seed: Extract<ConverseOk, { pendingInvestigate: true }>
    ): Promise<void> {
        try {
            const timeoutMs = this.cfg.investigateAsync?.timeoutMs ?? 5_000;
            const result = await this.converse(context, local, {
                timeoutMs,
                phase: 'investigate',
                checkCircuit: true,
                resume: seed
            });
            if (!result.ok) {
                this.logger.warn('Async agent investigate failed', result.reason);
                return;
            }
            const decision = this.toDecision(result.data, context, 0);
            const event: AgentInvestigationComplete = {
                requestId: seed.requestId,
                req: context,
                decision
            };
            await this.cfg.investigateAsync?.onComplete?.(event);
            await this.onInvestigateComplete?.(event);
        } catch (err) {
            this.logger.warn('Async agent investigate threw', err);
        }
    }

    private async converse(
        context: GuardRequestContext,
        local: LocalAnalysis,
        opts: {
            timeoutMs: number;
            phase: 'sync' | 'investigate';
            checkCircuit: boolean;
            resume?: Extract<ConverseOk, { pendingInvestigate: true }>;
        }
    ): Promise<ConverseResult> {
        if (opts.checkCircuit && this.circuitBreaker && !(await this.circuitBreaker.canCallRemote())) {
            return { ok: false, reason: 'circuit_open' };
        }

        const start = Date.now();
        const deadline = start + opts.timeoutMs;
        const requestId = opts.resume?.requestId ?? newIncidentId('req');
        const sent = new Set<RemotePayloadField>(opts.resume?.sent ?? this.initialInclude());
        const memory = await this.loadMemory(context);
        const maxFollow = this.maxFollowUps();
        let hopsUsed = opts.resume?.hopsUsed ?? 0;
        let data: unknown = opts.resume?.data;
        const legacy = !!(this.cfg.buildPayload || this.useLegacyPayload);

        if (!opts.resume) {
            const first = await this.postOnce(context, local, {
                requestId,
                include: sent,
                followUp: false,
                remainingMs: opts.timeoutMs,
                memory,
                phase: opts.phase
            });
            if (!first.ok) return first;
            data = first.data;
            await this.persistMemory(context, data);
        }

        for (let step = 0; step <= maxFollow; step++) {
            const need = !legacy ? parseNeed(data) : null;
            const canAsync = opts.phase === 'sync'
                && this.cfg.investigateAsync?.enabled === true
                && hasEnforcementVerdict(data)
                && wantsInvestigate(data)
                && !legacy;

            if (canAsync) {
                return {
                    ok: true,
                    pendingInvestigate: true,
                    data,
                    requestId,
                    sent,
                    hopsUsed
                };
            }

            if (!need) {
                return { ok: true, pendingInvestigate: false, data };
            }

            if (hopsUsed >= maxFollow) {
                if (hasEnforcementVerdict(data)) {
                    return { ok: true, pendingInvestigate: false, data };
                }
                this.logger.warn('Remote agent exceeded maxFollowUps');
                return { ok: false, reason: 'need_loop' };
            }

            const { grant, denied } = this.grantNeed(need.fields, sent);
            const skillRun = await this.runSkills(need.skills, context, local);
            if (!grant.length && !skillRun.results.length) {
                if (hasEnforcementVerdict(data)) {
                    return { ok: true, pendingInvestigate: false, data };
                }
                this.logger.warn('Remote agent NEED listed no declared fields/skills', {
                    denied,
                    deniedSkills: skillRun.denied
                });
                return { ok: false, reason: 'need_undeclared' };
            }

            const remainingMs = deadline - Date.now();
            if (remainingMs < 50) return { ok: false, reason: 'timeout' };
            for (const field of grant) sent.add(field);
            hopsUsed += 1;
            const next = await this.postOnce(context, local, {
                requestId,
                include: sent,
                followUp: true,
                denied,
                deniedSkills: skillRun.denied,
                skillResults: skillRun.results,
                remainingMs,
                memory: await this.loadMemory(context),
                phase: opts.phase
            });
            if (!next.ok) return next;
            data = next.data;
            await this.persistMemory(context, data);
        }

        if (hasEnforcementVerdict(data)) {
            return { ok: true, pendingInvestigate: false, data };
        }
        return { ok: false, reason: 'need_loop' };
    }

    private maxFollowUps(): number {
        const n = this.cfg.payload?.maxFollowUps;
        if (n === undefined) return 1;
        return Math.min(4, Math.max(1, Math.floor(n)));
    }

    private memoryKey(context: GuardRequestContext): string {
        const custom = this.cfg.memory?.key?.(context);
        return `ug:agent:mem:${custom || context.senderId || context.ip}`;
    }

    private async loadMemory(context: GuardRequestContext): Promise<unknown> {
        if (this.cfg.memory?.enabled === false || !this.store) return undefined;
        if (!this.cfg.memory?.enabled && !this.cfg.memory) return undefined;
        if (!this.cfg.memory?.enabled) return undefined;
        return this.store.get(this.memoryKey(context));
    }

    private async persistMemory(context: GuardRequestContext, data: unknown): Promise<void> {
        if (!this.cfg.memory?.enabled || !this.store) return;
        if (!data || typeof data !== 'object') return;
        const rec = data as Record<string, unknown>;
        const blob = rec.remember ?? rec.memory;
        if (blob === undefined) return;
        const maxBytes = this.cfg.memory.maxBytes ?? 4_096;
        const { data: clipped } = clipSkillData(blob, maxBytes);
        await this.store.set(this.memoryKey(context), clipped, this.cfg.memory.ttlMs ?? 30 * 60_000);
    }

    private async postOnce(
        context: GuardRequestContext,
        local: LocalAnalysis,
        hop: {
            requestId: string;
            include: Set<RemotePayloadField>;
            followUp: boolean;
            denied?: RemotePayloadField[];
            deniedSkills?: string[];
            skillResults?: RemoteAgentSkillResult[];
            remainingMs: number;
            memory?: unknown;
            phase?: 'sync' | 'investigate';
        }
    ): Promise<{ ok: true; data: unknown } | { ok: false; reason: string }> {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), hop.remainingMs);
        try {
            const payload = this.buildBody(context, local, hop);
            const bodyStr = JSON.stringify(payload);
            const res = await fetch(this.cfg.url!, {
                method: 'POST',
                headers: this.buildHeaders(bodyStr),
                body: bodyStr,
                signal: controller.signal
            });
            clearTimeout(timeoutId);

            if (!res.ok) {
                await this.circuitBreaker?.recordFailure();
                this.metrics?.increment('remoteAgentFailure', 1, { reason: 'http' });
                return { ok: false, reason: 'http' };
            }

            const rawText = await res.text();
            const hmacSecret = this.cfg.response?.hmacSecret;
            if (hmacSecret) {
                const headerName = this.cfg.response?.hmacHeader || 'x-urano-signature';
                const signature = res.headers.get(headerName) || '';
                if (!verifyHmacSignature(rawText, signature, hmacSecret)) {
                    await this.circuitBreaker?.recordFailure();
                    this.metrics?.increment('remoteAgentFailure', 1, { reason: 'bad_hmac' });
                    this.logger.warn('Remote agent response HMAC mismatch');
                    return { ok: false, reason: 'bad_hmac' };
                }
            }

            try {
                return { ok: true, data: JSON.parse(rawText) };
            } catch {
                await this.circuitBreaker?.recordFailure();
                this.metrics?.increment('remoteAgentFailure', 1, { reason: 'invalid_json' });
                return { ok: false, reason: 'invalid_json' };
            }
        } catch (err) {
            clearTimeout(timeoutId);
            await this.circuitBreaker?.recordFailure();
            this.metrics?.increment('remoteAgentFailure', 1, { reason: 'network' });
            this.logger.warn('Remote agent request failed', err);
            return { ok: false, reason: 'network' };
        }
    }

    private initialInclude(): RemotePayloadField[] {
        return this.cfg.payload?.include || [
            'ip', 'senderId', 'method', 'path', 'query', 'body', 'headers', 'localThreats', 'securityMode'
        ];
    }

    private grantNeed(
        need: RemotePayloadField[],
        already: Set<RemotePayloadField>
    ): { grant: RemotePayloadField[]; denied: RemotePayloadField[] } {
        const allowed = new Set(this.cfg.payload?.onRequest || []);
        const grant: RemotePayloadField[] = [];
        const denied: RemotePayloadField[] = [];
        for (const field of need) {
            if (already.has(field)) continue;
            if (allowed.has(field)) grant.push(field);
            else denied.push(field);
        }
        return { grant, denied };
    }

    private async runSkills(
        asks: RemoteAgentSkillRequest[],
        context: GuardRequestContext,
        local: LocalAnalysis
    ): Promise<{ results: RemoteAgentSkillResult[]; denied: string[] }> {
        const catalog = this.cfg.skills?.catalog || {};
        const maxBytes = this.cfg.skills?.maxResultBytes ?? 16_384;
        const results: RemoteAgentSkillResult[] = [];
        const denied: string[] = [];
        const seen = new Set<string>();

        for (const ask of asks) {
            if (!ask.name || seen.has(ask.name)) continue;
            seen.add(ask.name);
            const skill = catalog[ask.name];
            if (!skill || typeof skill.provide !== 'function') {
                denied.push(ask.name);
                continue;
            }
            try {
                const raw = await skill.provide(ask.args, context, local);
                const { data, truncated } = clipSkillData(raw, maxBytes);
                results.push({ name: ask.name, ok: true, data, truncated });
            } catch (err) {
                this.logger.warn(`Remote agent skill '${ask.name}' failed`, err);
                results.push({
                    name: ask.name,
                    ok: false,
                    error: err instanceof Error ? err.message : 'provide_failed'
                });
            }
        }
        return { results, denied };
    }

    private unavailable(context: GuardRequestContext, reason: string, latencyMs: number): SecurityDecision | null {
        if (!isFailClosed(this.cfg)) return null;
        return {
            allowed: false,
            action: 'BLOCK',
            riskScore: 100,
            threats: [{
                id: newIncidentId('thr_failclosed'),
                category: 'REMOTE_AGENT_VERDICT',
                severity: 'CRITICAL',
                riskScore: 100,
                summary: `Remote agent unavailable (${reason}) and failClosed is enabled`,
                detectedAt: new Date().toISOString(),
                sender: context.senderId || context.ip
            }],
            reason: `Remote agent unavailable (failClosed): ${reason}`,
            latencyMs,
            source: 'FALLBACK'
        };
    }

    private buildBody(
        context: GuardRequestContext,
        local: LocalAnalysis,
        hop?: {
            requestId: string;
            include: Set<RemotePayloadField>;
            followUp: boolean;
            denied?: RemotePayloadField[];
            deniedSkills?: string[];
            skillResults?: RemoteAgentSkillResult[];
            memory?: unknown;
            phase?: 'sync' | 'investigate';
        }
    ): unknown {
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

        const include = hop?.include ?? new Set(this.initialInclude());
        const maxBody = this.cfg.payload?.maxBodyBytes ?? 32_768;
        const requestId = hop?.requestId ?? newIncidentId('req');

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

        const onRequest = this.cfg.payload?.onRequest || [];
        const canDisclose = onRequest.filter(field => !include.has(field));
        const canInvoke = Object.keys(this.cfg.skills?.catalog || {});
        const hasCaps = onRequest.length > 0 || canInvoke.length > 0;

        const envelope: RemoteAgentRequestV1 = {
            schemaVersion: '1.0',
            source: 'urano-guard',
            requestId,
            request,
            memory: hop?.memory,
            followUp: hop?.followUp === true ? true : undefined,
            phase: hop?.phase,
            capabilities: hasCaps
                ? {
                    canDisclose,
                    canInvoke,
                    maxFollowUps: Math.min(4, Math.max(1, Math.floor(this.cfg.payload?.maxFollowUps ?? 1)))
                }
                : undefined,
            denied: hop?.denied?.length ? hop.denied : undefined,
            deniedSkills: hop?.deniedSkills?.length ? hop.deniedSkills : undefined,
            skillResults: hop?.skillResults?.length ? hop.skillResults : undefined
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

        const narrative = pickAgentNarrative(rec);
        const declared = declaredExtras(this.cfg.response?.include);

        return applyDeclared({
            allowed,
            action,
            riskScore: score,
            threats,
            reason,
            latencyMs,
            source: 'REMOTE_AGENT',
            agentAnalysis: narrative.agentAnalysis,
            agentReport: narrative.agentReport
        }, declared);
    }

    private fromMapped(mapped: RemoteMappedResponse, context: GuardRequestContext, latencyMs: number): SecurityDecision {
        return applyDeclared({
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
            source: 'REMOTE_AGENT',
            agentAnalysis: mapped.agentAnalysis,
            agentReport: mapped.agentReport
        }, declaredExtras(this.cfg.response?.include));
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

function isPayloadField(value: unknown): value is RemotePayloadField {
    return typeof value === 'string' && (REMOTE_PAYLOAD_FIELDS as readonly string[]).includes(value);
}

function parseSkillAsks(raw: unknown): RemoteAgentSkillRequest[] {
    if (!Array.isArray(raw)) return [];
    const out: RemoteAgentSkillRequest[] = [];
    for (const item of raw) {
        if (typeof item === 'string' && item) {
            out.push({ name: item });
            continue;
        }
        if (item && typeof item === 'object' && typeof (item as { name?: unknown }).name === 'string') {
            const name = (item as { name: string }).name;
            if (!name) continue;
            const args = (item as { args?: unknown }).args;
            out.push({
                name,
                args: args && typeof args === 'object' && !Array.isArray(args)
                    ? args as Record<string, unknown>
                    : undefined
            });
        }
    }
    return out;
}

function parseNeed(data: unknown): { fields: RemotePayloadField[]; skills: RemoteAgentSkillRequest[] } | null {
    if (!data || typeof data !== 'object') return null;
    const rec = data as Record<string, unknown>;
    const verdict = String(rec.verdict ?? '').toUpperCase();
    const investigate = rec.investigate === true || rec.pendingReport === true;
    if (verdict && verdict !== 'NEED' && !investigate) return null;
    const raw = rec.need ?? rec.requestFields ?? rec.disclose;
    const fields = Array.isArray(raw) ? raw.filter(isPayloadField) : [];
    const skills = parseSkillAsks(rec.skills);
    if (!fields.length && !skills.length) return null;
    return { fields, skills };
}

function clipSkillData(value: unknown, maxBytes: number): { data: unknown; truncated?: boolean } {
    if (typeof value === 'string') {
        return value.length > maxBytes
            ? { data: value.slice(0, maxBytes), truncated: true }
            : { data: value };
    }
    const encoded = stringifySafe(value, maxBytes);
    if (!encoded) return { data: value };
    if (encoded.length <= maxBytes) return { data: value };
    return { data: encoded.slice(0, maxBytes), truncated: true };
}

function wantsInvestigate(data: unknown): boolean {
    if (!data || typeof data !== 'object') return false;
    const rec = data as Record<string, unknown>;
    return rec.investigate === true || rec.pendingReport === true;
}

function hasEnforcementVerdict(data: unknown): boolean {
    if (!data || typeof data !== 'object') return false;
    const rec = data as Record<string, unknown>;
    if (typeof rec.allowed === 'boolean') return true;
    const verdict = String(rec.verdict ?? '').toUpperCase();
    return verdict === 'ALLOW' || verdict === 'OK' || verdict === 'BLOCK' || verdict === 'DENY'
        || verdict === 'MONITOR' || verdict === 'QUARANTINE' || verdict === 'CRITICAL_THREAT';
}

function declaredExtras(include?: RemoteDeclaredResponseField[]): Set<RemoteDeclaredResponseField> {
    if (!include) return new Set(['reason', 'threats', 'analysis', 'report']);
    return new Set(include);
}

function applyDeclared(decision: SecurityDecision, declared: Set<RemoteDeclaredResponseField>): SecurityDecision {
    if (!declared.has('reason')) decision.reason = undefined;
    if (!declared.has('threats')) decision.threats = [];
    if (!declared.has('analysis')) decision.agentAnalysis = undefined;
    if (!declared.has('report')) decision.agentReport = undefined;
    return decision;
}
