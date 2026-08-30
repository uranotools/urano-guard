import { GuardRequestContext, RemoteAgentReport, SecurityDecision } from './context';
import { ThreatIncident } from './threat';

export type RemoteInvokeWhen = 'local_clean' | 'local_suspicious' | 'always';
export type RemoteAuthType = 'bearer' | 'header' | 'hmac';
export type RemotePayloadField =
    | 'ip'
    | 'senderId'
    | 'method'
    | 'path'
    | 'query'
    | 'body'
    | 'rawBody'
    | 'headers'
    | 'localThreats'
    | 'fingerprint'
    | 'securityMode';

/** Extra fields the agent may put on the decision. Enforcement (verdict / score) is always read. */
export type RemoteDeclaredResponseField =
    | 'reason'
    | 'threats'
    | 'analysis'
    | 'report';

export const REMOTE_PAYLOAD_FIELDS: readonly RemotePayloadField[] = [
    'ip', 'senderId', 'method', 'path', 'query', 'body', 'rawBody',
    'headers', 'localThreats', 'fingerprint', 'securityMode'
];

export const REMOTE_DECLARED_RESPONSE_FIELDS: readonly RemoteDeclaredResponseField[] = [
    'reason', 'threats', 'analysis', 'report'
];

export interface RemoteAgentAuthConfig {
    type: RemoteAuthType;
    token?: string;
    headerName?: string;
    headerValue?: string;
    hmacSecret?: string;
    hmacHeader?: string;
    algorithm?: string;
}

export interface RemoteAgentPayloadConfig {
    /** Fields sent on the first hop. */
    include?: RemotePayloadField[];
    /**
     * Fields the agent may ask for later (`verdict: "NEED"` + `need: [...]`).
     * Intersection only — Guard never sends a field that is not listed here
     * (or already in `include`). Empty / omitted = no follow-up hop.
     */
    onRequest?: RemotePayloadField[];
    headerAllowlist?: string[];
    headerDenylist?: string[];
    maxBodyBytes?: number;
    extra?: Record<string, unknown> | ((ctx: GuardRequestContext) => Record<string, unknown>);
    /**
     * Extra NEED hops after the first POST (default 1, hard cap 4).
     * Shared with `timeoutMs` unless investigateAsync uses its own budget.
     */
    maxFollowUps?: number;
}

/**
 * A skill your integration implements. The agent may invoke it by name
 * on a NEED hop. Guard does not ship log collectors — you provide them.
 */
export interface RemoteAgentSkill {
    description?: string;
    provide: (
        args: Record<string, unknown> | undefined,
        ctx: GuardRequestContext,
        local: { threats: ThreatIncident[]; maxRiskScore: number }
    ) => unknown | Promise<unknown>;
}

export interface RemoteAgentSkillsConfig {
    /** Declared catalog. Unknown names the agent asks for are denied. */
    catalog: Record<string, RemoteAgentSkill>;
    /** Truncate each skill payload (default 16 KiB). */
    maxResultBytes?: number;
}

export interface RemoteAgentSkillRequest {
    name: string;
    args?: Record<string, unknown>;
}

export interface RemoteAgentSkillResult {
    name: string;
    ok: boolean;
    data?: unknown;
    error?: string;
    truncated?: boolean;
}

export interface RemoteAgentResponseConfig {
    verdictField?: string;
    riskScoreField?: string;
    reasonField?: string;
    allowedField?: string;
    actionField?: string;
    threatVerdicts?: string[];
    hmacSecret?: string;
    hmacHeader?: string;
    /**
     * Declared extras the agent is allowed to return.
     * Omitted = all extras (`reason`, `threats`, `analysis`, `report`).
     * `[]` = verdict / score only (no analysis, no report).
     */
    include?: RemoteDeclaredResponseField[];
}

export interface RemoteAgentMemoryConfig {
    enabled?: boolean;
    key?: (ctx: GuardRequestContext) => string;
    maxBytes?: number;
    ttlMs?: number;
}

export interface AgentInvestigationComplete {
    requestId: string;
    req: GuardRequestContext;
    decision: SecurityDecision;
}

export interface RemoteAgentInvestigateAsyncConfig {
    enabled?: boolean;
    timeoutMs?: number;
    onComplete?: (event: AgentInvestigationComplete) => void | Promise<void>;
}

export interface RemoteMappedResponse {
    allowed: boolean;
    riskScore: number;
    reason?: string;
    action?: SecurityDecision['action'];
    threats?: ThreatIncident[];
    agentAnalysis?: string;
    agentReport?: RemoteAgentReport;
}

export interface RemoteAgentConfig {
    url?: string;
    timeoutMs?: number;
    failOpen?: boolean;
    failClosed?: boolean;
    invokeWhen?: RemoteInvokeWhen;
    minLocalScoreToInvoke?: number;
    maxLocalScoreToInvoke?: number;
    headers?: Record<string, string>;
    auth?: RemoteAgentAuthConfig;
    payload?: RemoteAgentPayloadConfig;
    /** On-demand providers (logs, chunks, tenant lookup). Agent must NEED them by name. */
    skills?: RemoteAgentSkillsConfig;
    /**
     * Cross-request blob in SharedStore (`ug:agent:mem:`). The agent may
     * return `remember` / `memory`; the next inspect() sends it back.
     */
    memory?: RemoteAgentMemoryConfig;
    /**
     * If the agent returns a verdict plus `investigate: true`, Guard
     * answers the HTTP request now and continues NEED/report in the
     * background (`onComplete` / EventBus `agentInvestigationComplete`).
     */
    investigateAsync?: RemoteAgentInvestigateAsyncConfig;
    response?: RemoteAgentResponseConfig;
    buildPayload?: (
        ctx: GuardRequestContext,
        local: { threats: ThreatIncident[]; maxRiskScore: number }
    ) => unknown;
    mapResponse?: (json: unknown) => RemoteMappedResponse;
}

export interface RemoteAgentRequestV1 {
    schemaVersion: '1.0';
    source: 'urano-guard';
    requestId: string;
    request: {
        ip?: string;
        senderId?: string;
        method?: string;
        path?: string;
        query?: Record<string, unknown>;
        body?: unknown;
        rawBody?: string;
        headers?: Record<string, string>;
    };
    localAnalysis?: {
        threats: ThreatIncident[];
        maxRiskScore: number;
        securityMode?: string;
    };
    extra?: Record<string, unknown>;
    fingerprint?: string;
    /** Prior `remember` blob for this sender (store-backed). */
    memory?: unknown;
    followUp?: boolean;
    phase?: 'sync' | 'investigate';
    capabilities?: {
        canDisclose: RemotePayloadField[];
        canInvoke: string[];
        maxFollowUps: number;
    };
    denied?: RemotePayloadField[];
    deniedSkills?: string[];
    skillResults?: RemoteAgentSkillResult[];
}
