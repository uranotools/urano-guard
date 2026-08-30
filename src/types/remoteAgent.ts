import { GuardRequestContext, SecurityDecision } from './context';
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
    include?: RemotePayloadField[];
    headerAllowlist?: string[];
    headerDenylist?: string[];
    maxBodyBytes?: number;
    extra?: Record<string, unknown> | ((ctx: GuardRequestContext) => Record<string, unknown>);
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
}

export interface RemoteMappedResponse {
    allowed: boolean;
    riskScore: number;
    reason?: string;
    action?: SecurityDecision['action'];
    threats?: ThreatIncident[];
}

export interface RemoteAgentConfig {
    url?: string;
    timeoutMs?: number;
    failOpen?: boolean;
    invokeWhen?: RemoteInvokeWhen;
    minLocalScoreToInvoke?: number;
    maxLocalScoreToInvoke?: number;
    headers?: Record<string, string>;
    auth?: RemoteAgentAuthConfig;
    payload?: RemoteAgentPayloadConfig;
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
}
