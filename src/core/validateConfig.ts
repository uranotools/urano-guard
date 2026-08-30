import { InspectorFlags, SecurityMode, UranoGuardConfig } from '../types/config';
import {
    REMOTE_DECLARED_RESPONSE_FIELDS,
    REMOTE_PAYLOAD_FIELDS
} from '../types/remoteAgent';

const SECURITY_MODES: SecurityMode[] = ['block_threats', 'monitor_only', 'strict_zero_trust', 'quarantine'];
const DEFAULT_ACTIONS = ['block', 'monitor', 'quarantine', 'allow'] as const;

const INSPECTOR_BOOL_FLAGS: (keyof InspectorFlags)[] = [
    'promptInjection',
    'maliciousUrls',
    'sqlAndCommands',
    'sqlInjection',
    'commandInjection',
    'xss',
    'botFuzzing',
    'piiDataMasking',
    'paddingEvasion',
    'jwtTampering',
    'graphqlAbuse'
];

const KNOWN_INSPECTOR_KEYS = new Set<string>([...INSPECTOR_BOOL_FLAGS, 'maliciousUrlsAllowHosts']);

export class ConfigValidationError extends Error {
    constructor(message: string) {
        super(`UranoGuard config: ${message}`);
        this.name = 'ConfigValidationError';
    }
}

function isHttpUrl(value: string): boolean {
    try {
        const parsed = new URL(value);
        return parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch {
        return false;
    }
}

function assertPositiveNumber(name: string, value: unknown): void {
    if (value === undefined) return;
    if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
        throw new ConfigValidationError(`${name} must be a positive finite number`);
    }
}

function assertNonNegativeNumber(name: string, value: unknown): void {
    if (value === undefined) return;
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
        throw new ConfigValidationError(`${name} must be a finite number >= 0`);
    }
}

function assertScore(name: string, value: unknown): void {
    if (value === undefined) return;
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 100) {
        throw new ConfigValidationError(`${name} must be a number between 0 and 100`);
    }
}

function assertHttpUrl(name: string, value: unknown): void {
    if (value === undefined || value === '') return;
    if (typeof value !== 'string' || !isHttpUrl(value)) {
        throw new ConfigValidationError(`${name} must be a valid http(s) URL`);
    }
}

function validateInspectors(flags: InspectorFlags): void {
    for (const key of Object.keys(flags)) {
        if (!KNOWN_INSPECTOR_KEYS.has(key)) {
            throw new ConfigValidationError(`unknown inspector flag '${key}'`);
        }
    }
    for (const flag of INSPECTOR_BOOL_FLAGS) {
        const value = flags[flag];
        if (value !== undefined && typeof value !== 'boolean') {
            throw new ConfigValidationError(`inspectors.${flag} must be a boolean`);
        }
    }
    const hosts = flags.maliciousUrlsAllowHosts;
    if (hosts !== undefined) {
        if (!Array.isArray(hosts) || hosts.some(host => typeof host !== 'string')) {
            throw new ConfigValidationError('inspectors.maliciousUrlsAllowHosts must be an array of strings');
        }
    }
}

/** Throws ConfigValidationError when construct-time options are invalid. */
export function validateConfig(config: UranoGuardConfig): void {
    if (config.failClosed === true && config.failOpen === true) {
        throw new ConfigValidationError('failClosed and failOpen cannot both be true');
    }

    if (config.securityMode !== undefined && !SECURITY_MODES.includes(config.securityMode)) {
        throw new ConfigValidationError(`securityMode must be one of ${SECURITY_MODES.join(', ')}`);
    }

    if (config.defaultAction !== undefined && !DEFAULT_ACTIONS.includes(config.defaultAction)) {
        throw new ConfigValidationError(`defaultAction must be one of ${DEFAULT_ACTIONS.join(', ')}`);
    }

    assertPositiveNumber('timeoutMs', config.timeoutMs);
    assertPositiveNumber('cacheTtlMs', config.cacheTtlMs);
    assertPositiveNumber('quarantineTtlMs', config.quarantineTtlMs);
    assertPositiveNumber('maxBodyBytes', config.maxBodyBytes);

    assertHttpUrl('agentWebhookUrl', config.agentWebhookUrl);

    if (config.crowdsec) {
        const cs = config.crowdsec;
        assertPositiveNumber('crowdsec.timeoutMs', cs.timeoutMs);
        if (cs.lookup && typeof cs.lookup !== 'function') {
            throw new ConfigValidationError('crowdsec.lookup must be a function');
        }
        if (!cs.lookup) {
            if (!cs.url) {
                throw new ConfigValidationError('crowdsec.url is required unless you inject crowdsec.lookup');
            }
            assertHttpUrl('crowdsec.url', cs.url);
            if (!cs.apiKey) {
                throw new ConfigValidationError('crowdsec.apiKey is required for CrowdSec LAPI (or inject crowdsec.lookup)');
            }
        }
    }

    if (config.remoteAgent) {
        assertHttpUrl('remoteAgent.url', config.remoteAgent.url);
        assertPositiveNumber('remoteAgent.timeoutMs', config.remoteAgent.timeoutMs);
        assertScore('remoteAgent.minLocalScoreToInvoke', config.remoteAgent.minLocalScoreToInvoke);
        assertScore('remoteAgent.maxLocalScoreToInvoke', config.remoteAgent.maxLocalScoreToInvoke);
        const min = config.remoteAgent.minLocalScoreToInvoke;
        const max = config.remoteAgent.maxLocalScoreToInvoke;
        if (min !== undefined && max !== undefined && min > max) {
            throw new ConfigValidationError('remoteAgent.minLocalScoreToInvoke cannot exceed maxLocalScoreToInvoke');
        }
        const invokeWhen = config.remoteAgent.invokeWhen;
        if (invokeWhen !== undefined && invokeWhen !== 'local_clean' && invokeWhen !== 'local_suspicious' && invokeWhen !== 'always') {
            throw new ConfigValidationError("remoteAgent.invokeWhen must be 'local_clean', 'local_suspicious', or 'always'");
        }
        const knownPayload = new Set<string>(REMOTE_PAYLOAD_FIELDS);
        for (const field of config.remoteAgent.payload?.include || []) {
            if (!knownPayload.has(field)) {
                throw new ConfigValidationError(`remoteAgent.payload.include has unknown field '${field}'`);
            }
        }
        for (const field of config.remoteAgent.payload?.onRequest || []) {
            if (!knownPayload.has(field)) {
                throw new ConfigValidationError(`remoteAgent.payload.onRequest has unknown field '${field}'`);
            }
        }
        const knownDeclared = new Set<string>(REMOTE_DECLARED_RESPONSE_FIELDS);
        for (const field of config.remoteAgent.response?.include || []) {
            if (!knownDeclared.has(field)) {
                throw new ConfigValidationError(`remoteAgent.response.include has unknown field '${field}'`);
            }
        }
        const followUps = config.remoteAgent.payload?.maxFollowUps;
        if (followUps !== undefined && (!Number.isFinite(followUps) || followUps < 1 || followUps > 4)) {
            throw new ConfigValidationError('remoteAgent.payload.maxFollowUps must be between 1 and 4');
        }
        assertPositiveNumber('remoteAgent.memory.maxBytes', config.remoteAgent.memory?.maxBytes);
        assertPositiveNumber('remoteAgent.memory.ttlMs', config.remoteAgent.memory?.ttlMs);
        assertPositiveNumber('remoteAgent.investigateAsync.timeoutMs', config.remoteAgent.investigateAsync?.timeoutMs);
        const skills = config.remoteAgent.skills;
        if (skills) {
            if (!skills.catalog || typeof skills.catalog !== 'object' || Array.isArray(skills.catalog)) {
                throw new ConfigValidationError('remoteAgent.skills.catalog must be an object of named providers');
            }
            for (const [name, skill] of Object.entries(skills.catalog)) {
                if (!name) {
                    throw new ConfigValidationError('remoteAgent.skills.catalog keys must be non-empty');
                }
                if (!skill || typeof skill.provide !== 'function') {
                    throw new ConfigValidationError(`remoteAgent.skills.catalog['${name}'].provide must be a function`);
                }
            }
        }
    }

    if (config.inspectors) {
        validateInspectors(config.inspectors);
    }

    if (config.routePolicies) {
        if (!Array.isArray(config.routePolicies)) {
            throw new ConfigValidationError('routePolicies must be an array');
        }
        for (const [index, policy] of config.routePolicies.entries()) {
            if (!policy || typeof policy.path !== 'string' || !policy.path) {
                throw new ConfigValidationError(`routePolicies[${index}].path must be a non-empty string`);
            }
            if (policy.securityMode !== undefined && !SECURITY_MODES.includes(policy.securityMode)) {
                throw new ConfigValidationError(`routePolicies[${index}].securityMode is invalid`);
            }
            if (policy.inspectors) validateInspectors(policy.inspectors);
        }
    }

    if (config.circuitBreaker) {
        assertPositiveNumber('circuitBreaker.latencyThresholdMs', config.circuitBreaker.latencyThresholdMs);
        assertPositiveNumber('circuitBreaker.failureThreshold', config.circuitBreaker.failureThreshold);
        assertPositiveNumber('circuitBreaker.recoveryTimeMs', config.circuitBreaker.recoveryTimeMs);
        assertPositiveNumber('circuitBreaker.probeSuccessThreshold', config.circuitBreaker.probeSuccessThreshold);
    }

    if (config.replayGuard) {
        assertPositiveNumber('replayGuard.timestampWindowMs', config.replayGuard.timestampWindowMs);
    }

    if (config.semanticRateLimit) {
        assertPositiveNumber('semanticRateLimit.windowMs', config.semanticRateLimit.windowMs);
        assertPositiveNumber('semanticRateLimit.maxRequestsPerWindow', config.semanticRateLimit.maxRequestsPerWindow);
        assertPositiveNumber('semanticRateLimit.campaignIpThreshold', config.semanticRateLimit.campaignIpThreshold);
    }

    if (config.fingerprinting) {
        assertPositiveNumber('fingerprinting.suspiciousThreshold', config.fingerprinting.suspiciousThreshold);
    }

    if (config.honeypot) {
        assertNonNegativeNumber('honeypot.tarpitDelayMs', config.honeypot.tarpitDelayMs);
    }
}
