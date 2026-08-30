import { GuardRequestContext } from '../types/context';
import { ThreatIncident } from '../types/threat';
import {
    CROWDSEC_SKILL_NAME,
    CrowdSecConfig,
    CrowdSecDecision,
    CrowdSecLookupResult
} from '../types/crowdsec';
import { RemoteAgentSkill } from '../types/remoteAgent';

const DEFAULT_BAN_TYPES = ['ban'];

export function createCrowdSecLookup(config: CrowdSecConfig): (ip: string) => Promise<CrowdSecLookupResult> {
    if (config.lookup) {
        return async (ip) => config.lookup!(ip);
    }

    const base = (config.url || '').replace(/\/$/, '');
    const apiKey = config.apiKey || '';
    const timeoutMs = config.timeoutMs ?? 800;
    const banTypes = new Set((config.banTypes || DEFAULT_BAN_TYPES).map(t => t.toLowerCase()));

    return async (ip: string): Promise<CrowdSecLookupResult> => {
        if (!ip) return { ip, banned: false, decisions: [] };
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        try {
            const res = await fetch(`${base}/v1/decisions?ip=${encodeURIComponent(ip)}`, {
                headers: { 'X-Api-Key': apiKey, Accept: 'application/json' },
                signal: controller.signal
            });
            if (!res.ok) {
                return { ip, banned: false, decisions: [], error: `http_${res.status}` };
            }
            const raw = await res.json();
            const decisions = normalizeDecisions(raw);
            const banned = decisions.some(d => banTypes.has(String(d.type || '').toLowerCase()));
            return { ip, banned, decisions };
        } catch (err) {
            const message = err instanceof Error ? err.message : 'network';
            return { ip, banned: false, decisions: [], error: message };
        } finally {
            clearTimeout(timer);
        }
    };
}

export function createCrowdSecSkill(config: CrowdSecConfig): RemoteAgentSkill {
    const lookup = createCrowdSecLookup(config);
    return {
        description: 'CrowdSec LAPI decisions for an IP (reputation, not content analysis)',
        provide: async (args, ctx: GuardRequestContext, _local: { threats: ThreatIncident[]; maxRiskScore: number }) => {
            const ip = typeof args?.ip === 'string' && args.ip ? args.ip : ctx.ip;
            return lookup(ip);
        }
    };
}

export function crowdsecSkillName(): string {
    return CROWDSEC_SKILL_NAME;
}

function normalizeDecisions(raw: unknown): CrowdSecDecision[] {
    if (raw == null) return [];
    if (!Array.isArray(raw)) return [];
    return raw.filter(item => item && typeof item === 'object') as CrowdSecDecision[];
}
