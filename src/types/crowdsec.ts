/**
 * Optional CrowdSec LAPI client. Not an AI agent — IP reputation / decisions.
 * Only configured when you set `crowdsec` on Guard. No API key is required
 * unless you enable this block (CrowdSec’s bouncer API uses `X-Api-Key`).
 *
 * Pass `lookup` to skip the key entirely (your own wrapper).
 */
export interface CrowdSecDecision {
    origin?: string;
    type?: string;
    scope?: string;
    value?: string;
    duration?: string;
    reason?: string;
}

export interface CrowdSecLookupResult {
    ip: string;
    banned: boolean;
    decisions: CrowdSecDecision[];
    error?: string;
}

export interface CrowdSecConfig {
    /** LAPI base, e.g. http://127.0.0.1:8080 — required unless `lookup` is set. */
    url?: string;
    /** Bouncer key. Required with `url`. Not used if you inject `lookup`. */
    apiKey?: string;
    timeoutMs?: number;
    /** Check the client IP on every inspect (default false). Fail-open on LAPI errors. */
    inspect?: boolean;
    /** Decision types that count as a ban (default `['ban']`). */
    banTypes?: string[];
    /** Auto-add `crowdsec.lookup` to the agent skill catalog (default true). */
    registerSkill?: boolean;
    /** Injected lookup — no CrowdSec key in this process. */
    lookup?: (ip: string) => Promise<CrowdSecLookupResult> | CrowdSecLookupResult;
}

export const CROWDSEC_SKILL_NAME = 'crowdsec.lookup';
