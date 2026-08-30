import { InspectorFlags, RoutePolicy, SecurityMode } from '../types/config';

export interface ResolvedRoutePolicy {
    skip: boolean;
    securityMode?: SecurityMode;
    inspectors?: InspectorFlags;
}

export function matchRoutePath(pattern: string, path: string): boolean {
    if (pattern === path) return true;
    if (pattern.endsWith('/*')) {
        const prefix = pattern.slice(0, -2);
        return path === prefix || path.startsWith(`${prefix}/`);
    }
    const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
    return new RegExp(`^${escaped}$`).test(path);
}

export function resolveRoutePolicy(
    policies: RoutePolicy[] | undefined,
    method: string,
    path: string
): ResolvedRoutePolicy | null {
    if (!policies?.length) return null;
    const upper = method.toUpperCase();
    for (const policy of policies) {
        if (policy.method && policy.method.toUpperCase() !== upper) continue;
        if (!matchRoutePath(policy.path, path)) continue;
        return {
            skip: policy.skip === true,
            securityMode: policy.securityMode,
            inspectors: policy.inspectors
        };
    }
    return null;
}
