export function pickClientIp(opts: {
    trustProxy: boolean;
    socketIp?: string;
    forwardedFor?: string | string[];
    realIp?: string;
    fallback?: string;
}): string {
    if (opts.trustProxy) {
        const raw = Array.isArray(opts.forwardedFor) ? opts.forwardedFor[0] : opts.forwardedFor;
        if (raw) return String(raw).split(',')[0].trim();
        if (opts.realIp) return opts.realIp;
    }
    return opts.socketIp || opts.fallback || '127.0.0.1';
}

export function pickSenderId(opts: {
    trustProxy: boolean;
    ip: string;
    headerUserId?: string;
    headerSenderId?: string;
}): string {
    if (opts.trustProxy) {
        return opts.headerUserId || opts.headerSenderId || opts.ip;
    }
    return opts.ip;
}

export function firstHeader(
    headers: Record<string, string | string[] | undefined> | undefined,
    name: string
): string | undefined {
    if (!headers) return undefined;
    const value = headers[name] ?? headers[name.toLowerCase()];
    if (value == null) return undefined;
    return String(Array.isArray(value) ? value[0] : value);
}
