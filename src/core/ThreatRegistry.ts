export class ThreatRegistry {
    private blacklist = new Set<string>();
    private whitelist = new Set<string>();
    private timedBlocks = new Map<string, number>();

    constructor(initialBlocked: string[] = [], initialWhitelisted: string[] = []) {
        initialBlocked.forEach(id => this.blacklist.add(id.trim()));
        initialWhitelisted.forEach(id => this.whitelist.add(id.trim()));
    }

    isWhitelisted(identifier: string): boolean {
        return this.whitelist.has(identifier);
    }

    isBlacklisted(identifier: string): boolean {
        const expiresAt = this.timedBlocks.get(identifier);
        if (expiresAt && Date.now() > expiresAt) {
            this.timedBlocks.delete(identifier);
            this.blacklist.delete(identifier);
            return false;
        }
        return this.blacklist.has(identifier);
    }

    block(identifier: string, ttlMs?: number): void {
        const id = identifier.trim();
        this.whitelist.delete(id);
        this.blacklist.add(id);
        if (ttlMs && ttlMs > 0) {
            this.timedBlocks.set(id, Date.now() + ttlMs);
        } else {
            this.timedBlocks.delete(id);
        }
    }

    unblock(identifier: string): void {
        const id = identifier.trim();
        this.blacklist.delete(id);
        this.timedBlocks.delete(id);
    }

    allow(identifier: string): void {
        const id = identifier.trim();
        this.blacklist.delete(id);
        this.timedBlocks.delete(id);
        this.whitelist.add(id);
    }
}
