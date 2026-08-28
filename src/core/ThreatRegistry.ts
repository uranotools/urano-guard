export class ThreatRegistry {
    private blacklist = new Set<string>();
    private whitelist = new Set<string>();

    constructor(initialBlocked: string[] = [], initialWhitelisted: string[] = []) {
        initialBlocked.forEach(id => this.blacklist.add(id.trim()));
        initialWhitelisted.forEach(id => this.whitelist.add(id.trim()));
    }

    isWhitelisted(identifier: string): boolean {
        return this.whitelist.has(identifier);
    }

    isBlacklisted(identifier: string): boolean {
        return this.blacklist.has(identifier);
    }

    block(identifier: string): void {
        this.whitelist.delete(identifier);
        this.blacklist.add(identifier.trim());
    }

    unblock(identifier: string): void {
        this.blacklist.delete(identifier.trim());
    }

    allow(identifier: string): void {
        this.blacklist.delete(identifier.trim());
        this.whitelist.add(identifier.trim());
    }
}