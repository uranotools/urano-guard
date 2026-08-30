import { SharedStore } from '../types/store';

const BLOCK_PREFIX = 'ug:block:';
const ALLOW_PREFIX = 'ug:allow:';

export class ThreatRegistry {
    private blacklist = new Set<string>();
    private whitelist = new Set<string>();
    private timedBlocks = new Map<string, number>();
    private store?: SharedStore;
    private seedPromise: Promise<void>;

    constructor(
        initialBlocked: string[] = [],
        initialWhitelisted: string[] = [],
        store?: SharedStore
    ) {
        this.store = store;
        const blocked = initialBlocked.map(id => id.trim()).filter(Boolean);
        const allowed = initialWhitelisted.map(id => id.trim()).filter(Boolean);
        blocked.forEach(id => this.blacklist.add(id));
        allowed.forEach(id => this.whitelist.add(id));
        this.seedPromise = this.seedStore(blocked, allowed);
    }

    /**
     * Resolves when constructor seeds have been written to the store.
     * `isBlacklisted` / `isWhitelisted` already await this. Call it after
     * `createUranoGuard` if another process may read the store before the
     * first request:
     *
     * ```ts
     * const guard = createUranoGuard({ store, blockedIdentifiers: ['1.2.3.4'] });
     * await guard.ready();
     * ```
     */
    ready(): Promise<void> {
        return this.seedPromise;
    }

    async isWhitelisted(identifier: string): Promise<boolean> {
        if (this.store) {
            await this.seedPromise;
            return (await this.store.get(ALLOW_PREFIX + identifier)) !== undefined;
        }
        return this.whitelist.has(identifier);
    }

    async isBlacklisted(identifier: string): Promise<boolean> {
        if (this.store) {
            await this.seedPromise;
            return (await this.store.get(BLOCK_PREFIX + identifier)) !== undefined;
        }
        const expiresAt = this.timedBlocks.get(identifier);
        if (expiresAt && Date.now() > expiresAt) {
            this.timedBlocks.delete(identifier);
            this.blacklist.delete(identifier);
            return false;
        }
        return this.blacklist.has(identifier);
    }

    async block(identifier: string, ttlMs?: number): Promise<void> {
        const id = identifier.trim();
        this.whitelist.delete(id);
        this.blacklist.add(id);
        if (ttlMs && ttlMs > 0) {
            this.timedBlocks.set(id, Date.now() + ttlMs);
        } else {
            this.timedBlocks.delete(id);
        }
        if (this.store) {
            await this.seedPromise;
            await this.store.delete(ALLOW_PREFIX + id);
            await this.store.set(BLOCK_PREFIX + id, true, ttlMs && ttlMs > 0 ? ttlMs : 0);
        }
    }

    async unblock(identifier: string): Promise<void> {
        const id = identifier.trim();
        this.blacklist.delete(id);
        this.timedBlocks.delete(id);
        if (this.store) {
            await this.seedPromise;
            await this.store.delete(BLOCK_PREFIX + id);
        }
    }

    async allow(identifier: string): Promise<void> {
        const id = identifier.trim();
        this.blacklist.delete(id);
        this.timedBlocks.delete(id);
        this.whitelist.add(id);
        if (this.store) {
            await this.seedPromise;
            await this.store.delete(BLOCK_PREFIX + id);
            await this.store.set(ALLOW_PREFIX + id, true, 0);
        }
    }

    private async seedStore(blocked: string[], allowed: string[]): Promise<void> {
        if (!this.store) return;
        await Promise.all([
            ...blocked.map(id => this.store!.set(BLOCK_PREFIX + id, true, 0)),
            ...allowed.map(id => this.store!.set(ALLOW_PREFIX + id, true, 0))
        ]);
    }
}
