import { SecurityDecision } from '../types/context';
import { MemoryStore, SharedStore } from './SharedStore';

const KEY_PREFIX = 'ug:cache:';

export class CacheManager {
    private store: SharedStore;
    private owned: MemoryStore | null;
    private defaultTtl: number;

    constructor(defaultTtlMs = 60000, maxEntries = 5000, store?: SharedStore) {
        this.defaultTtl = defaultTtlMs;
        this.owned = store ? null : new MemoryStore({ maxEntries, defaultTtlMs });
        this.store = store ?? this.owned!;
    }

    get(key: string): SecurityDecision | null | Promise<SecurityDecision | null> {
        if (this.owned) {
            const decision = this.owned.getImmediate<SecurityDecision>(KEY_PREFIX + key);
            return decision ? { ...decision, source: 'CACHE' } : null;
        }
        return this.store.get<SecurityDecision>(KEY_PREFIX + key).then((decision) =>
            decision ? { ...decision, source: 'CACHE' } : null
        );
    }

    set(key: string, decision: SecurityDecision, ttlMs?: number): void | Promise<void> {
        const ttl = ttlMs || this.defaultTtl;
        if (this.owned) {
            this.owned.setImmediate(KEY_PREFIX + key, decision, ttl);
            return;
        }
        return this.store.set(KEY_PREFIX + key, decision, ttl);
    }

    clear(): void {
        if (this.owned) {
            this.owned.clear();
            return;
        }
        // External stores are not wiped — caller owns lifecycle.
    }

    get size(): number {
        return this.owned ? this.owned.size : 0;
    }
}
