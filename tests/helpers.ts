import { GuardRequestContext } from '../src/types/context';

export function ctx(partial: Partial<GuardRequestContext> = {}): GuardRequestContext {
    return {
        ip: '1.2.3.4',
        method: 'POST',
        path: '/api/chat',
        headers: {},
        query: {},
        body: {},
        timestamp: Date.now(),
        ...partial
    };
}
