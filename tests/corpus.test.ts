import { readFileSync } from 'fs';
import { join } from 'path';
import { describe, expect, it } from 'vitest';
import { createUranoGuard } from '../src/core/UranoGuard';
import { ctx } from './helpers';

interface CorpusCase {
    id: string;
    body?: unknown;
    path?: string;
    query?: Record<string, unknown>;
    headers?: Record<string, string>;
}

function loadCases(rel: string): CorpusCase[] {
    return JSON.parse(readFileSync(join(__dirname, rel), 'utf8')) as CorpusCase[];
}

function guard() {
    return createUranoGuard({
        securityMode: 'block_threats',
        enableCache: false,
        inspectors: {
            jwtTampering: false,
            graphqlAbuse: false,
            botFuzzing: true
        }
    });
}

describe('attack corpus should block', () => {
    const attacks = [
        ...loadCases('fixtures/attacks/prompt.json'),
        ...loadCases('fixtures/attacks/sql.json'),
        ...loadCases('fixtures/attacks/xss.json'),
        ...loadCases('fixtures/attacks/cmd.json'),
        ...loadCases('fixtures/attacks/extra.json')
    ];

    it.each(attacks)('$id', async (sample) => {
        const decision = await guard().inspect(ctx({
            path: sample.path || '/api/chat',
            query: sample.query || {},
            headers: sample.headers || {},
            body: sample.body ?? {}
        }));
        expect(decision.allowed, `${sample.id} risk=${decision.riskScore} ${decision.reason}`).toBe(false);
        expect(decision.riskScore).toBeGreaterThanOrEqual(60);
    });
});

describe('benign corpus should not block', () => {
    const benign = loadCases('fixtures/benign/chat.json');

    it.each(benign)('$id', async (sample) => {
        const decision = await guard().inspect(ctx({
            path: sample.path || '/api/chat',
            query: sample.query || {},
            body: sample.body ?? {}
        }));
        expect(decision.allowed, `${sample.id} risk=${decision.riskScore} ${decision.reason}`).toBe(true);
    });
});

describe('jwt / graphql attack corpus should block', () => {
    const attacks = loadCases('fixtures/attacks/jwt-graphql.json');
    const jwtGraphqlGuard = () => createUranoGuard({
        securityMode: 'block_threats',
        enableCache: false,
        inspectors: {
            jwtTampering: true,
            graphqlAbuse: true,
            botFuzzing: false
        }
    });

    it.each(attacks)('$id', async (sample) => {
        const decision = await jwtGraphqlGuard().inspect(ctx({
            path: sample.path || '/api/chat',
            query: sample.query || {},
            headers: sample.headers || {},
            body: sample.body ?? {}
        }));
        expect(decision.allowed, `${sample.id} risk=${decision.riskScore} ${decision.reason}`).toBe(false);
        expect(decision.riskScore).toBeGreaterThanOrEqual(60);
    });
});
