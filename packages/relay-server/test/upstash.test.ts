/**
 * Unit tests for UpstashRelayStorage — REST wire format verified
 * against a mocked `fetch` that reproduces the real Upstash REST
 * behaviour (no network):
 *   request  — array of command arrays (auto-pipeline, lowercase verbs),
 *   response — bare array of `{ result, error }`, one per command.
 * Verified live against Upstash with a wire probe (@upstash/redis 1.41).
 * Live behaviour is covered by `upstash.live.test.ts` (env-gated).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { UpstashRelayStorage } from '../src/storage/upstash.js';

type FetchCall = { url: string; body: unknown };

const calls: FetchCall[] = [];
let cannedResults: unknown[] = [];

function installFetchMock() {
  const fake = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const body: unknown = JSON.parse(String(init?.body ?? 'null'));
    calls.push({ url: String(input), body });
    // Real Upstash REST: a nested body ([[cmd],[cmd]]) is a pipeline and
    // answers with a bare array of {result, error}; a flat body
    // (["dbsize"]) is a single command answered with ONE {result, error}
    // object. Verified live with a wire probe (@upstash/redis 1.41).
    const isPipeline =
      Array.isArray(body) && (body as unknown[]).every((c) => Array.isArray(c));
    const commands: unknown[] = isPipeline
      ? (body as unknown[])
      : [body];
    const results = commands.map(() => {
      const result = cannedResults.shift();
      return { result: result === undefined ? null : result, error: null };
    });
    const responseBody = isPipeline ? results : results[0];
    return new Response(JSON.stringify(responseBody), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  });
  vi.stubGlobal('fetch', fake);
  return fake;
}

function storage() {
  return new UpstashRelayStorage({ url: 'https://example.upstash.io', token: 'tok' });
}

beforeEach(() => {
  calls.length = 0;
  cannedResults = [null];
  installFetchMock();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('UpstashRelayStorage (REST wire format, ТЗ §6.1)', () => {
  it('putDrop sends SET … EX and does not interpret the envelope', async () => {
    await storage().putDrop('abc', '{"v":1,"mode":"sym"}', 300);
    expect(calls[0].body).toEqual([
      ['set', 'drop:abc', '{"v":1,"mode":"sym"}', 'ex', 300],
    ]);
  });

  it('getDrop returns the stored string verbatim, or null', async () => {
    cannedResults = ['{"v":1,"mode":"sym"}'];
    expect(await storage().getDrop('abc')).toBe('{"v":1,"mode":"sym"}');
    expect(calls[0].body).toEqual([['get', 'drop:abc']]);

    cannedResults = [null];
    expect(await storage().getDrop('missing')).toBeNull();
  });

  it('consumeDrop uses GETDEL (read exactly once, §6.4)', async () => {
    cannedResults = ['x'];
    expect(await storage().consumeDrop('abc')).toBe('x');
    expect(calls[0].body).toEqual([['getdel', 'drop:abc']]);
  });

  it('delete-token hash is stored under delete:{id} with the same TTL', async () => {
    await storage().putDeleteTokenHash('abc', 'a'.repeat(64), 300);
    expect(calls[0].body).toEqual([['set', 'delete:abc', 'a'.repeat(64), 'ex', 300]]);

    cannedResults = ['a'.repeat(64)];
    expect(await storage().getDeleteTokenHash('abc')).toBe('a'.repeat(64));
  });

  it('hitRateLimit pipelines INCR + EXPIRE per window and returns the counter', async () => {
    cannedResults = [3, 1];
    const counter = await storage().hitRateLimit('ip:deadbeef:post:m202611131012', 60);
    expect(counter).toBe(3);
    expect(calls[0].body).toEqual([
      ['incr', 'ratelimit:ip:deadbeef:post:m202611131012'],
      ['expire', 'ratelimit:ip:deadbeef:post:m202611131012', 60],
    ]);

    // Hourly POST bucket (§5.1): same pipeline, EX 3600.
    cannedResults = [1, 1];
    const hourly = await storage().hitRateLimit('ip:deadbeef:post:h1234', 3600);
    expect(hourly).toBe(1);
    expect(calls[1].body).toEqual([
      ['incr', 'ratelimit:ip:deadbeef:post:h1234'],
      ['expire', 'ratelimit:ip:deadbeef:post:h1234', 3600],
    ]);
  });

  it('dbsize returns the key count, or null on failure (§5.1 global guard)', async () => {
    cannedResults = [42];
    expect(await storage().dbsize()).toBe(42);
    // DBSizeCommand sends a flat single-command body (not a pipeline).
    expect(calls[0].body).toEqual(['dbsize']);

    // result:null (or any non-number) → null → the caller fails open.
    cannedResults = [null];
    expect(await storage().dbsize()).toBeNull();
  });

  it('burn marker: SET burn:{id} for non-burn drops, GET to detect (§5.2)', async () => {
    await storage().putBurnMarker('abc', 300);
    expect(calls[0].body).toEqual([['set', 'burn:abc', '0', 'ex', 300]]);

    cannedResults = ['0'];
    expect(await storage().getBurnMarker('abc')).toBe(true);
    expect(calls[1].body).toEqual([['get', 'burn:abc']]);

    cannedResults = [null];
    expect(await storage().getBurnMarker('missing')).toBe(false);
  });

  it('destroyDrop DELs all drop keys in one command (§5.4)', async () => {
    await storage().destroyDrop('abc');
    expect(calls[0].body).toEqual([['del', 'drop:abc', 'delete:abc', 'burn:abc']]);
  });

  it('ping maps PONG → true and any failure → false (§5.6)', async () => {
    cannedResults = ['PONG'];
    expect(await storage().ping()).toBe(true);
    expect(calls[0].body).toEqual([['ping']]);

    cannedResults = [null];
    expect(await storage().ping()).toBe(false);
  });

  it('rejects non-https endpoints and empty tokens (TLS 1.3, §8.6)', () => {
    expect(() => new UpstashRelayStorage({ url: 'http://x.upstash.io', token: 't' })).toThrow(/https/);
    expect(() => new UpstashRelayStorage({ url: 'https://x.upstash.io', token: '' })).toThrow(/token/);
  });
});
