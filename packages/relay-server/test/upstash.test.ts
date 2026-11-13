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
    // Real Upstash REST: body is an array of command arrays; the response is
    // a bare array of {result, error} — exactly one entry per command.
    const commands = Array.isArray(body) ? (body as unknown[]) : [body];
    const payload = commands.map(() => {
      const result = cannedResults.shift();
      return { result: result === undefined ? null : result, error: null };
    });
    return new Response(JSON.stringify(payload), {
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

  it('hitRateLimit pipelines INCR + EXPIRE 60 and returns the counter', async () => {
    cannedResults = [3, 1];
    const counter = await storage().hitRateLimit('ip:deadbeef:202611131012');
    expect(counter).toBe(3);
    expect(calls[0].body).toEqual([
      ['incr', 'ratelimit:ip:deadbeef:202611131012'],
      ['expire', 'ratelimit:ip:deadbeef:202611131012', 60],
    ]);
  });

  it('rejects non-https endpoints and empty tokens (TLS 1.3, §8.6)', () => {
    expect(() => new UpstashRelayStorage({ url: 'http://x.upstash.io', token: 't' })).toThrow(/https/);
    expect(() => new UpstashRelayStorage({ url: 'https://x.upstash.io', token: '' })).toThrow(/token/);
  });
});
