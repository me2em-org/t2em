import { describe, expect, it } from 'vitest';
import { createApp } from '../src/app.js';
import { InMemoryRelayStorage } from '../src/storage/memory.js';
import { UpstashRelayStorage } from '../src/storage/upstash.js';
import { RATE_LIMIT_WINDOW_SECONDS } from '../src/storage/types.js';

function app() {
  return createApp({ storage: new InMemoryRelayStorage() });
}

describe('healthz', () => {
  it('reports ok with service metadata', async () => {
    const res = await app().request('/healthz');
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toContain('no-store');
    const body = (await res.json()) as { ok: boolean; service: string; protocol: number };
    expect(body.ok).toBe(true);
    expect(body.service).toBe('t2em-relay');
    expect(body.protocol).toBe(1);
  });
});

describe('security headers', () => {
  it('applies nosniff / DENY / no-referrer to every response', async () => {
    const res = await app().request('/healthz');
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    expect(res.headers.get('x-frame-options')).toBe('DENY');
    expect(res.headers.get('referrer-policy')).toBe('no-referrer');
  });
});

describe('unknown routes', () => {
  it('return a JSON 404 without leaking internals', async () => {
    const res = await app().request('/nope');
    expect(res.status).toBe(404);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe('NOT_FOUND');
  });
});

describe('InMemoryRelayStorage', () => {
  it('implements GETDEL semantics on consumeDrop', async () => {
    const storage = new InMemoryRelayStorage();
    await storage.putDrop('abc', '{"v":1,"mode":"sym"}', 900);
    expect(await storage.getDrop('abc')).not.toBeNull();
    expect(await storage.consumeDrop('abc')).toBe('{"v":1,"mode":"sym"}');
    expect(await storage.consumeDrop('abc')).toBeNull(); // read exactly once
  });

  it('counts rate-limit hits within the 60 s window', async () => {
    const storage = new InMemoryRelayStorage();
    expect(await storage.hitRateLimit('ip:1:0')).toBe(1);
    expect(await storage.hitRateLimit('ip:1:0')).toBe(2);
    expect(RATE_LIMIT_WINDOW_SECONDS).toBe(60);
  });
});

describe('UpstashRelayStorage', () => {
  it('rejects non-https endpoints and empty tokens', () => {
    expect(() => new UpstashRelayStorage({ url: 'http://x', token: 't' })).toThrow(/https/);
    expect(() => new UpstashRelayStorage({ url: 'https://x', token: '' })).toThrow(/token/);
  });

  it('deliberately reports NOT_IMPLEMENTED in Этап 0', async () => {
    const storage = new UpstashRelayStorage({ url: 'https://example.upstash.io', token: 't' });
    await expect(storage.getDrop('abc')).rejects.toThrow(/NOT_IMPLEMENTED/);
  });
});
