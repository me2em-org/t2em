/**
 * Этап 1B — drop API contract tests (ТЗ §5) against the shared Hono
 * app with InMemory storage. Covers §5.2 create, §5.3 read (GETDEL,
 * anti-enumeration), §5.4 destroy, §5.6 health, §5.1 rate limit and
 * payload cap, and the §4.5 error taxonomy mapping.
 */
import { describe, expect, it } from 'vitest';
import { createApp, type AppDeps } from '../src/app.js';
import { InMemoryRelayStorage } from '../src/storage/memory.js';
import type { RelayStorage } from '../src/storage/types.js';
import {
  b64uDecodeStrict,
  b64uEncode,
  encodeUtf8,
  sha256Hex,
  type Envelope,
} from '@t2em/protocol';

const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function bytes(n: number, fill = 7): Uint8Array {
  return new Uint8Array(n).fill(fill);
}

/** Valid Mode B envelope with deterministic fixture bytes. */
function symEnvelope(): Envelope {
  return {
    v: 1,
    mode: 'sym',
    ciphertext: b64uEncode(bytes(48)),
    iv: b64uEncode(bytes(12, 3)),
  };
}

function deps(storage: RelayStorage, extra: Partial<AppDeps> = {}): AppDeps {
  return { storage, ...extra };
}

function post(app: ReturnType<typeof createApp>, body: unknown, ip = '203.0.113.10') {
  return app.request('/api/v1/drop', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-forwarded-for': ip },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
}

interface Created {
  id: string;
  url: string;
  expires_in: number;
  delete_token: string;
}

async function createDrop(
  app: ReturnType<typeof createApp>,
  envelope: Envelope = symEnvelope(),
  extra: Record<string, unknown> = {},
  ip = '203.0.113.10',
): Promise<Created> {
  const res = await post(app, { envelope, ttl: 300, ...extra }, ip);
  expect(res.status).toBe(201);
  return (await res.json()) as Created;
}

describe('POST /api/v1/drop (ТЗ §5.2)', () => {
  it('creates a burn drop: 201 + contract body + §6.1 keys', async () => {
    const storage = new InMemoryRelayStorage();
    const app = createApp(deps(storage));
    const envelope = symEnvelope();
    const res = await post(app, { envelope, ttl: 300 });
    expect(res.status).toBe(201);

    const body = (await res.json()) as Created;
    expect(body.id).toMatch(UUID_V4_RE);
    expect(body.url).toBe(`https://t2em.com/s/${body.id}`);
    expect(body.expires_in).toBe(300);
    // delete_token: base64url of exactly 32 bytes (§5.2)
    expect(body.delete_token).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(b64uDecodeStrict(body.delete_token).length).toBe(32);

    // drop:{id} stores the Envelope JSON verbatim (§6.1)
    expect(await storage.getDrop(body.id)).toBe(JSON.stringify(envelope));
    // delete:{id} stores hex(sha256(delete_token)) (§6.1)
    expect(await storage.getDeleteTokenHash(body.id)).toBe(
      await sha256Hex(encodeUtf8(body.delete_token)),
    );
    // default burn_after_reading=true → no burn marker
    expect(await storage.getBurnMarker(body.id)).toBe(false);
  });

  it('honours burn_after_reading=false via the burn:{id} marker', async () => {
    const storage = new InMemoryRelayStorage();
    const app = createApp(deps(storage));
    const created = await createDrop(app, symEnvelope(), { burn_after_reading: false });
    expect(await storage.getBurnMarker(created.id)).toBe(true);
  });

  it('accepts Mode A envelopes and preserves optional sender fields', async () => {
    const app = createApp(deps(new InMemoryRelayStorage()));
    const envelope: Envelope = {
      v: 1,
      mode: 'x25519',
      ephemeralPubKey: b64uEncode(bytes(32, 1)),
      ciphertext: b64uEncode(bytes(48)),
      iv: b64uEncode(bytes(12, 3)),
      senderSignature: b64uEncode(bytes(64, 4)),
      senderPubKey: b64uEncode(bytes(32, 5)),
    };
    const created = await createDrop(app, envelope);
    const res = await app.request(`/s/${created.id}`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { envelope: Envelope };
    expect(body.envelope).toEqual(envelope);
  });

  it('rejects invalid JSON and prototype-pollution keys (§11.4)', async () => {
    const app = createApp(deps(new InMemoryRelayStorage()));
    const bad = await post(app, 'not-json');
    expect(bad.status).toBe(400);
    expect(((await bad.json()) as { error: { code: string } }).error.code).toBe('INVALID_JSON');

    const raw =
      '{"envelope":{"v":1,"mode":"sym","__proto__":{},"ciphertext":"' +
      symEnvelope().ciphertext +
      '","iv":"' +
      symEnvelope().iv +
      '"},"ttl":300}';
    const evil = await post(app, raw);
    expect(evil.status).toBe(400);
    expect(((await evil.json()) as { error: { code: string } }).error.code).toBe('MALFORMED');
  });

  it('maps envelope failures to the §4.5 taxonomy', async () => {
    const app = createApp(deps(new InMemoryRelayStorage()));

    const wrongVersion = await post(app, { envelope: { ...symEnvelope(), v: 2 }, ttl: 300 });
    expect(wrongVersion.status).toBe(400);
    expect(((await wrongVersion.json()) as { error: { code: string } }).error.code).toBe(
      'UNSUPPORTED_VERSION',
    );

    const missingEnvelope = await post(app, { ttl: 300 });
    expect(missingEnvelope.status).toBe(400);
    expect(((await missingEnvelope.json()) as { error: { code: string } }).error.code).toBe(
      'MALFORMED',
    );

    const badIv = await post(app, {
      envelope: { ...symEnvelope(), iv: b64uEncode(bytes(11)) },
      ttl: 300,
    });
    expect(badIv.status).toBe(400);
    expect(((await badIv.json()) as { error: { code: string } }).error.code).toBe('MALFORMED');
  });

  it('enforces ttl as integer 60..900', async () => {
    const app = createApp(deps(new InMemoryRelayStorage()));
    for (const ttl of [59, 901, 300.5, '300', null]) {
      const res = await post(app, { envelope: symEnvelope(), ttl });
      expect(res.status).toBe(400);
      expect(((await res.json()) as { error: { code: string } }).error.code).toBe('INVALID_TTL');
    }
    for (const ttl of [60, 900]) {
      const res = await post(app, { envelope: symEnvelope(), ttl });
      expect(res.status).toBe(201);
    }
  });

  it('rejects burn_after_reading that is not a boolean', async () => {
    const app = createApp(deps(new InMemoryRelayStorage()));
    const res = await post(app, { envelope: symEnvelope(), ttl: 300, burn_after_reading: 'yes' });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe('MALFORMED');
  });

  it('rejects payloads over 64 KB with 413 (§5.1)', async () => {
    const app = createApp(deps(new InMemoryRelayStorage()));
    const oversized = {
      envelope: { ...symEnvelope(), ciphertext: 'A'.repeat(66000) },
      ttl: 300,
    };
    const res = await post(app, oversized);
    expect(res.status).toBe(413);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe(
      'PAYLOAD_TOO_LARGE',
    );
  });
});

describe('GET /s/:id (ТЗ §5.3)', () => {
  it('burns by default: first read returns the envelope, second is 404', async () => {
    const app = createApp(deps(new InMemoryRelayStorage()));
    const created = await createDrop(app);

    const first = await app.request(`/s/${created.id}`);
    expect(first.status).toBe(200);
    const body = (await first.json()) as { envelope: Envelope };
    expect(body.envelope).toEqual(symEnvelope());

    const second = await app.request(`/s/${created.id}`);
    expect(second.status).toBe(404);
    expect(second.headers.get('cache-control')).toContain('no-store');
  });

  it('serves non-burn drops repeatedly while the TTL lives', async () => {
    const app = createApp(deps(new InMemoryRelayStorage()));
    const created = await createDrop(app, symEnvelope(), { burn_after_reading: false });
    for (let i = 0; i < 2; i++) {
      const res = await app.request(`/s/${created.id}`);
      expect(res.status).toBe(200);
      const body = (await res.json()) as { envelope: Envelope };
      expect(body.envelope).toEqual(symEnvelope());
    }
  });

  it('returns one identical 404 body for missing, already-read and malformed ids', async () => {
    const app = createApp(deps(new InMemoryRelayStorage()));
    const created = await createDrop(app);
    await app.request(`/s/${created.id}`); // burn it

    const read = await app.request(`/s/${created.id}`);
    const missing = await app.request(`/s/550e8400-e29b-41d4-a716-446655440000`);
    const malformed = await app.request(`/s/not-a-uuid`);
    const bodies: unknown[] = [];
    for (const res of [read, missing, malformed]) {
      expect(res.status).toBe(404);
      const body = (await res.json()) as { error: { code: string } };
      expect(body.error.code).toBe('NOT_FOUND');
      bodies.push(body);
    }
    // Anti-enumeration (§5.3): identical bodies.
    expect(bodies[0]).toEqual(bodies[1]);
  });
});

describe('DELETE /api/v1/drop/:id (ТЗ §5.4)', () => {
  it('requires the delete token: 401 without, 403 with a wrong one', async () => {
    const app = createApp(deps(new InMemoryRelayStorage()));
    const created = await createDrop(app);

    const noToken = await app.request(`/api/v1/drop/${created.id}`, { method: 'DELETE' });
    expect(noToken.status).toBe(401);
    expect(((await noToken.json()) as { error: { code: string } }).error.code).toBe('UNAUTHORIZED');

    const wrong = await app.request(`/api/v1/drop/${created.id}`, {
      method: 'DELETE',
      headers: { 'x-delete-token': b64uEncode(bytes(32, 9)) },
    });
    expect(wrong.status).toBe(403);
    expect(((await wrong.json()) as { error: { code: string } }).error.code).toBe('FORBIDDEN');
  });

  it('destroys every §6.1 key with the correct token and is idempotent', async () => {
    const storage = new InMemoryRelayStorage();
    const app = createApp(deps(storage));
    const created = await createDrop(app, symEnvelope(), { burn_after_reading: false });

    const ok = await app.request(`/api/v1/drop/${created.id}`, {
      method: 'DELETE',
      headers: { 'x-delete-token': created.delete_token },
    });
    expect(ok.status).toBe(200);
    expect(((await ok.json()) as { deleted: boolean }).deleted).toBe(true);
    expect(await storage.getDrop(created.id)).toBeNull();
    expect(await storage.getDeleteTokenHash(created.id)).toBeNull();
    expect(await storage.getBurnMarker(created.id)).toBe(false);

    const again = await app.request(`/api/v1/drop/${created.id}`, {
      method: 'DELETE',
      headers: { 'x-delete-token': created.delete_token },
    });
    expect(again.status).toBe(404);
  });

  it('still clears the delete key for an already-burned drop', async () => {
    const storage = new InMemoryRelayStorage();
    const app = createApp(deps(storage));
    const created = await createDrop(app);
    await app.request(`/s/${created.id}`); // read → GETDEL

    const ok = await app.request(`/api/v1/drop/${created.id}`, {
      method: 'DELETE',
      headers: { 'x-delete-token': created.delete_token },
    });
    expect(ok.status).toBe(200);
    expect(await storage.getDeleteTokenHash(created.id)).toBeNull();
  });

  it('returns 404 for malformed ids', async () => {
    const app = createApp(deps(new InMemoryRelayStorage()));
    const res = await app.request('/api/v1/drop/nope', {
      method: 'DELETE',
      headers: { 'x-delete-token': b64uEncode(bytes(32)) },
    });
    expect(res.status).toBe(404);
  });
});

describe('rate limiting (ТЗ §5.1, §6.1)', () => {
  it('returns 429 with X-RateLimit-* / Retry-After and per-IP isolation', async () => {
    const app = createApp(deps(new InMemoryRelayStorage(), { rateLimitPerMinute: 2 }));

    await post(app, { envelope: symEnvelope(), ttl: 300 }, '198.51.100.1');
    await post(app, { envelope: symEnvelope(), ttl: 300 }, '198.51.100.1');
    const third = await post(app, { envelope: symEnvelope(), ttl: 300 }, '198.51.100.1');
    expect(third.status).toBe(429);
    expect(third.headers.get('x-ratelimit-limit')).toBe('2');
    expect(third.headers.get('x-ratelimit-remaining')).toBe('0');
    expect(Number(third.headers.get('retry-after'))).toBeGreaterThan(0);
    expect(((await third.json()) as { error: { code: string } }).error.code).toBe('RATE_LIMITED');

    // another IP is unaffected
    const other = await post(app, { envelope: symEnvelope(), ttl: 300 }, '198.51.100.2');
    expect(other.status).toBe(201);
  });

  it('hashes the client IP into the rate-limit key (§6.3)', async () => {
    const storage = new InMemoryRelayStorage();
    const app = createApp(deps(storage));
    await post(app, { envelope: symEnvelope(), ttl: 300 }, '198.51.100.7');
    // sha256('198.51.100.7') must be the only ratelimit key material
    const expectedHash = await sha256Hex(encodeUtf8('198.51.100.7'));
    const keys = [...storage['counters'].keys()];
    expect(keys).toHaveLength(1);
    expect(keys[0].startsWith(`ratelimit:${expectedHash}:`)).toBe(true);
    expect(keys[0].includes('198.51.100.7')).toBe(false); // never plaintext
  });
});

describe('GET /health (ТЗ §5.6)', () => {
  it('reports ok with the relay version', async () => {
    const app = createApp(deps(new InMemoryRelayStorage()));
    const res = await app.request('/health');
    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string; redis: string; version: string };
    expect(body.status).toBe('ok');
    expect(body.redis).toBe('ok');
    expect(typeof body.version).toBe('string');
  });

  it('degrades to 503 when storage ping fails', async () => {
    const base = new InMemoryRelayStorage();
    const dead: RelayStorage = {
      putDrop: (...a) => base.putDrop(...a),
      getDrop: (...a) => base.getDrop(...a),
      consumeDrop: (...a) => base.consumeDrop(...a),
      putDeleteTokenHash: (...a) => base.putDeleteTokenHash(...a),
      getDeleteTokenHash: (...a) => base.getDeleteTokenHash(...a),
      putBurnMarker: (...a) => base.putBurnMarker(...a),
      getBurnMarker: (...a) => base.getBurnMarker(...a),
      destroyDrop: (...a) => base.destroyDrop(...a),
      hitRateLimit: (...a) => base.hitRateLimit(...a),
      ping: async () => false,
    };
    const app = createApp(deps(dead));
    const res = await app.request('/health');
    expect(res.status).toBe(503);
    const body = (await res.json()) as { status: string; redis: string };
    expect(body.status).toBe('degraded');
    expect(body.redis).toBe('unavailable');
  });
});

describe('security headers on the API (§5.1)', () => {
  it('apply no-store/nosniff/DENY/no-referrer to drop responses', async () => {
    const app = createApp(deps(new InMemoryRelayStorage()));
    const res = await post(app, { envelope: symEnvelope(), ttl: 300 });
    expect(res.headers.get('cache-control')).toContain('no-store');
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    expect(res.headers.get('x-frame-options')).toBe('DENY');
    expect(res.headers.get('referrer-policy')).toBe('no-referrer');
  });
});
