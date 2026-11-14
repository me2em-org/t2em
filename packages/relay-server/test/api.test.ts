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
import { WEB_UI_CSP } from '@t2em/web-ui';
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

  it('rejects envelopes over the field cap with 400 (§5.1, §9.2)', async () => {
    const app = createApp(deps(new InMemoryRelayStorage()));
    // Exactly 10 fields (4 valid + 6 unknown) still passes — the cap is
    // `>`, and validateEnvelope keeps only known fields.
    const bloated: Record<string, unknown> = { ...symEnvelope() };
    for (let i = 0; i < 6; i++) bloated[`aux${i}`] = 'x'.repeat(8);
    const ok = await post(app, { envelope: bloated, ttl: 300 });
    expect(ok.status).toBe(201);

    const over = await post(app, { envelope: { ...bloated, aux999: 'y' }, ttl: 300 });
    expect(over.status).toBe(400);
    expect(((await over.json()) as { error: { code: string } }).error.code).toBe('MALFORMED');
  });

  it('refuses POST with 503 once the global drop budget is spent (§5.1, §9.5)', async () => {
    const base = new InMemoryRelayStorage();
    // Scripted DBSIZE: the app logic under test is the threshold
    // semantics, not key accounting (the adapters' DBSIZE wire behaviour
    // is covered in upstash.test.ts / smoke.test.ts). 3 < 4 = under the
    // 2× ceiling; 4 = at the ceiling.
    let scriptedSize: number | null = 3;
    const scripted: RelayStorage = {
      putDrop: (...a) => base.putDrop(...(a as Parameters<typeof base.putDrop>)),
      getDrop: (...a) => base.getDrop(...(a as Parameters<typeof base.getDrop>)),
      consumeDrop: (...a) => base.consumeDrop(...(a as Parameters<typeof base.consumeDrop>)),
      putDeleteTokenHash: (...a) =>
        base.putDeleteTokenHash(...(a as Parameters<typeof base.putDeleteTokenHash>)),
      getDeleteTokenHash: (...a) =>
        base.getDeleteTokenHash(...(a as Parameters<typeof base.getDeleteTokenHash>)),
      putBurnMarker: (...a) => base.putBurnMarker(...(a as Parameters<typeof base.putBurnMarker>)),
      getBurnMarker: (...a) => base.getBurnMarker(...(a as Parameters<typeof base.getBurnMarker>)),
      destroyDrop: (...a) => base.destroyDrop(...(a as Parameters<typeof base.destroyDrop>)),
      hitRateLimit: (...a) => base.hitRateLimit(...(a as [string, number])),
      dbsize: async () => scriptedSize,
      ping: () => base.ping(),
    };
    const app = createApp(deps(scripted, { globalActiveDropsLimit: 2 }));

    const first = await post(app, { envelope: symEnvelope(), ttl: 300 }, '198.51.100.5');
    expect(first.status).toBe(201); // dbsize 3 < 2×2
    const { id, delete_token } = (await first.json()) as Created;

    scriptedSize = 4;
    const second = await post(app, { envelope: symEnvelope(), ttl: 300 }, '198.51.100.5');
    expect(second.status).toBe(503); // dbsize 4 ≥ 2×2
    expect(((await second.json()) as { error: { code: string } }).error.code).toBe(
      'GLOBAL_LIMIT_EXCEEDED',
    );

    // §9.5 chaos contract: reads and destroys stay 200 when POST is 503.
    const read = await app.request(`/s/${id}`);
    expect(read.status).toBe(200);
    const destroy = await app.request(`/api/v1/drop/${id}`, {
      method: 'DELETE',
      headers: { 'x-delete-token': delete_token },
    });
    expect(destroy.status).toBe(200);
  });

  it('fails open when the store cannot answer DBSIZE', async () => {
    const base = new InMemoryRelayStorage();
    const blind: RelayStorage = {
      putDrop: (...a) => base.putDrop(...(a as Parameters<typeof base.putDrop>)),
      getDrop: (...a) => base.getDrop(...(a as Parameters<typeof base.getDrop>)),
      consumeDrop: (...a) => base.consumeDrop(...(a as Parameters<typeof base.consumeDrop>)),
      putDeleteTokenHash: (...a) =>
        base.putDeleteTokenHash(...(a as Parameters<typeof base.putDeleteTokenHash>)),
      getDeleteTokenHash: (...a) =>
        base.getDeleteTokenHash(...(a as Parameters<typeof base.getDeleteTokenHash>)),
      putBurnMarker: (...a) => base.putBurnMarker(...(a as Parameters<typeof base.putBurnMarker>)),
      getBurnMarker: (...a) => base.getBurnMarker(...(a as Parameters<typeof base.getBurnMarker>)),
      destroyDrop: (...a) => base.destroyDrop(...(a as Parameters<typeof base.destroyDrop>)),
      hitRateLimit: (...a) => base.hitRateLimit(...(a as [string, number])),
      dbsize: async () => null,
      ping: () => base.ping(),
    };
    const app = createApp(deps(blind, { globalActiveDropsLimit: 1 }));
    const res = await post(app, { envelope: symEnvelope(), ttl: 300 }, '198.51.100.6');
    expect(res.status).toBe(201);
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
    const app = createApp(deps(new InMemoryRelayStorage(), { rateLimitDropPerMinute: 2 }));

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

  it('enforces the hourly POST bucket independently of the minute one', async () => {
    // Minute ceiling high enough to never trip; hour ceiling trips first.
    const app = createApp(
      deps(new InMemoryRelayStorage(), { rateLimitDropPerMinute: 1000, rateLimitDropPerHour: 3 }),
    );
    for (let i = 0; i < 3; i++) {
      const res = await post(app, { envelope: symEnvelope(), ttl: 300 }, '198.51.100.3');
      expect(res.status).toBe(201);
    }
    const fourth = await post(app, { envelope: symEnvelope(), ttl: 300 }, '198.51.100.3');
    expect(fourth.status).toBe(429);
    expect(fourth.headers.get('x-ratelimit-limit')).toBe('3');
    // Retry-After points to the end of the hour window, not the minute one.
    expect(Number(fourth.headers.get('retry-after'))).toBeGreaterThan(1);
    expect(((await fourth.json()) as { error: { code: string } }).error.code).toBe('RATE_LIMITED');
  });

  it('keeps POST, GET and DELETE budgets separate (§5.1 per-endpoint)', async () => {
    const app = createApp(
      deps(new InMemoryRelayStorage(), { rateLimitFetchPerMinute: 2, rateLimitDeletePerMinute: 1 }),
    );

    // GET budget exhausts on the 3rd read…
    const created = await createDrop(app, symEnvelope(), {}, '198.51.100.4');
    await app.request(`/s/${created.id}`, { headers: { 'x-forwarded-for': '198.51.100.4' } });
    await app.request(`/s/${created.id}`, { headers: { 'x-forwarded-for': '198.51.100.4' } });
    const thirdGet = await app.request(`/s/${created.id}`, {
      headers: { 'x-forwarded-for': '198.51.100.4' },
    });
    expect(thirdGet.status).toBe(429);
    expect(thirdGet.headers.get('x-ratelimit-limit')).toBe('2');

    // …while the same IP's POST budget is untouched.
    const postRes = await post(app, { envelope: symEnvelope(), ttl: 300 }, '198.51.100.4');
    expect(postRes.status).toBe(201);

    // DELETE has its own bucket: first call (401, missing token) consumes
    // it, the second is rate-limited.
    const noToken = await app.request(`/api/v1/drop/${created.id}`, {
      method: 'DELETE',
      headers: { 'x-forwarded-for': '198.51.100.4' },
    });
    expect(noToken.status).toBe(401);
    const delLimited = await app.request(`/api/v1/drop/${created.id}`, {
      method: 'DELETE',
      headers: { 'x-forwarded-for': '198.51.100.4' },
    });
    expect(delLimited.status).toBe(429);
    expect(delLimited.headers.get('x-ratelimit-limit')).toBe('1');
  });

  it('hashes the client IP into the rate-limit keys (§6.3)', async () => {
    const storage = new InMemoryRelayStorage();
    const app = createApp(deps(storage));
    await post(app, { envelope: symEnvelope(), ttl: 300 }, '198.51.100.7');
    // sha256('198.51.100.7') must be the only ratelimit key material.
    // One POST fills its minute bucket and its hour bucket (§5.1).
    const expectedHash = await sha256Hex(encodeUtf8('198.51.100.7'));
    const keys = [...storage['counters'].keys()];
    expect(keys).toHaveLength(2);
    for (const key of keys) {
      expect(key.startsWith(`ratelimit:${expectedHash}:post:`)).toBe(true);
      expect(key.includes('198.51.100.7')).toBe(false); // never plaintext
    }
    // Exactly one minute and one hour bucket for the same request.
    expect(keys.filter((k) => k.includes(':m')).length).toBe(1);
    expect(keys.filter((k) => k.includes(':h')).length).toBe(1);
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
      hitRateLimit: (...a) => base.hitRateLimit(...(a as [string, number])),
      dbsize: async () => null,
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

describe('embedded Web UI (Этап 1D, §3.2, §5.3, §7.1)', () => {
  it('serves the create page at / with the UI CSP', async () => {
    const app = createApp(deps(new InMemoryRelayStorage()));
    const res = await app.request('/');
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('text/html');
    expect(res.headers.get('content-security-policy')).toBe(WEB_UI_CSP);
    const html = await res.text();
    expect(html).toContain('<form id="create-form"');
    expect(html).toContain('<script src="/ui.js"></script>');
  });

  it('serves the static assets with exact content types and the CSP', async () => {
    const app = createApp(deps(new InMemoryRelayStorage()));
    for (const asset of [
      { path: '/ui.js', type: 'text/javascript; charset=utf-8' },
      { path: '/ui.css', type: 'text/css; charset=utf-8' },
    ]) {
      const res = await app.request(asset.path);
      expect(res.status).toBe(200);
      expect(res.headers.get('content-type')).toBe(asset.type);
      expect(res.headers.get('content-security-policy')).toBe(WEB_UI_CSP);
      expect((await res.text()).length).toBeGreaterThan(0);
    }
  });

  it('Accept: text/html gets the open page with the embedded envelope and burns the drop', async () => {
    const storage = new InMemoryRelayStorage();
    const app = createApp(deps(storage));
    const envelope = symEnvelope();
    const created = await createDrop(app, envelope);

    const res = await app.request(`/s/${created.id}`, {
      headers: { accept: 'text/html,application/xhtml+xml' },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('text/html');
    const html = await res.text();
    const m = /<script type="application\/json" id="t2em-envelope">(.*?)<\/script>/s.exec(html);
    expect(m).not.toBeNull();
    expect(JSON.parse((m as RegExpExecArray)[1])).toEqual(envelope);

    // consumed by the HTML request itself (§6.4) — also for JSON clients
    expect(await storage.getDrop(created.id)).toBeNull();
    const again = await app.request(`/s/${created.id}`);
    expect(again.status).toBe(404);
  });

  it('keeps the JSON contract for non-browser clients (§5.3)', async () => {
    const app = createApp(deps(new InMemoryRelayStorage()));
    const created = await createDrop(app);
    const res = await app.request(`/s/${created.id}`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('application/json');
  });

  it('renders one identical HTML 404 for missing, malformed and already-read ids', async () => {
    const app = createApp(deps(new InMemoryRelayStorage()));
    const created = await createDrop(app);
    await app.request(`/s/${created.id}`); // burn it

    const missing = await app.request(`/s/${crypto.randomUUID()}`, {
      headers: { accept: 'text/html' },
    });
    const read = await app.request(`/s/${created.id}`, {
      headers: { accept: 'text/html' },
    });
    const malformed = await app.request('/s/not-a-uuid', {
      headers: { accept: 'text/html' },
    });
    expect(missing.status).toBe(404);
    expect(read.status).toBe(404);
    expect(malformed.status).toBe(404);
    const missingBody = await missing.text();
    expect(await read.text()).toBe(missingBody);
    expect(await malformed.text()).toBe(missingBody);
    expect(missingBody).toContain('does not exist, has expired, or has already been read');
  });
});

describe('GET /for-agents (static agent guide)', () => {
  it('serves the CSP-guarded HTML guide without touching any storage', async () => {
    const app = createApp(deps(new InMemoryRelayStorage()));
    const res = await app.request('/for-agents');
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('text/html');
    expect(res.headers.get('content-security-policy')).toBe(WEB_UI_CSP);
    const body = await res.text();
    expect(body).toContain('api/v1/drop');
    expect(body).not.toContain('<script');
    // repeat-safe: static page, no drop consumption, identical on refetch
    const res2 = await app.request('/for-agents');
    expect(res2.status).toBe(200);
    expect(await res2.text()).toBe(body);
  });
});
