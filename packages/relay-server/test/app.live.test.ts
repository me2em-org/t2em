/**
 * Live end-to-end test: the full §5 drop API (shared Hono app) on top
 * of the REAL Upstash Redis adapter — the exact production combination
 * (ТЗ §3.4 deployment mode 1). Bridges the gap between api.test.ts
 * (app on InMemory) and upstash.live.test.ts (adapter only).
 *
 * Skipped unless credentials are provided via env:
 *   UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN
 * Never runs in CI — secrets stay out of the repo.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApp } from '../src/app.js';
import { UpstashRelayStorage } from '../src/storage/upstash.js';

const URL_ = process.env.UPSTASH_REDIS_REST_URL;
const TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

const d = URL_ && TOKEN ? describe : describe.skip;

d('drop API over live Upstash (ТЗ §5 E2E)', () => {
  let storage: UpstashRelayStorage;
  let app: ReturnType<typeof createApp>;
  const createdIds: string[] = [];

  beforeAll(() => {
    storage = new UpstashRelayStorage({ url: URL_ as string, token: TOKEN as string });
    app = createApp({ storage, publicOrigin: 'https://live-test.local' });
  });

  afterAll(async () => {
    // Best-effort cleanup — nothing the test created outlives the run.
    for (const id of createdIds) {
      await storage.destroyDrop(id).catch(() => undefined);
    }
  });

  function postDrop(body: Record<string, unknown>, ip: string) {
    return app.request('/api/v1/drop', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': ip },
      body: JSON.stringify(body),
    });
  }

  it('burn drop: create → read once → gone (§5.2, §5.3, §6.4)', async () => {
    const envelope = { v: 1, mode: 'sym', ciphertext: 'A'.repeat(64), iv: 'B'.repeat(16) };
    const res = await postDrop({ envelope, ttl: 120 }, '203.0.113.44');
    expect(res.status).toBe(201);
    const created = (await res.json()) as {
      id: string;
      url: string;
      expires_in: number;
      delete_token: string;
    };
    createdIds.push(created.id);
    expect(created.url).toBe(`https://live-test.local/s/${created.id}`);
    expect(created.expires_in).toBe(120);

    const first = await app.request(`/s/${created.id}`);
    expect(first.status).toBe(200);
    expect(((await first.json()) as { envelope: unknown }).envelope).toEqual(envelope);

    const second = await app.request(`/s/${created.id}`);
    expect(second.status).toBe(404); // burned by the first read
  });

  it('early destroy: 401 without token, 403 wrong, 200 right, then 404 (§5.4)', async () => {
    const envelope = {
      v: 1,
      mode: 'x25519',
      ephemeralPubKey: 'C'.repeat(43), // 32 bytes
      ciphertext: 'A'.repeat(64),
      iv: 'B'.repeat(16),
    };
    const res = await postDrop({ envelope, ttl: 120, burn_after_reading: false }, '203.0.113.45');
    expect(res.status).toBe(201);
    const created = (await res.json()) as { id: string; delete_token: string };
    createdIds.push(created.id);

    const noToken = await app.request(`/api/v1/drop/${created.id}`, { method: 'DELETE' });
    expect(noToken.status).toBe(401);

    const wrong = await app.request(`/api/v1/drop/${created.id}`, {
      method: 'DELETE',
      headers: { 'x-delete-token': 'd'.repeat(43) },
    });
    expect(wrong.status).toBe(403);

    const ok = await app.request(`/api/v1/drop/${created.id}`, {
      method: 'DELETE',
      headers: { 'x-delete-token': created.delete_token },
    });
    expect(ok.status).toBe(200);
    expect(((await ok.json()) as { deleted: boolean }).deleted).toBe(true);

    const gone = await app.request(`/s/${created.id}`);
    expect(gone.status).toBe(404);
  });

  it('health reports the live redis as ok (§5.6)', async () => {
    const res = await app.request('/health');
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ status: 'ok', redis: 'ok' });
  });
});
