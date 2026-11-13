/**
 * Live integration test against a real Upstash Redis (REST).
 *
 * Skipped unless credentials are provided via env:
 *   UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN
 * (see .env.example). Never runs in CI — secrets stay out of the repo.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import { UpstashRelayStorage } from '../src/storage/upstash.js';

const URL_ = process.env.UPSTASH_REDIS_REST_URL;
const TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

const d = URL_ && TOKEN ? describe : describe.skip;

d('UpstashRelayStorage (live Upstash REST)', () => {
  let storage: UpstashRelayStorage;

  beforeAll(() => {
    storage = new UpstashRelayStorage({ url: URL_ as string, token: TOKEN as string });
  });

  it('put/get/consume drop round-trip with GETDEL semantics', async () => {
    const id = `ci-${Date.now().toString(36)}`;
    const envelope = JSON.stringify({ v: 1, mode: 'sym', ciphertext: 'A'.repeat(43), iv: 'B'.repeat(16) });

    await storage.putDrop(id, envelope, 120);
    expect(await storage.getDrop(id)).toBe(envelope);   // чтение не уничтожает
    expect(await storage.consumeDrop(id)).toBe(envelope); // GETDEL
    expect(await storage.getDrop(id)).toBeNull();          // ключ исчез
    expect(await storage.getDeleteTokenHash(id)).toBeNull();
  });

  it('rate-limit counter increments within the bucket', async () => {
    const bucket = `ci:${Date.now().toString(36)}`;
    const first = await storage.hitRateLimit(bucket);
    const second = await storage.hitRateLimit(bucket);
    expect(second).toBe(first + 1);
  });
});
