/**
 * Keyfile §8.2 format tests (`packages/cli/src/keys.ts`): the v2.1
 * fixed shape (version/type/createdAt/fingerprint) with fingerprint
 * self-verification, plus backward compatibility with the pre-v2.1
 * legacy (v/kind) format.
 */
import { chmodSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { b64uEncode } from '@me2em/protocol';
import { KEYFILE_KIND, KEYFILE_TYPE, KEYFILE_VERSION, keygenToFile, loadKeyFile } from '../src/keys.js';

function tmp(): string {
  return mkdtempSync(join(tmpdir(), 't2em-keys-'));
}

/** 32 zero bytes, base64url — valid key length for shape tests. */
const ZERO32 = 'A'.repeat(43);

describe('keyfile §8.2 format (v2.1)', () => {
  it('keygen writes the fixed §8.2 shape with a verified 16-char fingerprint', async () => {
    const dir = tmp();
    const path = join(dir, 'agent.key');
    const warnings: string[] = [];
    const publicKey = await keygenToFile(path, (l) => warnings.push(l));
    expect(warnings).toEqual([]);

    const payload = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
    expect(Object.keys(payload).sort()).toEqual(
      ['createdAt', 'fingerprint', 'privateKey', 'publicKey', 'type', 'version'],
    );
    expect(payload.version).toBe(KEYFILE_VERSION);
    expect(payload.type).toBe(KEYFILE_TYPE);
    expect(payload.publicKey).toBe(publicKey);
    expect(String(payload.createdAt)).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
    expect(payload.fingerprint).toHaveLength(16);
    expect(payload.fingerprint).toBe(await (await import('@me2em/protocol')).fingerprintPubKeyB64u(publicKey));

    const loaded = await loadKeyFile(path);
    expect(loaded.format).toBe('current');
    expect(b64uEncode(loaded.publicKey)).toBe(publicKey);
    // 0600 (§8.2)
    expect(statSync(path).mode & 0o077).toBe(0);
  });

  it('legacy (pre-v2.1) keyfiles still load and are marked legacy', async () => {
    const dir = tmp();
    const path = join(dir, 'legacy.key');
    writeFileSync(
      path,
      JSON.stringify({ v: 1, kind: KEYFILE_KIND, privateKey: ZERO32, publicKey: ZERO32 }),
    );
    const loaded = await loadKeyFile(path);
    expect(loaded.format).toBe('legacy');
    expect(loaded.privateKey.length).toBe(32);
    expect(loaded.publicKey.length).toBe(32);
  });

  it('fails closed on a spliced fingerprint (self-verification, §8.2)', async () => {
    const dir = tmp();
    const path = join(dir, 'spliced.key');
    const warnings: string[] = [];
    await keygenToFile(path, (l) => warnings.push(l));
    const payload = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
    payload.fingerprint = '0'.repeat(16);
    writeFileSync(path, JSON.stringify(payload));
    await expect(loadKeyFile(path)).rejects.toThrow(/fingerprint mismatch/);
  });

  it('rejects unknown kinds and wrong key lengths', async () => {
    const dir = tmp();
    const weird = join(dir, 'weird.key');
    writeFileSync(weird, JSON.stringify({ v: 1, kind: 'other-kind', privateKey: '', publicKey: '' }));
    await expect(loadKeyFile(weird)).rejects.toThrow(/unsupported keyfile kind/);

    const short = join(dir, 'short.key');
    writeFileSync(
      short,
      JSON.stringify({ version: 1, type: KEYFILE_TYPE, privateKey: 'AAAA', publicKey: 'AAAA' }),
    );
    await expect(loadKeyFile(short)).rejects.toThrow(/32 bytes/);
  });

  it('warns when permissions are wider than 0600 (§8.2)', async () => {
    const dir = tmp();
    const path = join(dir, 'wide.key');
    await keygenToFile(path);
    chmodSync(path, 0o644);
    const warnings: string[] = [];
    await loadKeyFile(path, (l) => warnings.push(l));
    expect(warnings.some((w) => w.includes('chmod 600'))).toBe(true);
  });
});
