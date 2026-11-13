/**
 * Shared test vectors (ТЗ §4.5): `vectors/t2em-drop.v1.json` is the
 * bit-compatibility contract between the TypeScript implementation
 * and the future Python SDK (Этап 4). Every implementation must open
 * the fixed envelopes to the exact plaintext, and must re-produce the
 * fixed ciphertexts from the fixed key material (key-schedule proof).
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { hkdfWithInfo, importAeadKey, x25519SharedSecret } from '@me2em/crypto';
import {
  HKDF_INFO_DROP_V1,
  b64uDecodeStrict,
  b64uEncode,
  decodeUtf8,
  fingerprintPubKey,
  packDropAsym,
  packDropSym,
  unpackDropAsym,
  unpackDropSym,
} from '../src/index.js';

interface VectorFile {
  protocol: number;
  hkdf_info: string;
  vectors: Array<{
    name: string;
    envelope: Record<string, string | number>;
    sym_key?: string;
    recipient_privkey?: string;
    recipient_pubkey?: string;
    ephemeral_privkey?: string;
    plaintext_utf8: string;
  }>;
}

const VECTORS_PATH = fileURLToPath(new URL('../../../vectors/t2em-drop.v1.json', import.meta.url));
const file = JSON.parse(readFileSync(VECTORS_PATH, 'utf8')) as VectorFile;

const symVectors = file.vectors.filter((v) => v.envelope.mode === 'sym');
const asymVectors = file.vectors.filter((v) => v.envelope.mode === 'x25519');

describe('shared test vectors (ТЗ §4.5 bit-compatibility)', () => {
  it('file declares protocol v1 and the frozen HKDF info string', () => {
    expect(file.protocol).toBe(1);
    expect(file.hkdf_info).toBe(HKDF_INFO_DROP_V1);
    expect(symVectors.length).toBeGreaterThan(0);
    expect(asymVectors.length).toBeGreaterThan(0);
  });

  for (const v of symVectors) {
    it(`opens Mode B vector '${v.name}' to the exact plaintext`, async () => {
      const pt = await unpackDropSym(v.envelope as never, v.sym_key as string);
      expect(decodeUtf8(pt)).toBe(v.plaintext_utf8);
    });
  }

  for (const v of asymVectors) {
    it(`opens Mode A vector '${v.name}' to the exact plaintext`, async () => {
      const pt = await unpackDropAsym(v.envelope as never, b64uDecodeStrict(v.recipient_privkey as string));
      expect(decodeUtf8(pt)).toBe(v.plaintext_utf8);
    });
  }

  it('re-derives the Mode A key schedule bit-exactly from fixed key material', async () => {
    const v = asymVectors[0];
    const ephPriv = b64uDecodeStrict(v.ephemeral_privkey as string);
    const recipPub = b64uDecodeStrict(v.recipient_pubkey as string);
    const ephPub = (v.envelope as { ephemeralPubKey: string }).ephemeralPubKey;

    const shared = x25519SharedSecret(ephPriv, recipPub);
    const salt = new Uint8Array([...b64uDecodeStrict(ephPub), ...recipPub]);
    const aesKey = await hkdfWithInfo(shared, salt, HKDF_INFO_DROP_V1, 32);
    const key = await importAeadKey(aesKey);
    const pt = new TextEncoder().encode(v.plaintext_utf8);
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: b64uDecodeStrict((v.envelope as { iv: string }).iv) },
      key,
      pt,
    );
    expect(b64uEncode(new Uint8Array(ct))).toBe((v.envelope as { ciphertext: string }).ciphertext);
  });

  it('roundtrips fresh Mode A drops through the vector key format', async () => {
    for (const v of asymVectors) {
      const recipient = b64uDecodeStrict(v.recipient_privkey as string);
      const pub = b64uDecodeStrict(v.recipient_pubkey as string);
      const { envelope } = await packDropAsym(new TextEncoder().encode(v.plaintext_utf8), pub);
      const pt = await unpackDropAsym(envelope, recipient);
      expect(decodeUtf8(pt)).toBe(v.plaintext_utf8);
      expect(envelope.ephemeralPubKey).not.toBe(v.recipient_pubkey);
    }
  });

  it('roundtrips fresh Mode B drops', async () => {
    for (const v of symVectors) {
      const { envelope, symKey } = await packDropSym(new TextEncoder().encode(v.plaintext_utf8));
      const pt = await unpackDropSym(envelope, symKey);
      expect(decodeUtf8(pt)).toBe(v.plaintext_utf8);
    }
  });

  it('recipient fingerprint is 8 chars and stable (§4.2.1)', async () => {
    const v = asymVectors[0];
    const pub = b64uDecodeStrict(v.recipient_pubkey as string);
    const fp = await fingerprintPubKey(pub);
    expect(fp).toHaveLength(8);
    expect(fp).toBe(await fingerprintPubKey(pub));
  });
});
