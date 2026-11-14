/**
 * Shared test vectors (ТЗ §4.5, extended set per ТЗ v2.1 fix #23):
 * `vectors/t2em-drop.v1.json` is the bit-compatibility contract between
 * the TypeScript implementation and the Python SDK. Every positive
 * vector must open (through the §3.6 `unpackDrop` facade) to the exact
 * plaintext; every negative/cross-mode vector must fail with the
 * pinned taxonomy code; fingerprint pins must reproduce bit-exactly.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { ed25519PrivToX25519, hkdfWithInfo, importAeadKey, verifyRaw, x25519SharedSecret } from '@me2em/crypto';
import {
  FINGERPRINT_LENGTH,
  HKDF_INFO_DROP_V1,
  b64uDecodeStrict,
  b64uEncode,
  decodeUtf8,
  encodeUtf8,
  fingerprintPubKey,
  packDrop,
  packDropAsym,
  packDropSym,
  unpackDrop,
  unpackDropAsym,
  unpackDropSym,
  validateEnvelope,
} from '../src/index.js';

interface VectorFile {
  protocol: number;
  hkdf_info: string;
  fingerprint_length: number;
  signature_convention: string;
  vectors: Array<{
    name: string;
    expected: 'ok' | 'error';
    error_code?: string;
    envelope: Record<string, unknown>;
    sym_key?: string;
    recipient_privkey?: string;
    recipient_pubkey?: string;
    recipient_ed25519_privkey?: string;
    sender_ed25519_privkey?: string;
    sender_ed25519_pubkey?: string;
    ephemeral_privkey?: string;
    plaintext_utf8?: string;
    plaintext_b64u?: string;
  }>;
  fingerprint_vectors: Array<{ pubkey_b64u: string; fingerprint: string }>;
}

const VECTORS_PATH = fileURLToPath(new URL('../../../vectors/t2em-drop.v1.json', import.meta.url));
const file = JSON.parse(readFileSync(VECTORS_PATH, 'utf8')) as VectorFile;

const okVectors = file.vectors.filter((v) => v.expected === 'ok');
const errorVectors = file.vectors.filter((v) => v.expected === 'error');
const asymVectors = okVectors.filter((v) => v.envelope.mode === 'x25519');
const symVectors = okVectors.filter((v) => v.envelope.mode === 'sym');

function expectedPlaintext(v: (typeof okVectors)[number]): Uint8Array {
  if (v.plaintext_b64u !== undefined) return b64uDecodeStrict(v.plaintext_b64u);
  return encodeUtf8(v.plaintext_utf8 as string);
}

describe('shared test vectors (ТЗ §4.5 bit-compatibility)', () => {
  it('file declares protocol v1, the frozen HKDF info string and fingerprint length', () => {
    expect(file.protocol).toBe(1);
    expect(file.hkdf_info).toBe(HKDF_INFO_DROP_V1);
    expect(file.fingerprint_length).toBe(16);
    expect(file.fingerprint_length).toBe(FINGERPRINT_LENGTH);
    expect(okVectors.length).toBeGreaterThan(0);
    expect(errorVectors.length).toBeGreaterThan(0);
  });

  for (const v of okVectors) {
    it(`opens vector '${v.name}' through the §3.6 facade to the exact plaintext`, async () => {
      const envelope = validateEnvelope(v.envelope);
      if (envelope.mode === 'sym') {
        const pt = await unpackDrop(envelope, { mode: 'sym', symKey: b64uDecodeStrict(v.sym_key as string) });
        expect(new Uint8Array(pt)).toEqual(expectedPlaintext(v));
      } else {
        const pt = await unpackDrop(envelope, {
          mode: 'x25519',
          recipientPrivkey: b64uDecodeStrict(v.recipient_privkey as string),
        });
        expect(new Uint8Array(pt)).toEqual(expectedPlaintext(v));
      }
    });
  }

  it('Ed25519-converted recipient vector pins the conversion bit-exactly', async () => {
    const v = okVectors.find((x) => x.name === 'mode-a-ed25519-recv') as (typeof okVectors)[number];
    const converted = ed25519PrivToX25519(b64uDecodeStrict(v.recipient_ed25519_privkey as string));
    expect(b64uEncode(converted)).toBe(v.recipient_privkey);
  });

  it('sender-signed vector verifies against the pinned signature convention', async () => {
    const v = okVectors.find((x) => x.name === 'mode-a-sender-signed') as (typeof okVectors)[number];
    const env = validateEnvelope(v.envelope);
    if (env.mode !== 'x25519' || env.senderSignature === undefined || env.senderPubKey === undefined) {
      throw new Error('sender-signed vector lost its sender fields');
    }
    const message = encodeUtf8(`${env.ephemeralPubKey}.${env.ciphertext}.${env.iv}`);
    expect(
      verifyRaw(b64uDecodeStrict(env.senderPubKey), message, b64uDecodeStrict(env.senderSignature)),
    ).toBe(true);
    // Tampered message must fail closed.
    expect(
      verifyRaw(b64uDecodeStrict(env.senderPubKey), encodeUtf8('tampered'), b64uDecodeStrict(env.senderSignature)),
    ).toBe(false);
  });

  it('re-derives the Mode A key schedule bit-exactly from fixed key material', async () => {
    const v = asymVectors[0];
    const ephPriv = b64uDecodeStrict(v.ephemeral_privkey as string);
    const recipPub = b64uDecodeStrict(v.recipient_pubkey as string);
    const ephPub = (v.envelope as { ephemeralPubKey: string }).ephemeralPubKey;

    const shared = x25519SharedSecret(ephPriv, recipPub);
    const salt = new Uint8Array([...b64uDecodeStrict(ephPub), ...recipPub]);
    const aesKey = await hkdfWithInfo(shared, salt, HKDF_INFO_DROP_V1, 32);
    const key = await importAeadKey(aesKey);
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: b64uDecodeStrict((v.envelope as { iv: string }).iv) },
      key,
      expectedPlaintext(v),
    );
    expect(b64uEncode(new Uint8Array(ct))).toBe((v.envelope as { ciphertext: string }).ciphertext);
  });

  it('roundtrips fresh Mode A drops through the vector key format', async () => {
    for (const v of asymVectors) {
      if (v.recipient_pubkey === undefined) continue;
      const recipient = b64uDecodeStrict(v.recipient_privkey as string);
      const pub = b64uDecodeStrict(v.recipient_pubkey as string);
      const { envelope } = await packDropAsym(expectedPlaintext(v), pub);
      const pt = await unpackDropAsym(envelope, recipient);
      expect(pt).toEqual(expectedPlaintext(v));
      expect(envelope.ephemeralPubKey).not.toBe(v.recipient_pubkey);
    }
  });

  it('roundtrips fresh Mode B drops', async () => {
    for (const v of symVectors) {
      const { envelope, symKey } = await packDropSym(expectedPlaintext(v));
      const pt = await unpackDropSym(envelope, symKey);
      expect(pt).toEqual(expectedPlaintext(v));
    }
  });

  it('packDrop facade roundtrips both modes (§3.6)', async () => {
    const pt = encodeUtf8('facade roundtrip §3.6');
    const packedSym = await packDrop(pt, { mode: 'sym' });
    expect(packedSym.symKey).toHaveLength(32);
    expect(await unpackDrop(packedSym.envelope, { mode: 'sym', symKey: packedSym.symKey as Uint8Array })).toEqual(pt);

    const { publicKey, privateKey } = (await import('@me2em/crypto')).generateX25519KeyPair();
    const packedAsym = await packDrop(pt, { mode: 'x25519', recipientPubkey: publicKey });
    expect(packedAsym.symKey).toBeUndefined();
    expect(await unpackDrop(packedAsym.envelope, { mode: 'x25519', recipientPrivkey: privateKey })).toEqual(pt);
  });

  for (const v of errorVectors) {
    it(`rejects vector '${v.name}' with code ${v.error_code} (§4.5)`, async () => {
      let validated: unknown;
      let validationThrew = false;
      try {
        validated = validateEnvelope(v.envelope);
      } catch (err) {
        validationThrew = true;
        expect((err as { code?: string }).code).toBe(v.error_code);
      }
      if (!validationThrew) {
        // Envelope shape is valid — the error must come from the
        // unpackDrop facade (§4.5 cross-mode).
        const envelope = validated as Parameters<typeof unpackDrop>[0];
        const options =
          v.sym_key !== undefined
            ? ({ mode: 'sym', symKey: b64uDecodeStrict(v.sym_key) } as const)
            : ({ mode: 'x25519', recipientPrivkey: b64uDecodeStrict(v.recipient_privkey as string) } as const);
        await expect(unpackDrop(envelope, options)).rejects.toMatchObject({ code: v.error_code });
      }
    });
  }

  it('fingerprint pins reproduce bit-exactly and are 16 chars (§4.2.1)', async () => {
    for (const pin of file.fingerprint_vectors) {
      const fp = await fingerprintPubKey(b64uDecodeStrict(pin.pubkey_b64u));
      expect(fp).toBe(pin.fingerprint);
      expect(fp).toHaveLength(16);
      expect(fp).toBe(await fingerprintPubKey(b64uDecodeStrict(pin.pubkey_b64u)));
    }
  });
});
