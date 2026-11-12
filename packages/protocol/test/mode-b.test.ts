/**
 * Phase 1A tests — Mode B crypto, base64url, validation, fingerprint.
 * ТЗ §9.1: packDrop/unpackDrop, envelope validation, secureWipe checks.
 */
import { describe, expect, it } from 'vitest';
import {
  b64uDecodeStrict,
  b64uEncode,
  decodeUtf8,
  encodeUtf8,
  EnvelopeValidationError,
  fingerprintPubKey,
  isB64uOfLength,
  packDropSym,
  safeJsonParse,
  sha256Hex,
  SYM_KEY_BYTES,
  unpackDropSym,
  validateEnvelope,
} from '../src/index.js';

describe('base64url (RFC 4648 §5)', () => {
  it('round-trips arbitrary bytes without padding', () => {
    const bytes = new Uint8Array(256).map((_, i) => i);
    const enc = b64uEncode(bytes);
    expect(enc).not.toMatch(/[+/=]/);
    expect(b64uDecodeStrict(enc)).toEqual(bytes);
  });

  it('matches known vectors', () => {
    expect(b64uEncode(new Uint8Array([0xfb, 0xff, 0xbf]))).toBe('-_-_');
    expect(b64uEncode(new Uint8Array([0x00, 0x01, 0x02]))).toBe('AAEC');
  });

  it('rejects padded / standard-alphabet strings', () => {
    expect(() => b64uDecodeStrict('AAE=')).toThrow(/MALFORMED/);
    expect(() => b64uDecodeStrict('AA/+')).toThrow(/MALFORMED/);
    expect(isB64uOfLength('AAAA', 3)).toBe(true);
    expect(isB64uOfLength('****', 3)).toBe(false);
  });
});

describe('Mode B pack/unpack (ТЗ §4.3)', () => {
  it('encrypts then decrypts back to the same plaintext', async () => {
    const plaintext = encodeUtf8('sk-live-SECRET-1234\n');
    const { envelope, symKey } = await packDropSym(plaintext);
    expect(envelope.mode).toBe('sym');
    expect(envelope.v).toBe(1);
    expect(symKey.length).toBeGreaterThan(40); // 32B base64url ⇒ 43 chars
    expect(isB64uOfLength(symKey, SYM_KEY_BYTES)).toBe(true);

    const decrypted = await unpackDropSym(envelope, symKey);
    expect(decodeUtf8(decrypted)).toBe('sk-live-SECRET-1234\n');
  });

  it('uses a fresh key and IV per drop (no IV reuse, §11.2)', async () => {
    const p = encodeUtf8('same secret');
    const a = await packDropSym(p);
    const b = await packDropSym(p);
    expect(a.symKey).not.toBe(b.symKey);
    expect(a.envelope.iv).not.toBe(b.envelope.iv);
    expect(a.envelope.ciphertext).not.toBe(b.envelope.ciphertext);
  });

  it('fails authentication when the key is wrong (GCM tag)', async () => {
    const { envelope } = await packDropSym(encodeUtf8('secret'));
    const wrongKey = b64uEncode(new Uint8Array(SYM_KEY_BYTES).fill(7));
    await expect(unpackDropSym(envelope, wrongKey)).rejects.toThrow();
  });

  it('rejects malformed sym key length', async () => {
    const { envelope } = await packDropSym(encodeUtf8('secret'));
    await expect(unpackDropSym(envelope, b64uEncode(new Uint8Array(16)))).rejects.toThrow(/MALFORMED/);
  });
});

describe('envelope validation (ТЗ §5.2, §4.5)', () => {
  const validSym = { v: 1, mode: 'sym', ciphertext: b64uEncode(new Uint8Array(32)), iv: b64uEncode(new Uint8Array(12)) };

  it('accepts a well-formed Mode B envelope', () => {
    expect(validateEnvelope(validSym)).toEqual(validSym);
  });

  it('accepts a well-formed Mode A envelope with optional sender fields', () => {
    const env = {
      ...validSym,
      mode: 'x25519',
      ephemeralPubKey: b64uEncode(new Uint8Array(32)),
      senderSignature: b64uEncode(new Uint8Array(64)),
      senderPubKey: b64uEncode(new Uint8Array(32)),
    };
    expect(validateEnvelope(env)).toMatchObject({ mode: 'x25519' });
  });

  it('throws UNSUPPORTED_VERSION for foreign envelope.v', () => {
    try {
      validateEnvelope({ ...validSym, v: 2 });
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(EnvelopeValidationError);
      expect((e as EnvelopeValidationError).code).toBe('UNSUPPORTED_VERSION');
    }
  });

  it('throws MALFORMED on missing/bad fields', () => {
    const bad = [
      null,
      'string',
      [],
      { ...validSym, iv: 'short' }, // iv not 12 bytes
      { ...validSym, ciphertext: '' },
      { ...validSym, mode: 'rsa' },
      { ...validSym, v: '1' }, // string version
      { ...validSym, mode: 'x25519' }, // missing ephemeralPubKey
    ];
    for (const b of bad) {
      expect(() => validateEnvelope(b), JSON.stringify(b)).toThrow(EnvelopeValidationError);
    }
  });
});

describe('safeJsonParse (ТЗ §11.4)', () => {
  it('parses ordinary JSON', () => {
    expect(safeJsonParse('{"a":[1,2],"b":{"c":true}}')).toEqual({ a: [1, 2], b: { c: true } });
  });

  it('rejects __proto__ payloads', () => {
    expect(() => safeJsonParse('{"__proto__":{"polluted":true}}')).toThrow(/forbidden key/);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });
});

describe('fingerprint (ТЗ §4.2.1)', () => {
  it('is 8 chars of base64url(sha256(pubkey))', async () => {
    const pub = new Uint8Array(32).fill(3);
    const fp = await fingerprintPubKey(pub);
    expect(fp).toHaveLength(8);
    // Cross-check against the hex sha256 → base64url path.
    const hex = await sha256Hex(pub);
    const raw = Uint8Array.from(hex.match(/../g)!.map((h) => parseInt(h, 16)));
    expect(fp).toBe(b64uEncode(raw).slice(0, 8));
  });

  it('rejects non-32-byte keys', async () => {
    await expect(fingerprintPubKey(new Uint8Array(31))).rejects.toThrow(/MALFORMED/);
  });
});
