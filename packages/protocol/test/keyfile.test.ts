/**
 * §8.2 keyfile parsing (parseKeyFileJson — the validator shared by
 * CLI/MCP) and the §4.5 unified error surface (errorCodeOf /
 * formatErrorLine).
 */
import { describe, expect, it } from 'vitest';
import {
  EnvelopeValidationError,
  KEYFILE_KIND,
  KEYFILE_TYPE,
  KEYFILE_VERSION,
  b64uEncode,
  errorCodeOf,
  fingerprintPubKeyB64u,
  formatErrorLine,
  parseKeyFileJson,
} from '../src/index.js';

const ZERO32 = 'A'.repeat(43); // base64url of 32 zero bytes

async function currentPayload(overrides: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
  return {
    version: KEYFILE_VERSION,
    type: KEYFILE_TYPE,
    privateKey: ZERO32,
    publicKey: ZERO32,
    createdAt: '2026-11-14T10:00:00Z',
    fingerprint: await fingerprintPubKeyB64u(ZERO32),
    ...overrides,
  };
}

describe('parseKeyFileJson (§8.2, shared CLI/MCP validator)', () => {
  it('accepts the current §8.2 format and verifies the fingerprint', async () => {
    const parsed = await parseKeyFileJson(await currentPayload());
    expect(parsed.format).toBe('current');
    expect(parsed.privateKey.length).toBe(32);
    expect(parsed.publicKey.length).toBe(32);
  });

  it('accepts the legacy v/kind format without a fingerprint check', async () => {
    const parsed = await parseKeyFileJson({
      v: 1,
      kind: KEYFILE_KIND,
      privateKey: ZERO32,
      publicKey: ZERO32,
    });
    expect(parsed.format).toBe('legacy');
    expect(parsed.privateKey.length).toBe(32);
  });

  it('fails closed on a spliced fingerprint (MALFORMED)', async () => {
    await expect(parseKeyFileJson(await currentPayload({ fingerprint: '0'.repeat(16) }))).rejects.toMatchObject({
      code: 'MALFORMED',
    });
  });

  it('rejects missing createdAt in the current format (MALFORMED)', async () => {
    await expect(parseKeyFileJson(await currentPayload({ createdAt: undefined }))).rejects.toMatchObject({
      code: 'MALFORMED',
    });
  });

  it('rejects wrong key lengths and unknown kinds (MALFORMED)', async () => {
    await expect(parseKeyFileJson(await currentPayload({ privateKey: 'AAAA' }))).rejects.toMatchObject({
      code: 'MALFORMED',
    });
    await expect(parseKeyFileJson({ v: 1, kind: 'other' })).rejects.toMatchObject({ code: 'MALFORMED' });
    await expect(parseKeyFileJson('not an object')).rejects.toMatchObject({ code: 'MALFORMED' });
  });
});

describe('error surface (§4.5 code/level contract)', () => {
  class FakeCryptoError extends Error {
    constructor(readonly code: string, readonly level: string) {
      super('auth failure or corrupt data');
    }
  }

  it('errorCodeOf maps EnvelopeValidationError and CryptoError codes', () => {
    expect(errorCodeOf(new EnvelopeValidationError('MALFORMED', 'x'))).toBe('MALFORMED');
    expect(errorCodeOf(new EnvelopeValidationError('UNSUPPORTED_VERSION', 'v=2'))).toBe('UNSUPPORTED_VERSION');
    expect(errorCodeOf(new FakeCryptoError('DECRYPTION_FAILED', 'CIPHER'))).toBe('DECRYPTION_FAILED');
    // Client-side codes must NOT leak into the §4.5 namespace.
    expect(errorCodeOf(new FakeCryptoError('DROP_NOT_FOUND', 'HTTP'))).toBeUndefined();
    expect(errorCodeOf(new Error('plain'))).toBeUndefined();
    expect(errorCodeOf(undefined)).toBeUndefined();
  });

  it('formatErrorLine prefixes the code once and stays idempotent', () => {
    // EnvelopeValidationError already renders `MALFORMED: …` itself.
    expect(formatErrorLine(new EnvelopeValidationError('MALFORMED', 'bad thing'))).toBe('MALFORMED: bad thing');
    // CryptoError message carries no code — the surface adds it.
    expect(formatErrorLine(new FakeCryptoError('DECRYPTION_FAILED', 'CIPHER'))).toBe(
      'DECRYPTION_FAILED: auth failure or corrupt data',
    );
    // Non-taxonomy errors pass through unchanged.
    expect(formatErrorLine(new Error('plain failure'))).toBe('plain failure');
    expect(formatErrorLine('string failure')).toBe('string failure');
  });

  it('b64uEncode produces the pinned fingerprint length used by keyfiles', async () => {
    expect(await fingerprintPubKeyB64u(ZERO32)).toHaveLength(16);
    expect(b64uEncode(new Uint8Array(32))).toBe(ZERO32);
  });
});
