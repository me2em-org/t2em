import { describe, expect, it } from 'vitest';
import {
  assertSupportedVersion,
  HKDF_INFO_DROP_V1,
  isEnvelope,
  MAX_TTL_SECONDS,
  MIN_TTL_SECONDS,
  T2EM_PROTOCOL_VERSION,
  type ModeAEnvelope,
  type ModeBEnvelope,
} from '../src/index.js';

describe('protocol v1 constants', () => {
  it('fixes the wire-level constants per ТЗ §4', () => {
    expect(T2EM_PROTOCOL_VERSION).toBe(1);
    expect(MIN_TTL_SECONDS).toBe(60);
    expect(MAX_TTL_SECONDS).toBe(900);
  });

  it('freezes the HKDF info string (ТЗ §4.5)', () => {
    expect(HKDF_INFO_DROP_V1).toBe('me2em/crypto/v1/t2em-drop');
  });
});

describe('isEnvelope', () => {
  it('accepts a valid Mode B envelope', () => {
    const env: ModeBEnvelope = { v: 1, mode: 'sym', ciphertext: 'AA', iv: 'BB' };
    expect(isEnvelope(env)).toBe(true);
  });

  it('accepts a valid Mode A envelope', () => {
    const env: ModeAEnvelope = {
      v: 1,
      mode: 'x25519',
      ephemeralPubKey: 'AA',
      ciphertext: 'BB',
      iv: 'CC',
    };
    expect(isEnvelope(env)).toBe(true);
  });

  it('rejects unknown modes and wrong versions', () => {
    expect(isEnvelope({ v: 1, mode: 'rsa', ciphertext: 'AA', iv: 'BB' })).toBe(false);
    expect(isEnvelope({ v: 2, mode: 'sym', ciphertext: 'AA', iv: 'BB' })).toBe(false);
    expect(isEnvelope(null)).toBe(false);
    expect(isEnvelope('sym')).toBe(false);
  });
});

describe('assertSupportedVersion', () => {
  it('passes for v1 and throws UNSUPPORTED_VERSION otherwise', () => {
    expect(() => assertSupportedVersion(1)).not.toThrow();
    expect(() => assertSupportedVersion(2)).toThrow(/UNSUPPORTED_VERSION/);
  });
});
