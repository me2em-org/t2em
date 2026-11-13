import { describe, expect, it } from 'vitest';
import {
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

// Valid-shape fixtures: iv = 12 bytes, ciphertext ≥ 16 bytes (GCM tag),
// ephemeralPubKey = 32 bytes — enforced by validateEnvelope (ТЗ §4.2/4.3).
const CT = 'A'.repeat(43); // 43 chars base64url = 32 bytes
const IV12 = 'B'.repeat(16); // 16 chars base64url = 12 bytes
const PK32 = 'C'.repeat(43); // 32 bytes

describe('isEnvelope (wrapper over validateEnvelope, single source of truth)', () => {
  it('accepts a valid Mode B envelope', () => {
    const env: ModeBEnvelope = { v: 1, mode: 'sym', ciphertext: CT, iv: IV12 };
    expect(isEnvelope(env)).toBe(true);
  });

  it('accepts a valid Mode A envelope', () => {
    const env: ModeAEnvelope = {
      v: 1,
      mode: 'x25519',
      ephemeralPubKey: PK32,
      ciphertext: CT,
      iv: IV12,
    };
    expect(isEnvelope(env)).toBe(true);
  });

  it('rejects unknown modes, wrong versions, undersized fields', () => {
    expect(isEnvelope({ v: 1, mode: 'rsa', ciphertext: CT, iv: IV12 })).toBe(false);
    expect(isEnvelope({ v: 2, mode: 'sym', ciphertext: CT, iv: IV12 })).toBe(false);
    expect(isEnvelope({ v: 1, mode: 'sym', ciphertext: 'AA', iv: IV12 })).toBe(false); // ct < tag
    expect(isEnvelope({ v: 1, mode: 'sym', ciphertext: CT, iv: 'BB' })).toBe(false); // iv ≠ 12B
    expect(isEnvelope(null)).toBe(false);
    expect(isEnvelope('sym')).toBe(false);
  });
});

// UNSUPPORTED_VERSION taxonomy is covered in mode-b.test.ts via
// `validateEnvelope` — the only validation implementation there is.
