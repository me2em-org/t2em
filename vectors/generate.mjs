#!/usr/bin/env node
/**
 * Deterministic generator for `vectors/t2em-drop.v1.json` (ТЗ §4.5).
 *
 * Test vectors are the bit-compatibility contract between the
 * TypeScript implementation (@t2em/protocol) and the Python SDK —
 * both must open the fixed envelopes to the exact plaintext, and the
 * TS side additionally re-seals with the fixed key material to prove
 * the whole key schedule (X25519 → HKDF → AES-GCM) matches.
 *
 * Determinism: every key and IV below is a FIXED byte string; no
 * randomness is used anywhere.
 *
 * Key schedule (ТЗ §4.2 Mode A):
 *   shared  = X25519(eph_priv, recip_pub)
 *   salt    = eph_pub || recip_pub                       (64B, UKS-safe)
 *   aes_key = HKDF-SHA256(shared, salt, HKDF_INFO_DROP_V1, 32)
 *   ct      = AES-256-GCM(aes_key, fixed_iv, plaintext)
 *
 * Mode B uses the raw sym key directly — no HKDF (§4.3).
 *
 * Run from the repo root:  node vectors/generate.mjs
 */
import { hkdfWithInfo, x25519SharedSecret, deriveX25519PublicKey } from '@me2em/crypto';
import { writeFileSync } from 'node:fs';

const HKDF_INFO = 'me2em/crypto/v1/t2em-drop';
const hex = (s) => Uint8Array.from(s.match(/../g).map((h) => parseInt(h, 16)));
const b64u = (bytes) => Buffer.from(bytes).toString('base64url');

// Fixed test keys (NEVER use outside of test vectors).
const RECIP_PRIV = hex('101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f');
const EPH_PRIV = hex('303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f');
const SYM_KEY = hex('a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf');

const IV_A = hex('0102030405060708090a0b0c');
const IV_B = hex('f0f1f2f3f4f5f6f7f8f9fafb');

const recipPub = deriveX25519PublicKey(RECIP_PRIV);
const ephPub = deriveX25519PublicKey(EPH_PRIV);
const shared = x25519SharedSecret(EPH_PRIV, recipPub);
const salt = new Uint8Array([...ephPub, ...recipPub]);
const aesKeyA = await hkdfWithInfo(shared, salt, HKDF_INFO, 32);

async function aesGcm(keyBytes, iv, plaintext) {
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext));
  // Sanity: the fixed key+iv must decrypt back to the plaintext.
  const back = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct));
  if (Buffer.from(back).compare(Buffer.from(plaintext)) !== 0) throw new Error('AES-GCM sanity failed');
  return ct;
}

const PLAINTEXTS = [
  ['ascii', 't2em test vector v1'],
  ['utf8', 'привет, мир — кириллица и UTF-8 обязательны'],
  ['empty', ''],
];

const vectors = [];
for (const [name, plaintext] of PLAINTEXTS) {
  const pt = new TextEncoder().encode(plaintext);

  const ctA = await aesGcm(aesKeyA, IV_A, pt);
  vectors.push({
    name: `mode-a-${name}`,
    envelope: {
      v: 1,
      mode: 'x25519',
      ephemeralPubKey: b64u(ephPub),
      ciphertext: b64u(ctA),
      iv: b64u(IV_A),
    },
    recipient_privkey: b64u(RECIP_PRIV),
    recipient_pubkey: b64u(recipPub),
    ephemeral_privkey: b64u(EPH_PRIV),
    plaintext_utf8: plaintext,
  });

  const ctB = await aesGcm(SYM_KEY, IV_B, pt);
  vectors.push({
    name: `mode-b-${name}`,
    envelope: { v: 1, mode: 'sym', ciphertext: b64u(ctB), iv: b64u(IV_B) },
    sym_key: b64u(SYM_KEY),
    plaintext_utf8: plaintext,
  });
}

const out = {
  $comment: 't2em drop test vectors v1 (ТЗ §4.5) — deterministic, fixed keys/IVs. Test material only.',
  protocol: 1,
  hkdf_info: HKDF_INFO,
  vectors,
};

const path = new URL('./t2em-drop.v1.json', import.meta.url).pathname;
writeFileSync(path, JSON.stringify(out, null, 2) + '\n');
console.log(`written ${path}: ${vectors.length} vectors`);
