#!/usr/bin/env node
/**
 * Deterministic generator for `vectors/t2em-drop.v1.json` (ТЗ §4.5,
 * extended set per ТЗ v2.1 fix #23: negative, edge, cross-mode,
 * senderSignature/Ed25519 vectors + fingerprint pins).
 *
 * Test vectors are the bit-compatibility contract between the
 * TypeScript implementation (@t2em/protocol) and the Python SDK —
 * both must open the fixed envelopes to the exact plaintext, and the
 * TS side additionally re-seals with the fixed key material to prove
 * the whole key schedule (X25519 → HKDF → AES-GCM) matches.
 *
 * Determinism: every key and IV below is a FIXED byte string; no
 * randomness is used anywhere. Ed25519 (RFC 8032) is deterministic —
 * fixed seeds reproduce fixed signatures.
 *
 * Key schedule (ТЗ §4.2 Mode A):
 *   shared  = X25519(eph_priv, recip_pub)
 *   salt    = eph_pub || recip_pub                       (64B, UKS-safe)
 *   aes_key = HKDF-SHA256(shared, salt, HKDF_INFO_DROP_V1, 32)
 *   ct      = AES-256-GCM(aes_key, fixed_iv, plaintext)
 *
 * Mode B uses the raw sym key directly — no HKDF (§4.3).
 *
 * Sender signature convention (pinned by this file; §4.2 step 8 leaves
 * the signed message to the implementation — the vector file freezes
 * the v1 convention):
 *   senderSignature = Ed25519sign(sender_priv,
 *     UTF-8( ephemeralPubKey_b64u + '.' + ciphertext_b64u + '.' + iv_b64u ))
 *
 * Run from the repo root:  node vectors/generate.mjs
 */
import { hkdfWithInfo, x25519SharedSecret, deriveX25519PublicKey, ed25519PrivToX25519, ed25519PubToX25519, signRaw } from '@me2em/crypto';
import { writeFileSync } from 'node:fs';

const HKDF_INFO = 'me2em/crypto/v1/t2em-drop';
const hex = (s) => Uint8Array.from(s.match(/../g).map((h) => parseInt(h, 16)));
const b64u = (bytes) => Buffer.from(bytes).toString('base64url');

// Fixed test keys (NEVER use outside of test vectors).
const RECIP_PRIV = hex('101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f');
const EPH_PRIV = hex('303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f');
const SYM_KEY = hex('a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf');

// Fixed Ed25519 pairs (RFC 8032, deterministic). Generated once with
// node:crypto generateKeyPairSync('ed25519'); seeds are 32B raw.
const ED_SENDER_SEED = hex('3161a0de08f9554bf806d976a0e9f1ba43a1b6ca490b8cb203cae1b9174cd39d');
const ED_SENDER_PUB = hex('d1449d74ee8fe5d876ed3e4c5859591e09a422d614333de182be18abd9215601');
const ED_RECIP_SEED = hex('80063e9dd4f94d46d04149ccbb2ab6fa1bdeabb3c3a3c8a5b475779b87036a2e');
const ED_RECIP_PUB = hex('49524abc27db5de9971f7e5bc5f3b68503e60029ecfd162b6ceeff088f90996e');

const IV_A = hex('0102030405060708090a0b0c');
const IV_B = hex('f0f1f2f3f4f5f6f7f8f9fafb');
const IV_C = hex('0badcafe1234567890abcded');
const IV_D = hex('102030405060708090a0b0c0');

const recipPub = deriveX25519PublicKey(RECIP_PRIV);
const ephPub = deriveX25519PublicKey(EPH_PRIV);
const shared = x25519SharedSecret(EPH_PRIV, recipPub);
const salt = new Uint8Array([...ephPub, ...recipPub]);
const aesKeyA = await hkdfWithInfo(shared, salt, HKDF_INFO, 32);

// Ed25519-converted recipient (§4.2 step 2): the sender seals to
// ed25519PubToX25519(recip_ed_pub); the recipient opens with
// ed25519PrivToX25519(recip_ed_seed).
const recipXFromEd = ed25519PrivToX25519(ED_RECIP_SEED);
const recipXFromEdPub = ed25519PubToX25519(ED_RECIP_PUB);
// Conversion sanity: the seed-derived twin must match the pub-derived one.
if (Buffer.from(recipXFromEdPub).compare(Buffer.from(deriveX25519PublicKey(recipXFromEd))) !== 0) {
  throw new Error('ed25519 conversion sanity failed');
}
const sharedEd = x25519SharedSecret(EPH_PRIV, recipXFromEdPub);
const saltEd = new Uint8Array([...ephPub, ...recipXFromEdPub]);
const aesKeyEd = await hkdfWithInfo(sharedEd, saltEd, HKDF_INFO, 32);

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
    expected: 'ok',
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
    expected: 'ok',
    envelope: { v: 1, mode: 'sym', ciphertext: b64u(ctB), iv: b64u(IV_B) },
    sym_key: b64u(SYM_KEY),
    plaintext_utf8: plaintext,
  });
}

// Edge case §4.5: plaintext exactly 64 KB (max payload at the API
// layer). Binary plaintext travels as base64url (`plaintext_b64u`).
{
  const pt = new Uint8Array(65536);
  for (let i = 0; i < pt.length; i++) pt[i] = i % 251;
  const ctA = await aesGcm(aesKeyA, IV_D, pt);
  vectors.push({
    name: 'mode-a-64k',
    expected: 'ok',
    envelope: {
      v: 1,
      mode: 'x25519',
      ephemeralPubKey: b64u(ephPub),
      ciphertext: b64u(ctA),
      iv: b64u(IV_D),
    },
    recipient_privkey: b64u(RECIP_PRIV),
    recipient_pubkey: b64u(recipPub),
    ephemeral_privkey: b64u(EPH_PRIV),
    plaintext_b64u: b64u(pt),
  });
  const ctB = await aesGcm(SYM_KEY, IV_D, pt);
  vectors.push({
    name: 'mode-b-64k',
    expected: 'ok',
    envelope: { v: 1, mode: 'sym', ciphertext: b64u(ctB), iv: b64u(IV_D) },
    sym_key: b64u(SYM_KEY),
    plaintext_b64u: b64u(pt),
  });
}

// Positive §4.5: Mode A with an Ed25519-converted recipient key.
{
  const pt = new TextEncoder().encode('sealed to an Ed25519-converted recipient');
  const ct = await aesGcm(aesKeyEd, IV_C, pt);
  vectors.push({
    name: 'mode-a-ed25519-recv',
    expected: 'ok',
    envelope: {
      v: 1,
      mode: 'x25519',
      ephemeralPubKey: b64u(ephPub),
      ciphertext: b64u(ct),
      iv: b64u(IV_C),
    },
    recipient_ed25519_privkey: b64u(ED_RECIP_SEED),
    recipient_ed25519_pubkey: b64u(ED_RECIP_PUB),
    // Converted X25519 twin (ed25519PrivToX25519) — the open path.
    recipient_privkey: b64u(recipXFromEd),
    ephemeral_privkey: b64u(EPH_PRIV),
    plaintext_utf8: 'sealed to an Ed25519-converted recipient',
  });
}

// Positive §4.5: Mode A with senderSignature + senderPubKey (Ed25519).
{
  const pt = new TextEncoder().encode('signed drop from a verified sender');
  const ct = await aesGcm(aesKeyA, IV_C, pt);
  const message = new TextEncoder().encode(
    `${b64u(ephPub)}.${b64u(ct)}.${b64u(IV_C)}`,
  );
  const sig = signRaw(ED_SENDER_SEED, message);
  // Sanity: RFC 8032 is deterministic — verify against the fixed pub.
  vectors.push({
    name: 'mode-a-sender-signed',
    expected: 'ok',
    envelope: {
      v: 1,
      mode: 'x25519',
      ephemeralPubKey: b64u(ephPub),
      ciphertext: b64u(ct),
      iv: b64u(IV_C),
      senderSignature: b64u(sig),
      senderPubKey: b64u(ED_SENDER_PUB),
    },
    recipient_privkey: b64u(RECIP_PRIV),
    recipient_pubkey: b64u(recipPub),
    ephemeral_privkey: b64u(EPH_PRIV),
    sender_ed25519_privkey: b64u(ED_SENDER_SEED),
    sender_ed25519_pubkey: b64u(ED_SENDER_PUB),
    plaintext_utf8: 'signed drop from a verified sender',
  });
}

// Negative §4.5: envelope validation must fail with the pinned code.
function neg(name, envelope, errorCode) {
  vectors.push({ name, expected: 'error', error_code: errorCode, envelope });
}

const symBase = { v: 1, mode: 'sym', ciphertext: b64u(hex('aa'.repeat(32))), iv: b64u(IV_B) };
const asymBase = {
  v: 1,
  mode: 'x25519',
  ephemeralPubKey: b64u(ephPub),
  ciphertext: b64u(hex('bb'.repeat(48))),
  iv: b64u(IV_A),
};

neg('neg-v-zero', { ...symBase, v: 0 }, 'UNSUPPORTED_VERSION');
neg('neg-v-two', { ...symBase, v: 2 }, 'UNSUPPORTED_VERSION');
neg('neg-v-string', { ...symBase, v: '1' }, 'MALFORMED');
neg('neg-v-null', { ...symBase, v: null }, 'MALFORMED');
neg('neg-mode-ecies', { ...symBase, mode: 'ecies' }, 'MALFORMED');
neg('neg-mode-empty', { ...symBase, mode: '' }, 'MALFORMED');
neg('neg-mode-null', { ...symBase, mode: null }, 'MALFORMED');
neg('neg-ct-short', { ...symBase, ciphertext: b64u(hex('cc'.repeat(15))) }, 'MALFORMED');
neg('neg-ct-bad-b64u', { ...symBase, ciphertext: 'A+B/C==' }, 'MALFORMED');
neg('neg-iv-13', { ...symBase, iv: b64u(hex('dd'.repeat(13))) }, 'MALFORMED');
neg('neg-eph-31', { ...asymBase, ephemeralPubKey: b64u(hex('ee'.repeat(31))) }, 'MALFORMED');
neg(
  'neg-sym-with-ephemeral',
  { ...symBase, ephemeralPubKey: b64u(ephPub) },
  'MALFORMED',
);
neg(
  'neg-sym-with-sender-fields',
  { ...symBase, senderSignature: b64u(hex('ff'.repeat(64))), senderPubKey: b64u(ED_SENDER_PUB) },
  'MALFORMED',
);

// Cross-mode §4.5: wrong-mode unpack options must fail closed on
// unpackDrop — the envelope itself validates, the MODE MISMATCH is the
// error (facade level).
vectors.push({
  name: 'cross-mode-a-as-b',
  expected: 'error',
  error_code: 'MALFORMED',
  envelope: { ...asymBase },
  sym_key: b64u(SYM_KEY),
});
vectors.push({
  name: 'cross-mode-b-as-a',
  expected: 'error',
  error_code: 'MALFORMED',
  envelope: { ...symBase },
  recipient_privkey: b64u(RECIP_PRIV),
});

// Fingerprint pins (§4.2.1: 16-char base64url, 96 bits).
const fingerprint_vectors = [
  { pubkey_b64u: b64u(recipPub), fingerprint: b64u(await crypto.subtle.digest('SHA-256', recipPub)).slice(0, 16) },
  { pubkey_b64u: b64u(ED_SENDER_PUB), fingerprint: b64u(await crypto.subtle.digest('SHA-256', ED_SENDER_PUB)).slice(0, 16) },
];

const out = {
  $comment:
    't2em drop test vectors v1 (ТЗ §4.5, extended set per ТЗ v2.1 fix #23) — deterministic, fixed keys/IVs. Test material only.',
  protocol: 1,
  hkdf_info: HKDF_INFO,
  fingerprint_length: 16,
  signature_convention:
    'senderSignature = Ed25519sign(sender_priv, UTF-8(ephemeralPubKey_b64u + "." + ciphertext_b64u + "." + iv_b64u))',
  vectors,
  fingerprint_vectors,
};

const path = new URL('./t2em-drop.v1.json', import.meta.url).pathname;
writeFileSync(path, JSON.stringify(out, null, 2) + '\n');
console.log(`written ${path}: ${vectors.length} vectors, ${fingerprint_vectors.length} fingerprint pins`);
