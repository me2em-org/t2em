/**
 * Mode A — asymmetric E2EE on X25519 (ТЗ §4.2).
 *
 * The sender holds the recipient's static X25519 public key out of
 * band (keyfile / fingerprint check / we2em registry in v2.0). The
 * relay sees only the sealed envelope — it can never derive the AES
 * key (§6.3 zero-knowledge).
 *
 * Key schedule (§4.2, freeze rule §4.5):
 *   shared   = X25519(eph_priv, recipient_pub)          — 32B, full
 *   salt     = eph_pub || recipient_pub                 — 64B, UKS-safe
 *   aes_key  = HKDF-SHA256(shared, salt, HKDF_INFO_DROP_V1, 32)
 *   iv       = random 12B
 *   ct       = AES-256-GCM(aes_key, iv, plaintext)      — includes 16B tag
 *
 * All secret buffers are wiped two-pass via `secureWipe` (§4.4) — a
 * mitigation, not a guarantee (JSDoc of @me2em/crypto applies).
 */
import {
  decryptAead,
  encryptAead,
  generateX25519KeyPair,
  hkdfWithInfo,
  importAeadKey,
  secureWipeMultiple,
  x25519SharedSecret,
  deriveX25519PublicKey,
} from '@me2em/crypto';
import { T2EM_PROTOCOL_VERSION, type ModeAEnvelope } from './index.js';
import { HKDF_INFO_DROP_V1 } from './index.js';
import { EnvelopeValidationError } from './envelope.js';
import { b64uDecodeStrict, b64uEncode } from './base64url.js';

/** X25519 public/private key length in bytes (RFC 7748). */
export const X25519_KEY_BYTES = 32;

/**
 * Seal `plaintext` to a static X25519 `recipientPubKey` (§4.2 steps 1-7).
 *
 * Returns the envelope for `POST /api/v1/drop`; the share URL carries
 * NO secret fragment in Mode A. The ephemeral private key never leaves
 * this function alive (wiped in `finally`).
 */
export async function packDropAsym(
  plaintext: Uint8Array,
  recipientPubKey: Uint8Array,
): Promise<{ envelope: ModeAEnvelope }> {
  if (recipientPubKey.length !== X25519_KEY_BYTES) {
    throw new EnvelopeValidationError(
      'MALFORMED',
      `recipient pubkey must be ${X25519_KEY_BYTES} bytes`,
    );
  }
  const ephemeral = generateX25519KeyPair();
  let shared: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  let aesKeyBytes: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  try {
    shared = x25519SharedSecret(ephemeral.privateKey, recipientPubKey);
    const salt = concat(ephemeral.publicKey, recipientPubKey);
    aesKeyBytes = await hkdfWithInfo(shared, salt, HKDF_INFO_DROP_V1, 32);
    const key = await importAeadKey(aesKeyBytes);
    const { ciphertext, iv } = await encryptAead(key, plaintext);
    return {
      envelope: {
        v: T2EM_PROTOCOL_VERSION,
        mode: 'x25519',
        ephemeralPubKey: b64uEncode(ephemeral.publicKey),
        ciphertext: b64uEncode(ciphertext),
        iv: b64uEncode(iv),
      },
    };
  } finally {
    // §4.4: eph_priv, shared secret and derived key never outlive the call.
    secureWipeMultiple(ephemeral.privateKey, ephemeral.publicKey, shared, aesKeyBytes);
  }
}

/**
 * Open a Mode A envelope with the recipient's static X25519 private key.
 * Validates the envelope structure first (§4.5 taxonomy).
 */
export async function unpackDropAsym(
  envelope: ModeAEnvelope,
  recipientPrivKey: Uint8Array,
): Promise<Uint8Array> {
  const ephPub = b64uDecodeStrict(envelope.ephemeralPubKey);
  const ciphertext = b64uDecodeStrict(envelope.ciphertext);
  const iv = b64uDecodeStrict(envelope.iv);
  if (ephPub.length !== X25519_KEY_BYTES) {
    throw new EnvelopeValidationError(
      'MALFORMED',
      `ephemeralPubKey must be ${X25519_KEY_BYTES} bytes`,
    );
  }
  const recipientPub = deriveX25519PublicKey(recipientPrivKey);
  const shared = x25519SharedSecret(recipientPrivKey, ephPub);
  const salt = concat(ephPub, recipientPub);
  const aesKeyBytes = await hkdfWithInfo(shared, salt, HKDF_INFO_DROP_V1, 32);
  try {
    const key = await importAeadKey(aesKeyBytes);
    return await decryptAead(key, ciphertext, iv);
  } finally {
    secureWipeMultiple(recipientPub, shared, aesKeyBytes);
  }
}

/** Concatenate two byte arrays into a fresh buffer (salt building). */
function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}
