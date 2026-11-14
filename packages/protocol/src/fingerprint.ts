/**
 * Fingerprint — 16-char key verification token (ТЗ §4.2.1, v2.1 fix #4).
 *
 * fingerprint = base64url(sha256(pubkey))[0..16]
 *
 * 16 base64url chars = 96 bits: collision at ~2⁴⁸ keys (birthday
 * paradox). The previous 8-char form (48 bits) collided at ~16M keys,
 * which makes the fingerprint useless for large systems — the length
 * was raised to 16 in ТЗ v2.1 §4.2.1.
 *
 * Used by CLI/SDK/MCP to protect against key substitution (MITM):
 * the parties compare fingerprints out-of-band before Mode A use.
 */
import { b64uDecodeStrict, b64uEncode } from './base64url.js';
import { sha256 } from './hash.js';

/** Canonical fingerprint length in characters (§4.2.1: 16 = 96 bits). */
export const FINGERPRINT_LENGTH = 16;

/** Compute the 16-char fingerprint of a raw 32-byte public key. */
export async function fingerprintPubKey(pubKey: Uint8Array): Promise<string> {
  if (pubKey.length !== 32) {
    throw new Error(`MALFORMED: pubkey must be 32 bytes, got ${pubKey.length}`);
  }
  const hash = await sha256(pubKey);
  return b64uEncode(hash).slice(0, FINGERPRINT_LENGTH);
}

/** Fingerprint from a base64url-encoded public key string. */
export async function fingerprintPubKeyB64u(pubKeyB64u: string): Promise<string> {
  return fingerprintPubKey(b64uDecodeStrict(pubKeyB64u));
}

/**
 * §3.6 fixed public-API name for the fingerprint function. Async
 * because sha256 comes from @me2em/crypto's WebCrypto layer — the
 * §3.6 sketch shows a sync signature, which WebCrypto cannot honour.
 */
export const generateFingerprint = fingerprintPubKey;
