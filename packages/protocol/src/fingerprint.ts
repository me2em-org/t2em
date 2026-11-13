/**
 * Fingerprint — 8-char key verification token (ТЗ §4.2.1, §2.1).
 *
 * fingerprint = base64url(sha256(pubkey))[0..8]
 *
 * Used by CLI/SDK/MCP to protect against key substitution (MITM):
 * the parties compare fingerprints out-of-band before Mode A use.
 */
import { b64uDecodeStrict, b64uEncode } from './base64url.js';
import { sha256 } from './hash.js';

/** Canonical fingerprint length in characters (§4.2.1). */
export const FINGERPRINT_LENGTH = 8;

/** Compute the 8-char fingerprint of a raw 32-byte public key. */
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
