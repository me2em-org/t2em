/**
 * Base64URL helpers (RFC 4648 §5, no padding) — ТЗ §4.1.
 *
 * Single source of truth for the wire encoding used by every t2em
 * component (protocol, relay, CLI, SDK, MCP).
 *
 * Built on the `@me2em/crypto` base64 primitives (`toBase64` /
 * `fromBase64`) per §4.1 — application code must not hand-roll crypto
 * plumbing where an audited primitive exists; only the URL-safe
 * alphabet translation lives here, because `@me2em/crypto` exposes
 * standard (padded) base64 only.
 */
import { fromBase64, toBase64 } from '@me2em/crypto';

const B64URL_PLUS = '-';
const B64URL_SLASH = '_';

/** Encode bytes to unpadded base64url. */
export function b64uEncode(bytes: Uint8Array): string {
  return toBase64(bytes)
    .replace(/\+/g, B64URL_PLUS)
    .replace(/\//g, B64URL_SLASH)
    .replace(/=+$/, '');
}

/** Throwing strict decoder: rejects any non-base64url alphabet or padding. */
export function b64uDecodeStrict(s: string): Uint8Array {
  if (s.length === 0) return new Uint8Array(0);
  if (!/^[A-Za-z0-9\-_]+$/.test(s)) {
    throw new Error('MALFORMED: not base64url (RFC 4648 §5, unpadded)');
  }
  // Length ≡ 1 (mod 4) cannot be valid base64 for any alphabet.
  if (s.length % 4 === 1) {
    throw new Error('MALFORMED: invalid base64url length');
  }
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
  return fromBase64(b64 + pad);
}

/** True when `s` decodes to exactly `byteLength` bytes. */
export function isB64uOfLength(s: string, byteLength: number): boolean {
  try {
    return b64uDecodeStrict(s).length === byteLength;
  } catch {
    return false;
  }
}
