/**
 * Base64URL helpers (RFC 4648 §5, no padding) — ТЗ §4.1.
 *
 * Single source of truth for the wire encoding used by every t2em
 * component (protocol, relay, CLI, SDK, MCP). Implemented on top of
 * standard base64 with character substitution and padding stripped.
 */

const B64URL_PLUS = '-';
const B64URL_SLASH = '_';

/** Encode bytes to unpadded base64url. */
export function b64uEncode(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i] as number);
  const b64 = btoa(bin); // stdlib base64 (with padding)
  return b64.replace(/\+/g, B64URL_PLUS).replace(/\//g, B64URL_SLASH).replace(/=+$/, '');
}

/** Throwing strict decoder: rejects any non-base64url alphabet or padding. */
export function b64uDecodeStrict(s: string): Uint8Array {
  if (s.length === 0) return new Uint8Array(0);
  if (!/^[A-Za-z0-9\-_]+$/.test(s)) {
    throw new Error('MALFORMED: not base64url (RFC 4648 §5, unpadded)');
  }
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
  const bin = atob(b64 + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** True when `s` decodes to exactly `byteLength` bytes. */
export function isB64uOfLength(s: string, byteLength: number): boolean {
  try {
    return b64uDecodeStrict(s).length === byteLength;
  } catch {
    return false;
  }
}
