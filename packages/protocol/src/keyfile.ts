/**
 * X25519 keyfile — pure payload parsing (ТЗ §8.2).
 *
 * This module is deliberately fs-free so every client (CLI, MCP, SDK
 * bindings) shares ONE validation. Callers do their own file I/O and
 * hand the parsed JSON in.
 *
 * Current (§8.2) shape:
 *   { "version": 1, "type": "x25519",
 *     "privateKey": "<base64url 32B>", "publicKey": "<base64url 32B>",
 *     "createdAt": "<ISO-8601 Z, seconds precision>",
 *     "fingerprint": "<16-char base64url, §4.2.1>" }
 *
 * Legacy (pre-v2.1) shape, read for compatibility:
 *   { "v": 1, "kind": "t2em-x25519-key-v1", privateKey, publicKey }
 *
 * The current format self-verifies: the stored `fingerprint` must
 * match the recomputed fingerprint of `publicKey` — a corrupted or
 * spliced keyfile fails closed instead of silently sealing to the
 * wrong key.
 */
import { b64uDecodeStrict } from './base64url.js';
import { EnvelopeValidationError } from './envelope.js';
import { fingerprintPubKey } from './fingerprint.js';
import { X25519_KEY_BYTES } from './mode-a.js';

/** §8.2 fixed format constants. */
export const KEYFILE_VERSION = 1;
export const KEYFILE_TYPE = 'x25519';
/** Legacy (pre-v2.1) kind marker — read for compatibility, never written. */
export const KEYFILE_KIND = 't2em-x25519-key-v1';

/** Parsed key material from a §8.2 or legacy keyfile payload. */
export interface ParsedKeyFile {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  /** 'current' = §8.2 format (fingerprint verified); 'legacy' = pre-v2.1. */
  format: 'current' | 'legacy';
}

/**
 * Validate a parsed keyfile JSON payload. Throws
 * `EnvelopeValidationError` with the §4.5 taxonomy code (`MALFORMED`)
 * on any deviation — integrators branch on `code`, never on text.
 */
export async function parseKeyFileJson(payload: unknown): Promise<ParsedKeyFile> {
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    throw new EnvelopeValidationError('MALFORMED', `keyfile must be a JSON object, got ${typeof payload}`);
  }
  const p = payload as Record<string, unknown>;

  if (p.version === KEYFILE_VERSION && p.type === KEYFILE_TYPE) {
    const privateKey = decodeKey(p.privateKey, 'privateKey');
    const publicKey = decodeKey(p.publicKey, 'publicKey');
    if (typeof p.createdAt !== 'string' || p.createdAt.length === 0) {
      throw new EnvelopeValidationError('MALFORMED', 'keyfile.createdAt must be a non-empty ISO-8601 string');
    }
    // Self-verification (§8.2): stored fingerprint must match the
    // recomputed fingerprint of the public key.
    const recomputed = await fingerprintPubKey(publicKey);
    if (p.fingerprint !== recomputed) {
      throw new EnvelopeValidationError(
        'MALFORMED',
        `keyfile fingerprint mismatch: stored ${String(p.fingerprint)}, recomputed ${recomputed}`,
      );
    }
    return { privateKey, publicKey, format: 'current' };
  }

  if (p.v === 1 && p.kind === KEYFILE_KIND) {
    const privateKey = decodeKey(p.privateKey, 'privateKey');
    const publicKey = decodeKey(p.publicKey, 'publicKey');
    return { privateKey, publicKey, format: 'legacy' };
  }

  const kind = String(p.kind ?? p.type ?? '<none>');
  throw new EnvelopeValidationError('MALFORMED', `unsupported keyfile kind: ${kind}`);
}

function decodeKey(value: unknown, what: string): Uint8Array {
  if (typeof value !== 'string') {
    throw new EnvelopeValidationError('MALFORMED', `keyfile.${what} must be a base64url string`);
  }
  const decoded = b64uDecodeStrict(value);
  if (decoded.length !== X25519_KEY_BYTES) {
    throw new EnvelopeValidationError('MALFORMED', `keyfile keys must be ${X25519_KEY_BYTES} bytes`);
  }
  return decoded;
}
