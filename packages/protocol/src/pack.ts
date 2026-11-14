/**
 * Fixed public-API facade (ТЗ v2.1 §3.6): `packDrop` / `unpackDrop`.
 *
 * §3.6 pins the @me2em/protocol API — integrators (CLI, SDK, MCP, Web
 * UI) dispatch through exactly these functions instead of touching the
 * per-mode primitives directly. The facade also enforces the §4.5
 * cross-mode contract: an envelope passed with the WRONG mode option
 * fails closed (`MALFORMED`) — Mode A bytes can never be opened as
 * Mode B and vice versa.
 *
 * The §3.6 sketch types `symKey` as `Uint8Array` (raw 32 bytes); the
 * per-mode `packDropSym` returns the base64url fragment string, which
 * the facade decodes — callers b64u-encode it into the URL `#fragment`
 * (§4.3). `generateFingerprint` lives in `./fingerprint.js`.
 */
import { b64uDecodeStrict, b64uEncode } from './base64url.js';
import { EnvelopeValidationError } from './envelope.js';
import { packDropAsym, unpackDropAsym } from './mode-a.js';
import { packDropSym, unpackDropSym } from './mode-b.js';
import type { Envelope } from './index.js';

/** §3.6 pack options — exactly the two wire modes. */
export type PackOptions = { mode: 'sym' } | { mode: 'x25519'; recipientPubkey: Uint8Array };

/** §3.6 unpack options — symmetric raw key or the recipient's private key. */
export type UnpackOptions =
  | { mode: 'sym'; symKey: Uint8Array }
  | { mode: 'x25519'; recipientPrivkey: Uint8Array };

/** Encrypt `plaintext` into an Envelope v1 (§3.6 `packDrop`). */
export async function packDrop(
  plaintext: Uint8Array,
  options: PackOptions,
): Promise<{ envelope: Envelope; symKey?: Uint8Array }> {
  if (options.mode === 'sym') {
    const { envelope, symKey } = await packDropSym(plaintext);
    return { envelope, symKey: b64uDecodeStrict(symKey) };
  }
  const { envelope } = await packDropAsym(plaintext, options.recipientPubkey);
  return { envelope };
}

/** Decrypt an Envelope v1 to the exact plaintext (§3.6 `unpackDrop`). */
export async function unpackDrop(envelope: Envelope, options: UnpackOptions): Promise<Uint8Array> {
  if (options.mode !== envelope.mode) {
    // §4.5 cross-mode: fail closed on mode mismatch ( MALFORMED ).
    throw new EnvelopeValidationError(
      'MALFORMED',
      `envelope mode '${envelope.mode}' does not match options mode '${options.mode}'`,
    );
  }
  if (envelope.mode === 'sym') {
    if (!('symKey' in options)) {
      throw new EnvelopeValidationError('MALFORMED', 'sym unpack options require symKey');
    }
    return unpackDropSym(envelope, b64uEncode(options.symKey));
  }
  if (!('recipientPrivkey' in options)) {
    throw new EnvelopeValidationError('MALFORMED', 'x25519 unpack options require recipientPrivkey');
  }
  return unpackDropAsym(envelope, options.recipientPrivkey);
}
