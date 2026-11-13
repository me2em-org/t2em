/**
 * Mode B — Zero-Key Bootstrap (ТЗ §4.3).
 *
 * sym_key never touches the relay: it travels to the recipient inside
 * the URL `#fragment` (RFC 3986 — fragments are not sent to servers).
 * All secret buffers are wiped two-pass via `secureWipe` (§4.4).
 */
import {
  decryptAead,
  encryptAead,
  importAeadKey,
  randomBytes,
  secureWipe,
} from '@me2em/crypto';
import { T2EM_PROTOCOL_VERSION, type ModeBEnvelope } from './index.js';
import { EnvelopeValidationError } from './envelope.js';
import { b64uDecodeStrict, b64uEncode } from './base64url.js';

/** Key length for AES-256-GCM (ТЗ §11.2). */
export const SYM_KEY_BYTES = 32;

/** Encrypt `plaintext` under a fresh random symmetric key (Mode B). */
export async function packDropSym(plaintext: Uint8Array): Promise<{
  envelope: ModeBEnvelope;
  /** base64url(32B) — goes into the URL `#fragment`, never to the server. */
  symKey: string;
}> {
  const symKeyBytes = randomBytes(SYM_KEY_BYTES);
  try {
    const key = await importAeadKey(symKeyBytes);
    const { ciphertext, iv } = await encryptAead(key, plaintext);
    return {
      envelope: {
        v: T2EM_PROTOCOL_VERSION,
        mode: 'sym',
        ciphertext: b64uEncode(ciphertext),
        iv: b64uEncode(iv),
      },
      symKey: b64uEncode(symKeyBytes),
    };
  } finally {
    secureWipe(symKeyBytes); // §4.4 mitigation
  }
}

/** Decrypt a Mode B envelope with the key taken from the URL fragment. */
export async function unpackDropSym(envelope: ModeBEnvelope, symKey: string): Promise<Uint8Array> {
  const symKeyBytes = b64uDecodeStrict(symKey);
  if (symKeyBytes.length !== SYM_KEY_BYTES) {
    secureWipe(symKeyBytes);
    // §4.5 taxonomy: integrators branch on `code`, never on message text.
    throw new EnvelopeValidationError('MALFORMED', `sym key must be ${SYM_KEY_BYTES} bytes`);
  }
  try {
    const key = await importAeadKey(symKeyBytes);
    return await decryptAead(key, b64uDecodeStrict(envelope.ciphertext), b64uDecodeStrict(envelope.iv));
  } finally {
    secureWipe(symKeyBytes);
  }
}

/** UTF-8 helpers shared by all clients. */
export function encodeUtf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function decodeUtf8(b: Uint8Array): string {
  return new TextDecoder().decode(b);
}
