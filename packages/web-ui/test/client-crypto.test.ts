/**
 * Bit-compatibility between the browser client (/ui.js WebCrypto path)
 * and `@t2em/protocol` Mode B (ТЗ §4.3).
 *
 * Node ≥ 22 exposes the same WebCrypto as browsers, so these tests
 * replay the exact primitive calls the shipped /ui.js performs and
 * cross-verify against the protocol package in both directions:
 *   browser-encrypt → protocol-decrypt
 *   protocol-encrypt → browser-decrypt
 */
import { describe, expect, it } from 'vitest';
import {
  b64uDecodeStrict,
  b64uEncode,
  decodeUtf8,
  encodeUtf8,
  packDropSym,
  unpackDropSym,
} from '@t2em/protocol';

/** Mirror of the /ui.js create-page crypto (create() in src/assets.ts). */
async function browserEncrypt(plaintext: string): Promise<{
  envelope: { v: 1; mode: 'sym'; ciphertext: string; iv: string };
  symKey: string;
}> {
  const key = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aesKey = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, encodeUtf8(plaintext)),
  );
  return {
    envelope: { v: 1, mode: 'sym', ciphertext: b64uEncode(ciphertext), iv: b64uEncode(iv) },
    symKey: b64uEncode(key),
  };
}

/** Mirror of the /ui.js open-page crypto (runOpen() in src/assets.ts). */
async function browserDecrypt(
  envelope: { ciphertext: string; iv: string },
  symKey: string,
): Promise<string> {
  const keyBytes = b64uDecodeStrict(symKey);
  const aesKey = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64uDecodeStrict(envelope.iv) },
    aesKey,
    b64uDecodeStrict(envelope.ciphertext),
  );
  return decodeUtf8(new Uint8Array(plaintext));
}

describe('browser WebCrypto ↔ @t2em/protocol interop (§4.3)', () => {
  it('decrypts a drop encrypted the way /ui.js does', async () => {
    const { envelope, symKey } = await browserEncrypt('ghp_browser_to_protocol_123');
    const plaintext = await unpackDropSym(envelope, symKey);
    expect(decodeUtf8(plaintext)).toBe('ghp_browser_to_protocol_123');
  });

  it('decrypts a protocol-made drop the way /s/:id page does', async () => {
    const { envelope, symKey } = await packDropSym(encodeUtf8('protocol_to_browser_456'));
    const plaintext = await browserDecrypt(envelope, symKey);
    expect(plaintext).toBe('protocol_to_browser_456');
  });

  it('rejects a wrong fragment key (GCM auth failure)', async () => {
    const { envelope } = await browserEncrypt('top secret');
    const wrongKey = b64uEncode(new Uint8Array(32).fill(9));
    await expect(unpackDropSym(envelope, wrongKey)).rejects.toThrow();
  });
});
