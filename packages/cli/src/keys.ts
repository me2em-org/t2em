/**
 * X25519 keyfile for Mode A (ТЗ §8.2, §4.2.1).
 *
 * File format (JSON, UTF-8, written with 0600):
 *   { "v": 1, "kind": "t2em-x25519-key-v1",
 *     "privateKey": "<base64url 32B>", "publicKey": "<base64url 32B>" }
 *
 * The private key material is wiped two-pass after use (§4.4).
 */
import { chmodSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { generateX25519KeyPair, secureWipeMultiple } from '@me2em/crypto';
import { b64uDecodeStrict, b64uEncode, fingerprintPubKeyB64u } from '@t2em/protocol';

export const KEYFILE_KIND = 't2em-x25519-key-v1';
export const X25519_KEY_BYTES = 32;

export interface KeyFileJson {
  v: 1;
  kind: typeof KEYFILE_KIND;
  privateKey: string;
  publicKey: string;
}

export interface LoadedKey {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

/** Generate a keypair, write the keyfile with 0600, wipe the memory copy. */
export function keygenToFile(outPath: string, warn: (line: string) => void = () => undefined): string {
  const pair = generateX25519KeyPair();
  try {
    const json: KeyFileJson = {
      v: 1,
      kind: KEYFILE_KIND,
      privateKey: b64uEncode(pair.privateKey),
      publicKey: b64uEncode(pair.publicKey),
    };
    // mode in writeFileSync is umask-dependent — chmod explicitly (§8.2).
    writeFileSync(outPath, JSON.stringify(json, null, 2) + '\n', { mode: 0o600 });
    chmodSync(outPath, 0o600);
  } finally {
    secureWipeMultiple(pair.privateKey);
  }
  warnWiderPermissions(outPath, warn);
  return b64uEncode(pair.publicKey);
}

/** Load a keyfile, validate shape, warn if permissions are too wide. */
export function loadKeyFile(path: string, warn: (line: string) => void = () => undefined): LoadedKey {
  warnWiderPermissions(path, warn);
  let json: KeyFileJson;
  try {
    json = JSON.parse(readFileSync(path, 'utf8')) as KeyFileJson;
  } catch {
    throw new Error(`keyfile is not valid JSON: ${path}`);
  }
  if (json.v !== 1 || json.kind !== KEYFILE_KIND) {
    throw new Error(`unsupported keyfile kind: ${String((json as { kind?: unknown }).kind)}`);
  }
  const privateKey = b64uDecodeStrict(json.privateKey);
  const publicKey = b64uDecodeStrict(json.publicKey);
  if (privateKey.length !== X25519_KEY_BYTES || publicKey.length !== X25519_KEY_BYTES) {
    throw new Error(`keyfile keys must be ${X25519_KEY_BYTES} bytes`);
  }
  return { privateKey, publicKey };
}

function warnWiderPermissions(path: string, warn: (line: string) => void): void {
  try {
    const mode = statSync(path).mode & 0o777;
    if ((mode & 0o077) !== 0) {
      warn(`warning: keyfile permissions are ${mode.toString(8).padStart(3, '0')}, expected 600 — run: chmod 600 ${path}`);
    }
  } catch {
    // stat failure surfaces later with a better error
  }
}

/** Fingerprint line for stderr diagnostics (§4.2.1). */
export async function fingerprintLine(pubKeyB64u: string): Promise<string> {
  return `fingerprint: ${await fingerprintPubKeyB64u(pubKeyB64u)}`;
}
