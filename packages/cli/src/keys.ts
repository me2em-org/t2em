/**
 * X25519 keyfile for Mode A (ТЗ §8.2, format «уточнено» in v2.1).
 *
 * Current (§8.2) file format — JSON, UTF-8, written with 0600:
 *   { "version": 1, "type": "x25519",
 *     "privateKey": "<base64url 32B>", "publicKey": "<base64url 32B>",
 *     "createdAt": "<ISO-8601 Z, seconds precision>",
 *     "fingerprint": "<16-char base64url, §4.2.1>" }
 *
 * Legacy format (pre-v2.1) is still READ for backward compatibility:
 *   { "v": 1, "kind": "t2em-x25519-key-v1", privateKey, publicKey }
 *
 * The new format self-verifies: on load, the stored `fingerprint` is
 * recomputed from `publicKey` and must match — a corrupted or spliced
 * keyfile fails closed instead of silently sealing to the wrong key.
 *
 * The private key material is wiped two-pass after use (§4.4).
 */
import { chmodSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { generateX25519KeyPair, secureWipeMultiple } from '@me2em/crypto';
import {
  b64uDecodeStrict,
  b64uEncode,
  fingerprintPubKeyB64u,
  type Fingerprint,
} from '@t2em/protocol';

/** §8.2 fixed format constants. */
export const KEYFILE_VERSION = 1;
export const KEYFILE_TYPE = 'x25519';
/** Legacy (pre-v2.1) kind marker — read for compatibility, never written. */
export const KEYFILE_KIND = 't2em-x25519-key-v1';
export const X25519_KEY_BYTES = 32;

/** §8.2 keyfile shape (current). */
export interface KeyFileJson {
  version: 1;
  type: typeof KEYFILE_TYPE;
  privateKey: string;
  publicKey: string;
  /** ISO-8601 UTC, seconds precision. */
  createdAt: string;
  /** 16-char fingerprint of publicKey (§4.2.1) — verified on load. */
  fingerprint: Fingerprint;
}

/** Legacy keyfile shape (pre-v2.1, read-only compatibility). */
export interface LegacyKeyFileJson {
  v: 1;
  kind: typeof KEYFILE_KIND;
  privateKey: string;
  publicKey: string;
}

export interface LoadedKey {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  /** Format marker: 'current' (§8.2) or 'legacy' (pre-v2.1). */
  format: 'current' | 'legacy';
}

function validateKeys(privateKey: Uint8Array, publicKey: Uint8Array): void {
  if (privateKey.length !== X25519_KEY_BYTES || publicKey.length !== X25519_KEY_BYTES) {
    throw new Error(`keyfile keys must be ${X25519_KEY_BYTES} bytes`);
  }
}

/** ISO-8601 UTC with seconds precision (§8.2 example). */
function nowIsoSeconds(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/** Generate a keypair, write the §8.2 keyfile with 0600, wipe the memory copy. */
export async function keygenToFile(
  outPath: string,
  warn: (line: string) => void = () => undefined,
): Promise<string> {
  const pair = generateX25519KeyPair();
  let fingerprint: Fingerprint;
  try {
    const privateKey = pair.privateKey;
    const publicKey = pair.publicKey;
    fingerprint = await fingerprintPubKeyB64u(b64uEncode(publicKey));
    const json: KeyFileJson = {
      version: KEYFILE_VERSION,
      type: KEYFILE_TYPE,
      privateKey: b64uEncode(privateKey),
      publicKey: b64uEncode(publicKey),
      createdAt: nowIsoSeconds(),
      fingerprint,
    };
    // mode in writeFileSync is umask-dependent — chmod explicitly (§8.2).
    writeFileSync(outPath, JSON.stringify(json, null, 2) + '\n', { mode: 0o600 });
    chmodSync(outPath, 0o600);
    return b64uEncode(publicKey);
  } finally {
    // The KeyObject pair lives in @me2em/crypto — wipe our encoded copy.
    secureWipeMultiple(pair.privateKey);
  }
}

/**
 * Load a keyfile: §8.2 current format (fingerprint self-verified) or
 * the pre-v2.1 legacy format (accepted, marked 'legacy'). Warns when
 * permissions are wider than 0600 (§8.2).
 */
export async function loadKeyFile(
  path: string,
  warn: (line: string) => void = () => undefined,
): Promise<LoadedKey> {
  warnWiderPermissions(path, warn);
  let json: (KeyFileJson | LegacyKeyFileJson) & Record<string, unknown>;
  try {
    json = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    throw new Error(`keyfile is not valid JSON: ${path}`);
  }

  if (json.version === KEYFILE_VERSION && json.type === KEYFILE_TYPE) {
    const current = json as unknown as KeyFileJson;
    const privateKey = b64uDecodeStrict(current.privateKey);
    const publicKey = b64uDecodeStrict(current.publicKey);
    validateKeys(privateKey, publicKey);
    // Self-verification (§8.2): the stored fingerprint must match the
    // recomputed fingerprint of the public key.
    const recomputed = await fingerprintPubKeyB64u(current.publicKey);
    if (current.fingerprint !== recomputed) {
      throw new Error(
        `keyfile fingerprint mismatch: stored ${current.fingerprint}, recomputed ${recomputed}`,
      );
    }
    return { privateKey, publicKey, format: 'current' };
  }

  if (json.v === 1 && json.kind === KEYFILE_KIND) {
    const legacy = json as unknown as LegacyKeyFileJson;
    const privateKey = b64uDecodeStrict(legacy.privateKey);
    const publicKey = b64uDecodeStrict(legacy.publicKey);
    validateKeys(privateKey, publicKey);
    return { privateKey, publicKey, format: 'legacy' };
  }

  const kind = String(json.kind ?? json.type ?? '<none>');
  throw new Error(`unsupported keyfile kind: ${kind}`);
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
