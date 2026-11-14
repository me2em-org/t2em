/**
 * X25519 keyfile for Mode A (ТЗ §8.2, format «уточнено» in v2.1).
 *
 * File I/O + generation live here; payload VALIDATION is single-sourced
 * in `@t2em/protocol` (`parseKeyFileJson`) so the CLI, MCP server and
 * any other client accept exactly the same files:
 *
 *   { "version": 1, "type": "x25519",
 *     "privateKey": "<base64url 32B>", "publicKey": "<base64url 32B>",
 *     "createdAt": "<ISO-8601 Z, seconds precision>",
 *     "fingerprint": "<16-char base64url, §4.2.1>" }
 *
 * Legacy (pre-v2.1) `v`/`kind` files are still read (format 'legacy').
 * The current format self-verifies on load — a spliced fingerprint
 * fails closed.
 *
 * The private key material is wiped two-pass after use (§4.4).
 */
import { chmodSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { generateX25519KeyPair, secureWipeMultiple } from '@me2em/crypto';
import {
  b64uEncode,
  fingerprintPubKeyB64u,
  parseKeyFileJson,
  KEYFILE_VERSION,
  KEYFILE_TYPE,
  KEYFILE_KIND,
  type Fingerprint,
  type ParsedKeyFile,
} from '@t2em/protocol';

// §8.2 constants are single-sourced in @t2em/protocol.
export { KEYFILE_VERSION, KEYFILE_TYPE, KEYFILE_KIND };

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

export type LoadedKey = ParsedKeyFile;

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
  try {
    const publicKey = b64uEncode(pair.publicKey);
    const json: KeyFileJson = {
      version: KEYFILE_VERSION,
      type: KEYFILE_TYPE,
      privateKey: b64uEncode(pair.privateKey),
      publicKey,
      createdAt: nowIsoSeconds(),
      fingerprint: await fingerprintPubKeyB64u(publicKey),
    };
    // mode in writeFileSync is umask-dependent — chmod explicitly (§8.2).
    writeFileSync(outPath, JSON.stringify(json, null, 2) + '\n', { mode: 0o600 });
    chmodSync(outPath, 0o600);
    warnWiderPermissions(outPath, warn);
    return publicKey;
  } finally {
    secureWipeMultiple(pair.privateKey);
  }
}

/**
 * Load a keyfile: §8.2 current format (fingerprint self-verified) or
 * the pre-v2.1 legacy format (accepted, marked 'legacy'). Warns when
 * permissions are wider than 0600 (§8.2). Validation errors carry the
 * §4.5 code (`MALFORMED: …`) from `parseKeyFileJson`.
 */
export async function loadKeyFile(
  path: string,
  warn: (line: string) => void = () => undefined,
): Promise<LoadedKey> {
  warnWiderPermissions(path, warn);
  let payload: unknown;
  try {
    payload = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    throw new Error(`keyfile is not valid JSON: ${path}`);
  }
  return parseKeyFileJson(payload);
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
