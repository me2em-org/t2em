/**
 * Command implementations for `t2em-cli` (ТЗ §8.2).
 *
 * Each `run*` returns an exit code (0 success, 1 runtime failure) and
 * receives its I/O through `Io`, so tests run the full command layer
 * against the in-process relay app without sockets, ttys or the
 * filesystem beyond a temp keyfile.
 *
 * Diagnostics (fingerprints, delete token, drop id) go to `stderr`
 * only; `stdout` carries the share url / plaintext bytes — the UNIX
 * pipe contract (§8.2).
 */
import { secureWipeMultiple } from '@me2em/crypto';
import {
  b64uDecodeStrict,
  encodeUtf8,
  packDropAsym,
  packDropSym,
  unpackDropAsym,
  unpackDropSym,
} from '@t2em/protocol';
import { RelayClient, parseShareUrl, type WireEnvelope } from './client.js';
import { HttpError } from './errors.js';
import { fingerprintLine, keygenToFile, loadKeyFile } from './keys.js';
import type { CommandOptions } from './parse.js';

export interface Io {
  /** Full stdin bytes (the secret). */
  stdin(): Promise<Uint8Array>;
  /** Raw stdout — share urls and plaintext bytes only. */
  stdout(bytes: Uint8Array): void;
  /** Line-oriented diagnostics. */
  stderr(line: string): void;
}

export interface CommandDeps {
  client: RelayClient;
}

export async function runPush(options: Extract<CommandOptions, { command: 'push' }>, io: Io, deps: CommandDeps): Promise<number> {
  const plaintext = await io.stdin();
  if (plaintext.length === 0) {
    io.stderr('stdin is empty — nothing to drop');
    return 1;
  }
  let envelope: WireEnvelope;
  let shareUrl: string;
  if (options.to !== undefined) {
    io.stderr(await fingerprintLine(options.to));
    const { envelope: sealed } = await packDropAsym(plaintext, b64uDecodeStrict(options.to));
    envelope = sealed;
    const created = await deps.client.drop(envelope, options.ttl);
    io.stderr(`drop ${created.id} expires in ${created.expires_in}s`);
    shareUrl = created.url; // Mode A — no fragment, key stays with the recipient
  } else {
    const { envelope: sealed, symKey } = await packDropSym(plaintext);
    envelope = sealed;
    const created = await deps.client.drop(envelope, options.ttl);
    io.stderr(`drop ${created.id} expires in ${created.expires_in}s`);
    io.stderr(`delete token: ${created.delete_token}`);
    shareUrl = `${created.url}#${symKey}`; // §4.3 step 6-7: fragment never reaches the relay
  }
  io.stdout(encodeUtf8(shareUrl));
  return 0;
}

export async function runPull(options: Extract<CommandOptions, { command: 'pull' }>, io: Io, deps: CommandDeps): Promise<number> {
  const { id, fragment } = parseShareUrl(options.url);
  const envelope = await deps.client.consume(id);

  let plaintext: Uint8Array;
  if (options.key !== undefined) {
    if (envelope.mode !== 'x25519') {
      io.stderr(`relay envelope is '${envelope.mode}', but a Mode A keyfile was given`);
      return 1;
    }
    const key = loadKeyFile(options.key, io.stderr);
    try {
      if (envelope.senderPubKey !== undefined) {
        io.stderr(await fingerprintLine(envelope.senderPubKey)); // §4.2.1
      }
      plaintext = await unpackDropAsym(envelope, key.privateKey);
    } finally {
      secureWipeMultiple(key.privateKey); // §4.4
    }
  } else {
    if (envelope.mode !== 'sym') {
      io.stderr(`relay envelope is '${envelope.mode}', but the url carries a Mode B fragment`);
      return 1;
    }
    plaintext = await unpackDropSym(envelope, fragment as string);
  }
  io.stdout(plaintext);
  return 0;
}

export async function runKeygen(options: Extract<CommandOptions, { command: 'keygen' }>, io: Io, _deps: CommandDeps): Promise<number> {
  const publicKeyB64u = keygenToFile(options.out, io.stderr);
  io.stderr(await fingerprintLine(publicKeyB64u));
  io.stderr(`keyfile written: ${options.out} (0600) — share the pubkey, never the file`);
  io.stdout(encodeUtf8(publicKeyB64u));
  return 0;
}

export async function runDelete(options: Extract<CommandOptions, { command: 'delete' }>, io: Io, deps: CommandDeps): Promise<number> {
  const { id } = parseShareUrl(options.url);
  await deps.client.destroy(id, options.token);
  io.stderr(`drop ${id} destroyed`);
  return 0;
}

/** Human-readable line for an error that escapes a command. */
export function describeError(error: unknown): string {
  if (error instanceof HttpError) {
    if (error.status === 404) return 'drop not found, expired or already consumed';
    if (error.status === 429) {
      const wait = error.retryAfterSeconds !== undefined ? ` — retry in ${error.retryAfterSeconds}s` : '';
      return `rate limited${wait}`;
    }
    const code = error.code ? ` [${error.code}]` : '';
    return `relay error: HTTP ${error.status}${code} ${error.message}`;
  }
  if (error instanceof Error) return error.message;
  return String(error);
}
