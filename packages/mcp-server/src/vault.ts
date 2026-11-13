/**
 * `InMemorySecretVault` (ТЗ §8.4) — secrets live in the RAM of the MCP
 * process, never in the LLM context and never on disk.
 *
 * - `secret_handle` is `sec_<uuid v4>` — a reference, never the secret.
 * - `wipe` performs a two-pass overwrite (random noise, then zeros —
 *   the same mitigation contract as `@me2em/crypto` `secureWipe`)
 *   before the entry is deleted.
 * - Zero-logging: nothing in this module ever writes to stdout/stderr.
 */
import { randomUUID } from 'node:crypto';

/** `sec_<uuid>` — the handle shape fixed by the ТЗ. */
const HANDLE_RE = /^sec_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function isSecretHandle(value: unknown): value is string {
  return typeof value === 'string' && HANDLE_RE.test(value);
}

/** What a handle points at: a pulled secret or a generated private key. */
export type VaultKind = 'secret' | 'privkey';

export interface VaultEntryMeta {
  handle: string;
  kind: VaultKind;
  createdAt: number;
  byteLength: number;
}

interface VaultEntry extends VaultEntryMeta {
  bytes: Uint8Array;
}

export class InMemorySecretVault {
  readonly #entries = new Map<string, VaultEntry>();

  /** Store secret bytes; returns a fresh `sec_<uuid>` handle. */
  put(bytes: Uint8Array, kind: VaultKind = 'secret'): string {
    if (bytes.length === 0) throw new RangeError('vault refuses empty payloads');
    const handle = `sec_${randomUUID()}`;
    this.#entries.set(handle, {
      handle,
      kind,
      createdAt: Date.now(),
      byteLength: bytes.length,
      // Copy: callers may wipe/reuse their buffer after put().
      bytes: new Uint8Array(bytes),
    });
    return handle;
  }

  /** The stored bytes (a copy — mutating it cannot corrupt the vault). */
  get(handle: string): Uint8Array | undefined {
    const entry = this.#entries.get(handle);
    if (!entry) return undefined;
    return new Uint8Array(entry.bytes);
  }

  /** Metadata only — values never leave the vault through list(). */
  list(): VaultEntryMeta[] {
    return [...this.#entries.values()].map(({ bytes: _bytes, ...meta }) => meta);
  }

  /** Most recent privkey entry — the "active" keypair for Mode A pulls. */
  latestPrivKey(): { handle: string; bytes: Uint8Array } | undefined {
    for (const entry of [...this.#entries.values()].reverse()) {
      if (entry.kind === 'privkey') {
        return { handle: entry.handle, bytes: new Uint8Array(entry.bytes) };
      }
    }
    return undefined;
  }

  /**
   * Two-pass wipe (§4.4): random noise overwrites the original pattern,
   * zeros overwrite the noise; then the entry is deleted. Returns
   * `true` when a handle existed and was wiped.
   */
  wipe(handle: string): boolean {
    const entry = this.#entries.get(handle);
    if (!entry) return false;
    secureWipe(entry.bytes);
    this.#entries.delete(handle);
    return true;
  }

  get size(): number {
    return this.#entries.size;
  }
}

/** Two-pass in-place overwrite — mirrors `@me2em/crypto` `secureWipe`. */
export function secureWipe(array: Uint8Array): void {
  if (array.length === 0) return;
  const noise = new Uint8Array(array.length);
  for (let pass = 0; pass < 2; pass++) {
    crypto.getRandomValues(noise);
    array.set(noise);
  }
  array.fill(0);
}
