import { describe, expect, it } from 'vitest';
import { InMemorySecretVault, isSecretHandle, secureWipe } from '../src/vault.js';

describe('InMemorySecretVault (ТЗ §8.4)', () => {
  it('returns sec_<uuid v4> handles and copies on get()', () => {
    const vault = new InMemorySecretVault();
    const original = new TextEncoder().encode('sk-live-test');
    const handle = vault.put(original);

    expect(isSecretHandle(handle)).toBe(true);
    expect(handle).toMatch(/^sec_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);

    const copy = vault.get(handle)!;
    expect(new TextDecoder().decode(copy)).toBe('sk-live-test');

    // Mutating the copy must not corrupt the vault.
    copy.fill(0);
    expect(new TextDecoder().decode(vault.get(handle)!)).toBe('sk-live-test');
  });

  it('list() exposes metadata only — never values', () => {
    const vault = new InMemorySecretVault();
    const handle = vault.put(new TextEncoder().encode('topsecret'));
    const meta = vault.list();
    expect(meta).toHaveLength(1);
    expect(meta[0]!.handle).toBe(handle);
    expect(meta[0]!.byteLength).toBe(9);
    expect(meta[0]!.kind).toBe('secret');
    expect(JSON.stringify(meta)).not.toContain('topsecret');
  });

  it('wipe() two-pass overwrites and deletes', () => {
    const vault = new InMemorySecretVault();
    const handle = vault.put(new TextEncoder().encode('doomed'));
    expect(vault.wipe(handle)).toBe(true);
    expect(vault.get(handle)).toBeUndefined();
    expect(vault.wipe(handle)).toBe(false);
    expect(vault.size).toBe(0);
  });

  it('latestPrivKey() returns the most recent privkey entry', () => {
    const vault = new InMemorySecretVault();
    vault.put(new TextEncoder().encode('some-secret'), 'secret');
    vault.put(new Uint8Array(32).fill(1), 'privkey');
    vault.put(new TextEncoder().encode('another-secret'), 'secret');
    vault.put(new Uint8Array(32).fill(2), 'privkey');

    const latest = vault.latestPrivKey()!;
    expect(latest.bytes[0]).toBe(2);
    expect(latest.bytes.every((b, i) => b === 2 || i >= 1)).toBe(true);
  });

  it('latestPrivKey() is undefined while empty', () => {
    expect(new InMemorySecretVault().latestPrivKey()).toBeUndefined();
  });

  it('refuses empty payloads', () => {
    expect(() => new InMemorySecretVault().put(new Uint8Array(0))).toThrow(RangeError);
  });

  it('secureWipe zeroes the buffer in place', () => {
    const buf = new Uint8Array(16).fill(0xab);
    secureWipe(buf);
    expect(buf.every((b) => b === 0)).toBe(true);
  });

  it('isSecretHandle rejects non-handles', () => {
    expect(isSecretHandle('sec_not-a-uuid')).toBe(false);
    expect(isSecretHandle('sk-live-123')).toBe(false);
    expect(isSecretHandle(42)).toBe(false);
  });
});
