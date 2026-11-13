import { describe, expect, it } from 'vitest';
import { parseArgs, parseOptions, type ParsedInvocation } from '../src/parse.js';

const VALID_PUB = Buffer.from('a'.repeat(32), 'utf8').toString('base64url');
const SHORT_PUB = Buffer.from('a'.repeat(31), 'utf8').toString('base64url');

function opts(argv: readonly string[]) {
  const invocation = parseArgs(argv);
  if (invocation.kind !== 'command') throw new Error(`expected command, got ${invocation.kind}`);
  return parseOptions(invocation);
}

describe('parseOptions (ТЗ §8.2 flag contract)', () => {
  it('push defaults to ttl 300 without --to', () => {
    expect(opts(['push'])).toEqual({
      kind: 'options',
      options: { command: 'push', ttl: 300, to: undefined },
    });
  });

  it('push accepts valid ttl bounds and pubkey', () => {
    expect(opts(['push', '--ttl', '60', '--to', VALID_PUB])).toEqual({
      kind: 'options',
      options: { command: 'push', ttl: 60, to: VALID_PUB },
    });
    expect(opts(['push', '--ttl', '900']).kind).toBe('options');
  });

  it('push rejects ttl outside 60..900 and non-integers (exit 2 path)', () => {
    for (const bad of ['59', '901', '0', 'abc', '2.5', '']) {
      expect(opts(['push', '--ttl', bad]).kind).toBe('invalid');
    }
  });

  it('push rejects a pubkey that is not 32 bytes', () => {
    expect(opts(['push', '--to', SHORT_PUB]).kind).toBe('invalid');
    expect(opts(['push', '--to', 'not-base64!']).kind).toBe('invalid');
  });

  it('--secret is forbidden by contract (§8.2)', () => {
    const res = opts(['push', '--secret', 'x']);
    expect(res.kind).toBe('invalid');
    if (res.kind === 'invalid') expect(res.reason).toContain('stdin');
  });

  it('pull requires one url and exactly one of #fragment / --key', () => {
    expect(opts(['pull', 'https://t2em.com/s/abc#k']).kind).toBe('options');
    expect(opts(['pull', 'https://t2em.com/s/abc', '--key', './k.key']).kind).toBe('options');
    expect(opts(['pull', 'https://t2em.com/s/abc#k', '--key', './k.key']).kind).toBe('invalid');
    expect(opts(['pull', 'https://t2em.com/s/abc']).kind).toBe('invalid');
    expect(opts(['pull']).kind).toBe('invalid');
    expect(opts(['pull', 'a', 'b']).kind).toBe('invalid');
  });

  it('keygen requires --out', () => {
    expect(opts(['keygen', '--out', './agent.key']).kind).toBe('options');
    expect(opts(['keygen']).kind).toBe('invalid');
    expect(opts(['keygen', '--out']).kind).toBe('invalid');
  });

  it('delete requires one url and --token', () => {
    expect(opts(['delete', 'https://t2em.com/s/abc', '--token', 't']).kind).toBe('options');
    expect(opts(['delete', 'https://t2em.com/s/abc']).kind).toBe('invalid');
    expect(opts(['delete', '--token', 't']).kind).toBe('invalid');
    expect(opts(['delete', 'u', '--token', 'a', '--token', 'b']).kind).toBe('invalid');
  });

  it('unknown flags fail with exit-code-2 semantics', () => {
    expect(opts(['push', '--json']).kind).toBe('invalid');
    expect(opts(['pull', 'url', '--force']).kind).toBe('invalid');
    expect(opts(['keygen', '--out', 'a', 'extra']).kind).toBe('invalid');
  });

  it('parseOptions rejects non-command invocations defensively', () => {
    const help: ParsedInvocation = { kind: 'help' };
    expect(parseOptions(help).kind).toBe('invalid');
  });
});
