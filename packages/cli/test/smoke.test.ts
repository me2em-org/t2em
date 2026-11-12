import { describe, expect, it } from 'vitest';
import { HELP_TEXT, parseArgs } from '../src/parse.js';

describe('parseArgs (ТЗ §8.2 exit-code contract)', () => {
  it('empty argv asks for help', () => {
    expect(parseArgs([])).toEqual({ kind: 'help' });
  });

  it('recognizes --help/-h/help and --version/-v', () => {
    expect(parseArgs(['--help']).kind).toBe('help');
    expect(parseArgs(['-h']).kind).toBe('help');
    expect(parseArgs(['--version']).kind).toBe('version');
    expect(parseArgs(['-v']).kind).toBe('version');
  });

  it('parses all four commands', () => {
    expect(parseArgs(['push', '--ttl', '300'])).toEqual({
      kind: 'command',
      command: 'push',
      args: ['--ttl', '300'],
    });
    expect(parseArgs(['pull', 'https://t2em.com/s/abc']).kind).toBe('command');
    expect(parseArgs(['keygen', '--out', './agent.key']).kind).toBe('command');
    expect(parseArgs(['delete', 'u', '--token', 't']).kind).toBe('command');
  });

  it('flags unknown commands as invalid (exit code 2 path)', () => {
    const res = parseArgs(['send']); // "send" — запрещённый синоним, ТЗ §8.5: только push/pull
    expect(res).toEqual({ kind: 'invalid', reason: 'unknown command: send' });
  });

  it('help text forbids --secret (secrets only via stdin)', () => {
    expect(HELP_TEXT).toContain('--secret is forbidden');
  });
});
