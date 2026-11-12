/**
 * Pure argument parsing for `t2em-cli` (ТЗ §8.2).
 * Kept side-effect-free so the exit-code contract is unit-testable.
 *
 * Exit codes: 0 success · 1 error · 2 invalid arguments.
 */

export type CommandName = 'push' | 'pull' | 'keygen' | 'delete';

export type ParsedInvocation =
  | { kind: 'help' }
  | { kind: 'version' }
  | { kind: 'command'; command: CommandName; args: string[] }
  | { kind: 'invalid'; reason: string };

const COMMANDS: readonly CommandName[] = ['push', 'pull', 'keygen', 'delete'];

export const HELP_TEXT = `t2em-cli — Zero-Knowledge Token Transfer (t2em.com)

Usage:
  echo "secret" | t2em-cli push [--ttl <60..900>] [--to <pubkey>]
  t2em-cli pull <url> [--key <keyfile>]
  t2em-cli keygen --out <keyfile>
  t2em-cli delete <url> --token <delete_token>

Secrets are read from stdin only (--secret is forbidden by contract).
Diagnostics are printed to stderr.
Exit codes: 0 success, 1 error, 2 invalid arguments.`;

export function parseArgs(argv: readonly string[]): ParsedInvocation {
  if (argv.length === 0) return { kind: 'help' };

  const first = argv[0];
  if (first === '--help' || first === '-h' || first === 'help') return { kind: 'help' };
  if (first === '--version' || first === '-v') return { kind: 'version' };

  if (!(COMMANDS as readonly string[]).includes(first)) {
    return { kind: 'invalid', reason: `unknown command: ${first}` };
  }
  return { kind: 'command', command: first as CommandName, args: argv.slice(1) };
}
