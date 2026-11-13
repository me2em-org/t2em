/**
 * Pure argument parsing for `t2em-cli` (ТЗ §8.2).
 * Kept side-effect-free so the exit-code contract is unit-testable.
 *
 * Two layers:
 *   parseArgs     — command routing (help/version/command/invalid)
 *   parseOptions  — per-command flags → structured options | invalid
 *
 * Exit codes: 0 success · 1 error · 2 invalid arguments.
 */
import {
  b64uDecodeStrict,
  MAX_TTL_SECONDS,
  MIN_TTL_SECONDS,
} from '@t2em/protocol';

export type CommandName = 'push' | 'pull' | 'keygen' | 'delete';

export type ParsedInvocation =
  | { kind: 'help' }
  | { kind: 'version' }
  | { kind: 'command'; command: CommandName; args: string[] }
  | { kind: 'invalid'; reason: string };

const COMMANDS: readonly CommandName[] = ['push', 'pull', 'keygen', 'delete'];

export const HELP_TEXT = `t2em-cli — Zero-Knowledge Token Transfer (t2em.com)

Usage:
  echo "secret" | t2em-cli push [--ttl <60..900>] [--to <base64url-pubkey>]
  t2em-cli pull <url> [--key <keyfile>]
  t2em-cli keygen --out <keyfile>
  t2em-cli delete <url> --token <delete_token>

Options:
  --ttl   drop lifetime in seconds, 60..900 (default: 300)
  --to    recipient X25519 pubkey, base64url 32B (Mode A); otherwise Mode B
  --key   X25519 keyfile for Mode A pulls (mutually exclusive with #fragment)
  --out   keyfile path for keygen (written with 0600)
  --token delete_token from push (stderr) for early destroy

Contract:
  secrets travel via stdin only — --secret is forbidden by design;
  the pull prints plaintext bytes to stdout without a trailing newline;
  diagnostics (fingerprints, delete token, drop id) go to stderr;
  base url is overridden with the T2EM_BASE_URL environment variable.
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

// ---------------------------------------------------------------------------
// Option layer
// ---------------------------------------------------------------------------

/** Default drop lifetime for `push` (ТЗ §8.2 examples use --ttl 300). */
export const DEFAULT_TTL_SECONDS = 300;

export type CommandOptions =
  | { command: 'push'; ttl: number; to: string | undefined }
  | { command: 'pull'; url: string; key: string | undefined }
  | { command: 'keygen'; out: string }
  | { command: 'delete'; url: string; token: string };

export type ParsedOptions =
  | { kind: 'options'; options: CommandOptions }
  | { kind: 'invalid'; reason: string };

/**
 * Turn raw command args into structured options. Pure: no fs, no net.
 * The url-shape check for pull/delete (fragment vs --key exclusivity)
 * also happens here so that malformed invocations fail fast with
 * exit code 2 before any network or crypto work.
 */
export function parseOptions(invocation: ParsedInvocation): ParsedOptions {
  if (invocation.kind !== 'command') {
    return { kind: 'invalid', reason: 'parseOptions expects a command invocation' };
  }
  const { command, args } = invocation;

  // The contract explicitly forbids passing secrets as arguments.
  if (args.includes('--secret')) {
    return { kind: 'invalid', reason: '--secret is forbidden: secrets travel via stdin only (§8.2)' };
  }

  switch (command) {
    case 'push':
      return parsePush(args);
    case 'pull':
      return parsePull(args);
    case 'keygen':
      return parseKeygen(args);
    case 'delete':
      return parseDelete(args);
  }
}

function parsePush(args: readonly string[]): ParsedOptions {
  let ttl = DEFAULT_TTL_SECONDS;
  let to: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const flag = args[i];
    if (flag === '--ttl') {
      const value = args[++i];
      const parsed = value === undefined ? NaN : Number(value);
      if (!Number.isInteger(parsed) || parsed < MIN_TTL_SECONDS || parsed > MAX_TTL_SECONDS) {
        return { kind: 'invalid', reason: `--ttl must be an integer ${MIN_TTL_SECONDS}..${MAX_TTL_SECONDS}` };
      }
      ttl = parsed;
    } else if (flag === '--to') {
      const value = args[++i];
      if (value === undefined) return { kind: 'invalid', reason: '--to requires a base64url pubkey' };
      let bytes: Uint8Array;
      try {
        bytes = b64uDecodeStrict(value);
      } catch {
        return { kind: 'invalid', reason: '--to is not valid base64url' };
      }
      if (bytes.length !== 32) {
        return { kind: 'invalid', reason: `--to pubkey must be 32 bytes, got ${bytes.length}` };
      }
      if (to !== undefined) return { kind: 'invalid', reason: '--to given more than once' };
      to = value;
    } else {
      return { kind: 'invalid', reason: `unknown option for push: ${flag}` };
    }
  }
  return { kind: 'options', options: { command: 'push', ttl, to } };
}

function parsePull(args: readonly string[]): ParsedOptions {
  const positional: string[] = [];
  let key: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const flag = args[i];
    if (flag === '--key') {
      const value = args[++i];
      if (value === undefined) return { kind: 'invalid', reason: '--key requires a keyfile path' };
      if (key !== undefined) return { kind: 'invalid', reason: '--key given more than once' };
      key = value;
    } else if (flag.startsWith('--')) {
      return { kind: 'invalid', reason: `unknown option for pull: ${flag}` };
    } else {
      positional.push(flag);
    }
  }
  if (positional.length !== 1) {
    return { kind: 'invalid', reason: 'pull requires exactly one <url>' };
  }
  const url = positional[0];
  const hasFragment = url.includes('#');
  if (hasFragment && key !== undefined) {
    return { kind: 'invalid', reason: '#fragment and --key are mutually exclusive (Mode B vs Mode A)' };
  }
  if (!hasFragment && key === undefined) {
    return { kind: 'invalid', reason: 'pull needs a Mode B url with #fragment or --key <keyfile> for Mode A' };
  }
  return { kind: 'options', options: { command: 'pull', url, key } };
}

function parseKeygen(args: readonly string[]): ParsedOptions {
  let out: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const flag = args[i];
    if (flag === '--out') {
      const value = args[++i];
      if (value === undefined) return { kind: 'invalid', reason: '--out requires a path' };
      if (out !== undefined) return { kind: 'invalid', reason: '--out given more than once' };
      out = value;
    } else {
      return { kind: 'invalid', reason: `unknown option for keygen: ${flag}` };
    }
  }
  if (out === undefined) return { kind: 'invalid', reason: 'keygen requires --out <keyfile>' };
  return { kind: 'options', options: { command: 'keygen', out } };
}

function parseDelete(args: readonly string[]): ParsedOptions {
  const positional: string[] = [];
  let token: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const flag = args[i];
    if (flag === '--token') {
      const value = args[++i];
      if (value === undefined) return { kind: 'invalid', reason: '--token requires a delete_token' };
      if (token !== undefined) return { kind: 'invalid', reason: '--token given more than once' };
      token = value;
    } else if (flag.startsWith('--')) {
      return { kind: 'invalid', reason: `unknown option for delete: ${flag}` };
    } else {
      positional.push(flag);
    }
  }
  if (positional.length !== 1) {
    return { kind: 'invalid', reason: 'delete requires exactly one <url>' };
  }
  if (token === undefined) {
    return { kind: 'invalid', reason: 'delete requires --token <delete_token>' };
  }
  return { kind: 'options', options: { command: 'delete', url: positional[0], token } };
}
