/**
 * Unified error surface (ТЗ §4.5 taxonomy): «Интеграция — по полям
 * code/level». Both the CLI (stderr lines + exit codes) and the MCP
 * server (isError content) format failures through this module so the
 * §4.5 code is always machine-recognizable in the message.
 */
import { EnvelopeValidationError } from './envelope.js';

/**
 * §4.5 error taxonomy — the codes integrators branch on. CryptoError
 * codes from @me2em/crypto and envelope validation codes map onto the
 * same list; client-side codes (HTTP status codes etc.) must NOT leak
 * into this namespace.
 */
const TAXONOMY: ReadonlySet<string> = new Set([
  'UNSUPPORTED_VERSION',
  'MALFORMED',
  'INVALID_LENGTH',
  'INVALID_IV',
  'DECRYPTION_FAILED',
]);

/**
 * Extract the §4.5 taxonomy code from a thrown error:
 *  - `EnvelopeValidationError` → its `code`;
 *  - `CryptoError` from @me2em/crypto (duck-typed `code`/`level`) →
 *    its `code` when it is part of the taxonomy;
 *  - anything else → `undefined`.
 */
export function errorCodeOf(error: unknown): string | undefined {
  if (error instanceof EnvelopeValidationError) return error.code;
  if (error instanceof Error) {
    const code = (error as { code?: unknown }).code;
    if (typeof code === 'string' && TAXONOMY.has(code)) return code;
  }
  return undefined;
}

/**
 * Human- AND machine-readable one-line diagnostic: `CODE: message`
 * (§4.5). Idempotent — messages that already carry the code prefix
 * (e.g. `EnvelopeValidationError` renders `MALFORMED: …` itself) are
 * returned unchanged, never double-prefixed.
 */
export function formatErrorLine(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  const code = errorCodeOf(error);
  if (code === undefined || message.startsWith(`${code}:`)) return message;
  return `${code}: ${message}`;
}
