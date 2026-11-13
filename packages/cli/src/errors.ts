/**
 * CLI error taxonomy (ТЗ §8.2 exit codes).
 *
 * UsageError → exit 2 (invalid arguments)
 * HttpError / CryptoError / anything else → exit 1 (runtime failure)
 *
 * Integrators branch on the class, never on message text.
 */

/** Invalid usage: malformed url, missing option, bad flag value. */
export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UsageError';
  }
}

/** Non-2xx relay response, mapped from the §5 API contract. */
export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string | undefined,
    message: string,
    readonly retryAfterSeconds: number | undefined = undefined,
  ) {
    super(message);
    this.name = 'HttpError';
  }
}
