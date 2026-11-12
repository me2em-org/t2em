/**
 * `@t2em/web-ui` — embedded browser UI (vanilla TS, no framework).
 *
 * Этап 0 skeleton: fixes the asset contract served by the relay.
 * The Mode B decrypt page lands in Этап 1–2.
 */

export const WEB_UI_VERSION = '0.1.0';

/** HTTP routes served by the relay that render this UI (ТЗ §5, §8.1). */
export const WEB_UI_ROUTES = ['/', '/s/:id'] as const;

/**
 * Minimal CSP for the embedded UI pages (ТЗ §3.1: security headers).
 * Served as a static header by the relay — kept here as the single
 * source of truth so relay and docs cannot drift.
 */
export const WEB_UI_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "connect-src 'self'",
  'base-uri \'none\'',
  "frame-ancestors 'none'",
].join('; ');
