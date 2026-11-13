/**
 * `@t2em/web-ui` — embedded browser UI (vanilla TS, no framework).
 *
 * Этап 1D: full Mode B browser flow — create page (`/`), decrypt page
 * (`/s/:id`, envelope embedded as JSON data), static assets. The
 * relay mounts everything exported here (ТЗ §3.2, §5.3, §7.1).
 */
export * from './assets.js';
export * from './pages.js';

export const WEB_UI_VERSION = '0.1.0';

/** HTTP routes served by the relay that render this UI (ТЗ §5, §8.1). */
export const WEB_UI_ROUTES = ['/', '/s/:id'] as const;

/**
 * Minimal CSP for the embedded UI pages (ТЗ §3.1: security headers).
 * Served as a static header by the relay — kept here as the single
 * source of truth so relay and docs cannot drift.
 *
 * `script-src 'self'` + `style-src 'self'`: nothing inline is allowed,
 * the browser logic ships as `/ui.js` and styles as `/ui.css`.
 */
export const WEB_UI_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "connect-src 'self'",
  'base-uri \'none\'',
  "frame-ancestors 'none'",
].join('; ');
