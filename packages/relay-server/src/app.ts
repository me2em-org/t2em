/**
 * Shared Hono application of the Blind Relay (ТЗ §3.4):
 * both the Cloudflare Workers entry (`worker.ts`) and the self-hosted
 * Node entry (`node.ts`) mount exactly this app; only the storage
 * adapter differs.
 *
 * Этап 1B — full drop API per ТЗ §5:
 *   POST   /api/v1/drop       — create a drop (§5.2)
 *   GET    /s/:id             — read a drop, GETDEL by default (§5.3)
 *   DELETE /api/v1/drop/:id   — early destruction via delete token (§5.4)
 *   GET    /health            — health check incl. storage ping (§5.6)
 * plus the Этап 0 liveness probe `/healthz`.
 *
 * Zero-Knowledge duties implemented here (ТЗ §6.3, §5.1):
 *   - request bodies are never logged and never echoed;
 *   - client IPs are hashed (sha256) into the rate-limit key and never
 *     stored or logged in plaintext;
 *   - errors follow the §4.5 taxonomy (`code` field, integration by
 *     code — never by message text).
 */
import { Hono, type Context } from 'hono';
import { randomBytes } from '@me2em/crypto';
import {
  MAX_TTL_SECONDS,
  MIN_TTL_SECONDS,
  T2EM_PROTOCOL_VERSION,
  type Envelope,
  type EnvelopeValidationError,
  b64uEncode,
  encodeUtf8,
  safeJsonParse,
  sha256Hex,
  validateEnvelope,
} from '@t2em/protocol';
import type { RelayStorage } from './storage/types.js';
import { T2EM_RELAY_VERSION } from './version.js';

export interface AppDeps {
  storage: RelayStorage;
  /** Origin used to build drop URLs (§5.1: https://t2em.com). */
  publicOrigin?: string;
  /** §5.1: 60 requests/minute per IP by default. */
  rateLimitPerMinute?: number;
  /** §5.1 max request payload in bytes (default 64 KiB). */
  maxPayloadBytes?: number;
  /** Epoch-ms clock — injectable for tests. */
  now?: () => number;
  /** Drop-id generator (uuid v4). */
  genId?: () => string;
  /** Delete-token generator (base64url of 32 random bytes, §5.2). */
  genDeleteToken?: () => Promise<string>;
  /**
   * Client-IP resolver. The returned value is hashed immediately and
   * never stored or logged in plaintext (§6.3).
   */
  getClientIp?: (c: Context) => string;
}

const DEFAULT_PUBLIC_ORIGIN = 'https://t2em.com';
const DEFAULT_RATE_LIMIT_PER_MINUTE = 60;
const DEFAULT_MAX_PAYLOAD_BYTES = 65536; // 64 KB (§5.1)

/** Only v4 uuids are issued by this relay; strict format = anti-enum. */
const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/** Headers applied to every response (ТЗ §3.1, §5.1, §8.6). */
function applySecurityHeaders(c: Context): void {
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('X-Frame-Options', 'DENY');
  c.header('Referrer-Policy', 'no-referrer');
  // Zero-Knowledge transport hygiene: nothing dynamic is cacheable.
  c.header('Cache-Control', 'no-store, no-cache, private');
}

/**
 * Reverse a hex string comparison in constant time (§5.4): the delete
 * token hash must not leak prefix-match information to a brute force.
 */
function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/** Default IP resolver — Workers `CF-Connecting-IP` first, proxies after. */
function defaultClientIp(c: Context): string {
  return (
    c.req.header('CF-Connecting-IP') ??
    c.req.header('X-Real-IP') ??
    c.req.header('X-Forwarded-For')?.split(',')[0]?.trim() ??
    'unknown'
  );
}

export function createApp(deps: AppDeps): Hono {
  const {
    storage,
    publicOrigin = DEFAULT_PUBLIC_ORIGIN,
    rateLimitPerMinute = DEFAULT_RATE_LIMIT_PER_MINUTE,
    maxPayloadBytes = DEFAULT_MAX_PAYLOAD_BYTES,
    now = Date.now,
    genId = () => crypto.randomUUID(),
    genDeleteToken = async () => b64uEncode(randomBytes(32)),
    getClientIp = defaultClientIp,
  } = deps;

  const app = new Hono();

  app.use('*', async (c, next) => {
    applySecurityHeaders(c);
    await next();
  });

  /** Single error body builder — integration by `code`, never text. */
  type ApiErrorStatus = 400 | 401 | 403 | 404 | 413 | 429 | 500;
  const apiError = (
    c: Context,
    status: ApiErrorStatus,
    code: string,
    message: string,
  ) => c.json({ error: { code, message } }, status);

  /**
   * 404 for "does not exist / expired / already read" (§5.3) — one
   * shared builder so every anti-enumeration path returns an identical
   * body. Timing: valid-uuid reads always perform the same two storage
   * ops (marker + GETDEL/GET) whether the drop exists or not.
   */
  const notFound = (c: Context): Response => apiError(c, 404, 'NOT_FOUND', 'Not found');

  /**
   * Per-IP rate limiting (§5.1, §6.1): `ratelimit:{sha256(ip)}:{minute}`,
   * INCR + EX 60. The raw IP exists only inside this call frame.
   */
  const enforceRateLimit = async (c: Context): Promise<Response | null> => {
    const ip = getClientIp(c);
    const ipHash = await sha256Hex(encodeUtf8(ip));
    const nowSec = Math.floor(now() / 1000);
    const minute = Math.floor(nowSec / 60);
    const count = await storage.hitRateLimit(`${ipHash}:${minute}`);
    if (count <= rateLimitPerMinute) return null;
    const retryAfter = Math.max(1, (minute + 1) * 60 - nowSec);
    return c.json(
      { error: { code: 'RATE_LIMITED', message: 'Too many requests' } },
      429,
      {
        'X-RateLimit-Limit': String(rateLimitPerMinute),
        'X-RateLimit-Remaining': '0',
        'Retry-After': String(retryAfter),
      },
    );
  };

  // -- §5.6 health -----------------------------------------------------------

  app.get('/health', async (c) => {
    const alive = await storage.ping().catch(() => false);
    if (!alive) {
      return c.json({ status: 'degraded', redis: 'unavailable' }, 503);
    }
    return c.json({ status: 'ok', redis: 'ok', version: T2EM_RELAY_VERSION });
  });

  // -- §5.2 create ------------------------------------------------------------

  app.post('/api/v1/drop', async (c) => {
    const limited = await enforceRateLimit(c);
    if (limited) return limited;

    const text = await c.req.text();
    // §5.1 max payload — checked before parsing (cheap reject first).
    if (text.length > maxPayloadBytes || encodeUtf8(text).length > maxPayloadBytes) {
      return apiError(c, 413, 'PAYLOAD_TOO_LARGE', 'Payload exceeds 64 KB');
    }

    let parsed: unknown;
    try {
      parsed = safeJsonParse(text);
    } catch (err) {
      if ((err as EnvelopeValidationError).name === 'EnvelopeValidationError') {
        // Forbidden prototype-pollution keys (§11.4) — MALFORMED.
        return apiError(c, 400, 'MALFORMED', 'Forbidden key in JSON body');
      }
      return apiError(c, 400, 'INVALID_JSON', 'Request body must be valid JSON');
    }

    const body = parsed as Record<string, unknown>;

    let envelope: Envelope;
    try {
      envelope = validateEnvelope(body.envelope);
    } catch (err) {
      if ((err as EnvelopeValidationError).name === 'EnvelopeValidationError') {
        const e = err as EnvelopeValidationError;
        return apiError(c, 400, e.code, e.message);
      }
      return apiError(c, 400, 'MALFORMED', 'Invalid envelope');
    }

    const ttl = body.ttl;
    if (typeof ttl !== 'number' || !Number.isInteger(ttl) || ttl < MIN_TTL_SECONDS || ttl > MAX_TTL_SECONDS) {
      return apiError(
        c,
        400,
        'INVALID_TTL',
        `ttl must be an integer between ${MIN_TTL_SECONDS} and ${MAX_TTL_SECONDS}`,
      );
    }

    const burn = body.burn_after_reading === undefined ? true : body.burn_after_reading;
    if (typeof burn !== 'boolean') {
      return apiError(c, 400, 'MALFORMED', 'burn_after_reading must be a boolean');
    }

    const id = genId();
    const deleteToken = await genDeleteToken();
    const tokenHash = await sha256Hex(encodeUtf8(deleteToken));

    // Three independent writes; no MULTI in the REST interface. A
    // partial failure leaves orphan keys that expire within the TTL —
    // never a confidentiality issue (§6.4).
    await storage.putDrop(id, JSON.stringify(envelope), ttl);
    await storage.putDeleteTokenHash(id, tokenHash, ttl);
    if (!burn) await storage.putBurnMarker(id, ttl);

    return c.json(
      {
        id,
        url: `${publicOrigin}/s/${id}`,
        expires_in: ttl,
        delete_token: deleteToken,
      },
      201,
    );
  });

  // -- §5.3 read ---------------------------------------------------------------

  app.get('/s/:id', async (c) => {
    const limited = await enforceRateLimit(c);
    if (limited) return limited;

    const id = c.req.param('id');
    // uuid format is public knowledge — rejecting it early leaks only
    // what the sender already knows; existing-vs-missing stays uniform.
    if (id.length > 64 || !UUID_V4_RE.test(id)) return notFound(c);

    // §6.1 refinement: burn:{id} marker exists only for non-burn drops,
    // so both branches below run exactly two storage ops and the 404
    // body is byte-identical for missing/expired/already-read (§5.3).
    const nonBurn = await storage.getBurnMarker(id);
    const value = nonBurn ? await storage.getDrop(id) : await storage.consumeDrop(id);
    if (value === null) return notFound(c);

    // TODO(Этап 1D): `Accept: text/html` serves the decrypting Web UI;
    // until then every Accept receives the JSON contract (§5.3).
    return c.json({ envelope: JSON.parse(value) as Envelope });
  });

  // -- §5.4 destroy -------------------------------------------------------------

  app.delete('/api/v1/drop/:id', async (c) => {
    const limited = await enforceRateLimit(c);
    if (limited) return limited;

    const token = c.req.header('X-Delete-Token');
    if (typeof token !== 'string' || token.length === 0) {
      return apiError(c, 401, 'UNAUTHORIZED', 'X-Delete-Token header is required');
    }

    const id = c.req.param('id');
    if (id.length > 64 || !UUID_V4_RE.test(id)) return notFound(c);

    const storedHash = await storage.getDeleteTokenHash(id);
    if (storedHash === null) return notFound(c);

    const providedHash = await sha256Hex(encodeUtf8(token));
    if (!timingSafeEqualHex(providedHash, storedHash)) {
      return apiError(c, 403, 'FORBIDDEN', 'Invalid delete token');
    }

    await storage.destroyDrop(id);
    // Idempotent by design: deleting an already-read (burned) drop
    // still clears delete:{id} and reports success (§5.4).
    return c.json({ deleted: true });
  });

  // -- Этап 0 liveness probe (infra monitors) ----------------------------------

  app.get('/healthz', (c) =>
    c.json({
      ok: true,
      service: 't2em-relay',
      version: T2EM_RELAY_VERSION,
      protocol: T2EM_PROTOCOL_VERSION,
    }),
  );

  app.notFound((c) => apiError(c, 404, 'NOT_FOUND', 'Unknown route'));

  // Zero-logging: report the failure class, never request bodies.
  app.onError((err, c) => {
    if (err instanceof Error && err.message.startsWith('NOT_IMPLEMENTED')) {
      return c.json({ error: { code: 'NOT_IMPLEMENTED', message: err.message } }, 501);
    }
    return c.json({ error: { code: 'INTERNAL', message: 'Internal error' } }, 500);
  });

  return app;
}
