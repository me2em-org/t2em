/**
 * Guarded HTTPS request engine for `t2em_http_request` (ТЗ §8.4).
 *
 * `guardedRequest` runs the redirect loop on top of `validateTarget`
 * (SSRF rules + DNS pinning) and caps the response body. The actual
 * socket work is behind the injectable `Connect` function — unit
 * tests drive every branch without opening sockets; production binds
 * it to `node:https` with a pinned-IP lookup.
 */
import type { IncomingHttpHeaders } from 'node:http';
import { SsrfError, validateTarget, type Resolver } from './ssrf.js';

export const MAX_REDIRECTS = 3;
export const DEFAULT_MAX_BODY_BYTES = 1_048_576; // 1 MiB

export interface GuardedRequestInit {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  maxBodyBytes?: number;
  maxRedirects?: number;
}

export interface GuardedResponse {
  status: number;
  headers: Record<string, string>;
  body: Uint8Array;
  /** URL after the final redirect hop. */
  finalUrl: string;
  /** How many redirect hops were taken. */
  hops: number;
}

/**
 * Low-level connection: perform ONE HTTPS request against the pinned
 * IP and return the response. Production impl: node:https with
 * `lookup` pinned to `pinnedIp` (SNI/host header stay correct).
 */
export type Connect = (args: {
  url: URL;
  pinnedIp: string;
  method: string;
  headers: Record<string, string>;
  body?: Uint8Array;
  timeoutMs: number;
}) => Promise<{ status: number; headers: IncomingHttpHeaders; body: Uint8Array }>;

export interface GuardedOptions {
  connect?: Connect;
  resolve?: Resolver;
}

const BODYLESS = new Set(['GET', 'HEAD', 'OPTIONS']);

/** Perform `url` with full SSRF validation, DNS pinning and redirect re-validation. */
export async function guardedRequest(
  rawUrl: string,
  init: GuardedRequestInit = {},
  options: GuardedOptions = {},
): Promise<GuardedResponse> {
  const connect = options.connect ?? nodeHttpsConnect;
  const maxRedirects = init.maxRedirects ?? MAX_REDIRECTS;
  const maxBodyBytes = init.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  const timeoutMs = init.timeoutMs ?? 10_000;

  let method = (init.method ?? 'GET').toUpperCase();
  let headers: Record<string, string> = { ...(init.headers ?? {}) };
  let body: string | undefined = init.body;
  let currentUrl = rawUrl;
  let pinnedIp: string | undefined;
  let hops = 0;

  for (;;) {
    const target = await validateTarget(currentUrl, options.resolve);
    pinnedIp = target.pinnedIp;

    if (body !== undefined && !BODYLESS.has(method)) {
      headers['content-length'] = String(Buffer.byteLength(body, 'utf8'));
    } else if (body !== undefined && BODYLESS.has(method)) {
      body = undefined;
    }

    const response = await connect({
      url: target.url,
      pinnedIp,
      method,
      headers,
      body: body === undefined ? undefined : Buffer.from(body, 'utf8'),
      timeoutMs,
    });
    const capped = capBody(response.body, maxBodyBytes);

    const status = response.status;
    if (status === 301 || status === 302 || status === 303 || status === 307 || status === 308) {
      const location = headerValue(response.headers, 'location');
      if (!location) throw new SsrfError(`redirect ${status} without location`);
      if (hops >= maxRedirects) throw new SsrfError(`more than ${maxRedirects} redirects`);
      hops += 1;
      currentUrl = new URL(location, target.url).toString(); // relative allowed
      if (status === 303) {
        method = 'GET';
        body = undefined;
      }
      // 301/302/303 drop the body per fetch semantics; 307/308 keep it.
      if (status === 301 || status === 302) body = undefined;
      headers = { ...headers };
      delete headers['content-length'];
      continue; // next hop is re-validated from scratch (SSRF, pinning)
    }

    return {
      status,
      headers: flattenHeaders(response.headers),
      body: capped,
      finalUrl: target.url.toString(),
      hops,
    };
  }
}

function capBody(body: Uint8Array, maxBodyBytes: number): Uint8Array {
  if (body.length <= maxBodyBytes) return body;
  throw new SsrfError(`response body exceeds ${maxBodyBytes} bytes`);
}

function headerValue(headers: IncomingHttpHeaders, name: string): string | undefined {
  const value = headers[name];
  if (Array.isArray(value)) return value[0];
  return value;
}

function flattenHeaders(headers: IncomingHttpHeaders): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    out[key] = Array.isArray(value) ? value.join(', ') : value;
  }
  return out;
}

/** Production Connect: node:https with DNS pinned to the validated IP. */
export const nodeHttpsConnect: Connect = async ({
  url,
  pinnedIp,
  method,
  headers,
  body,
  timeoutMs,
}) => {
  const https = await import('node:https');
  return new Promise((resolve, reject) => {
    const port = url.port ? Number(url.port) : 443;
    const request = https.request(
      {
        protocol: 'https:',
        hostname: url.hostname.replace(/^\[|\]$/g, ''),
        port,
        path: `${url.pathname}${url.search}`,
        method,
        headers,
        servername: url.hostname.replace(/^\[|\]$/g, ''),
        timeout: timeoutMs,
        // DNS pinning: whatever this lookup is asked about, answer with
        // the validated address — rebinding cannot swap it underneath.
        lookup: (_host, _opts, callback) =>
          callback(null, pinnedIp, pinnedIp.includes(':') ? 6 : 4),
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on('data', (chunk: Buffer) => chunks.push(chunk));
        response.on('end', () => {
          resolve({
            status: response.statusCode ?? 0,
            headers: response.headers,
            body: new Uint8Array(Buffer.concat(chunks)),
          });
        });
        response.on('error', reject);
      },
    );
    request.on('timeout', () => {
      request.destroy(new SsrfError(`timeout after ${timeoutMs}ms`));
    });
    request.on('error', reject);
    if (body !== undefined && !BODYLESS.has(method)) request.write(body);
    request.end();
  });
};
