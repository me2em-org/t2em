/**
 * Relay API client for `t2em-cli` (ТЗ §5, §8.2).
 *
 * Speaks only the JSON contract (`Accept: application/json`) — no HTML
 * parsing, ever (§8.1 API-first). The transport is injectable so the
 * command layer is testable against the in-process Hono app without
 * opening sockets.
 */
import { UsageError, HttpError } from './errors.js';

/** `{ id, url, expires_in, delete_token }` from `POST /api/v1/drop`. */
export interface CreatedDrop {
  id: string;
  url: string;
  expires_in: number;
  delete_token: string;
}

/** Envelope shape as stored by the relay (opaque to the transport) —
 *  the canonical protocol type, re-exported for one source of truth. */
import type { Envelope } from '@t2em/protocol';
export type WireEnvelope = Envelope;

/** A share URL split into its relay id and the secret #fragment. */
export interface ShareUrlParts {
  id: string;
  /** Undefined for Mode A URLs — they carry no fragment. */
  fragment: string | undefined;
}

/** Parse `https://<host>/s/<id>[#<fragment>]` into its parts (§8.2). */
export function parseShareUrl(raw: string): ShareUrlParts {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new UsageError(`invalid url: ${raw}`);
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new UsageError(`unsupported url scheme: ${url.protocol}`);
  }
  const match = url.pathname.match(/^\/s\/([A-Za-z0-9_-]+)$/);
  if (!match) {
    throw new UsageError('url must point to a drop: https://<host>/s/<id>[#<key>]');
  }
  return { id: match[1], fragment: url.hash ? url.hash.slice(1) : undefined };
}

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export class RelayClient {
  private readonly fetchFn: FetchLike;

  constructor(
    private readonly baseUrl: string,
    fetchFn: FetchLike = (input, init) => fetch(input, init),
  ) {
    this.fetchFn = fetchFn;
  }

  /** `POST /api/v1/drop` (§5.2) — returns 201 payload. */
  async drop(envelope: WireEnvelope, ttl: number): Promise<CreatedDrop> {
    const res = await this.fetchFn(`${this.baseUrl}/api/v1/drop`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ envelope, ttl }),
    });
    if (res.status !== 201) throw await this.toHttpError(res);
    return (await res.json()) as CreatedDrop;
  }

  /** `GET /s/:id` with the JSON contract (§5.3) — consumes the drop. */
  async consume(id: string): Promise<WireEnvelope> {
    const res = await this.fetchFn(`${this.baseUrl}/s/${id}`, {
      headers: { accept: 'application/json' },
    });
    if (res.status !== 200) throw await this.toHttpError(res);
    // §5.3 wire shape: { envelope: {...} }
    const body = (await res.json()) as { envelope: WireEnvelope };
    return body.envelope;
  }

  /** `DELETE /api/v1/drop/:id` with the delete token (§5.4). */
  async destroy(id: string, deleteToken: string): Promise<void> {
    const res = await this.fetchFn(`${this.baseUrl}/api/v1/drop/${id}`, {
      method: 'DELETE',
      headers: { 'x-delete-token': deleteToken },
    });
    if (res.status !== 200) throw await this.toHttpError(res);
  }

  private async toHttpError(res: Response): Promise<HttpError> {
    const retryAfter = Number(res.headers.get('retry-after'));
    let code: string | undefined;
    let message = `relay returned HTTP ${res.status}`;
    try {
      const body = (await res.json()) as { error?: { code?: string; message?: string } };
      if (typeof body?.error?.code === 'string') code = body.error.code;
      if (typeof body?.error?.message === 'string') message = body.error.message;
    } catch {
      // non-JSON error body — keep the generic message
    }
    return new HttpError(
      res.status,
      code,
      message,
      Number.isFinite(retryAfter) ? retryAfter : undefined,
    );
  }
}
