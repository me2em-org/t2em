/**
 * Minimal relay client for the MCP server (ТЗ §5).
 *
 * Same JSON contract as the CLI's client, deliberately independent of
 * `@t2em/cli` — the ТЗ dependency rule keeps `@t2em/*` packages
 * independent of each other. Transport is injectable so tests run the
 * tools against the real Hono relay app without sockets.
 */
import type { Envelope } from '@t2em/protocol';

/** Same shape as the CLI `FetchLike` — Hono `app.request` matches it. */
export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface CreatedDrop {
  id: string;
  url: string;
  expires_in: number;
  delete_token: string;
}

export class RelayHttpError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string | undefined,
    message: string,
    public readonly retryAfter: number | undefined,
  ) {
    super(message);
    this.name = 'RelayHttpError';
  }
}

export class RelayClient {
  readonly #baseUrl: string;
  readonly #fetchFn: FetchLike;

  constructor(baseUrl: string, fetchFn: FetchLike) {
    this.#baseUrl = baseUrl.replace(/\/+$/, '');
    this.#fetchFn = fetchFn;
  }

  /** `POST /api/v1/drop` (§5.2) — returns the 201 payload. */
  async drop(envelope: Envelope, ttl: number): Promise<CreatedDrop> {
    const res = await this.#fetchFn(`${this.#baseUrl}/api/v1/drop`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ envelope, ttl }),
    });
    if (res.status !== 201) throw await this.#toHttpError(res);
    return (await res.json()) as CreatedDrop;
  }

  /** `GET /s/:id` with the JSON contract (§5.3) — consumes the drop. */
  async consume(id: string): Promise<Envelope> {
    const res = await this.#fetchFn(`${this.#baseUrl}/s/${id}`, {
      headers: { accept: 'application/json' },
    });
    if (res.status !== 200) throw await this.#toHttpError(res);
    const body = (await res.json()) as { envelope: Envelope };
    return body.envelope;
  }

  /** `DELETE /api/v1/drop/:id` with the delete token (§5.4). */
  async destroy(id: string, deleteToken: string): Promise<void> {
    const res = await this.#fetchFn(`${this.#baseUrl}/api/v1/drop/${id}`, {
      method: 'DELETE',
      headers: { 'x-delete-token': deleteToken },
    });
    if (res.status !== 200) throw await this.#toHttpError(res);
  }

  async #toHttpError(res: Response): Promise<RelayHttpError> {
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
    return new RelayHttpError(
      res.status,
      code,
      message,
      Number.isFinite(retryAfter) ? retryAfter : undefined,
    );
  }
}
