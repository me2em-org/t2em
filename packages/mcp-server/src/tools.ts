/**
 * The six MCP tools of ТЗ §8.4, implemented on the official MCP SDK.
 *
 * Security contract:
 *  - secrets live only in the `InMemorySecretVault`; tools return
 *    `secret_handle` references, never values (LLM context stays clean);
 *  - `t2em_http_request` substitutes `{{sec_...}}` tokens AFTER the
 *    URL passed the SSRF guard, and runs behind DNS pinning +
 *    hop-by-hop redirect re-validation;
 *  - zero-logging: no secret value is ever written to stdout/stderr;
 *  - `t2em_wipe_secret` two-pass wipes the stored bytes (§4.4).
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import {
  b64uDecodeStrict,
  b64uEncode,
  decodeUtf8,
  encodeUtf8,
  fingerprintPubKeyB64u,
  packDropAsym,
  packDropSym,
  unpackDropAsym,
  unpackDropSym,
  validateEnvelope,
  MAX_TTL_SECONDS,
  MIN_TTL_SECONDS,
  X25519_KEY_BYTES,
} from '@t2em/protocol';
import { generateX25519KeyPair, secureWipeMultiple } from '@me2em/crypto';
import { InMemorySecretVault, isSecretHandle, secureWipe } from './vault.js';
import { RelayClient, RelayHttpError, type FetchLike } from './relay.js';
import { guardedRequest, type GuardedOptions } from './http.js';
import { MCP_SERVER_NAME, MCP_SERVER_VERSION } from './index.js';

export interface T2emServerOptions {
  /** Relay origin (default `https://t2em.com`; env `T2EM_BASE_URL`). */
  baseUrl?: string;
  /** Relay transport override — tests bind the Hono app here. */
  fetchFn?: FetchLike;
  /** `t2em_http_request` transport override — tests bind a fake here. */
  guarded?: GuardedOptions;
  /** Vault override (tests pre-seed handles). */
  vault?: InMemorySecretVault;
}

const DEFAULT_BASE_URL = 'https://t2em.com';

/** JSON content helper — every tool answers with one JSON text block. */
function jsonContent(value: unknown): { content: [{ type: 'text'; text: string }]; isError?: boolean } {
  return { content: [{ type: 'text', text: JSON.stringify(value, null, 2) }] };
}

function errorContent(error: unknown): { content: [{ type: 'text'; text: string }]; isError: true } {
  if (error instanceof RelayHttpError) {
    // Status + code never contain secret material; the relay message stays generic.
    const code = error.code ? ` (${error.code})` : '';
    return {
      content: [{ type: 'text', text: `relay returned HTTP ${error.status}${code}: ${error.message}` }],
      isError: true,
    };
  }
  const message = error instanceof Error ? error.message : String(error);
  // Zero-logging: the message may carry a status/code, never a secret.
  return { content: [{ type: 'text', text: message }], isError: true };
}

/** `{{sec_uuid}}` occurrences in a template string. */
const HANDLE_TOKEN_RE = /\{\{\s*(sec_[0-9a-f-]{36})\s*\}\}/g;

export function createT2emServer(options: T2emServerOptions = {}): McpServer {
  const baseUrl = options.baseUrl ?? DEFAULT_BASE_URL;
  const vault = options.vault ?? new InMemorySecretVault();
  const relay = new RelayClient(baseUrl, options.fetchFn ?? ((input, init) => fetch(input, init)));

  const server = new McpServer(
    { name: MCP_SERVER_NAME, version: MCP_SERVER_VERSION },
    { capabilities: { tools: {} } },
  );

  // ------------------------------------------------------------------
  // t2em_keygen — privkey stays in the vault (§8.4)
  // ------------------------------------------------------------------
  server.registerTool(
    't2em_keygen',
    {
      description:
        'Generate an X25519 keypair for Mode A drops. The private key never leaves the in-process vault; share public_key out-of-band after verifying its 8-char fingerprint.',
      inputSchema: {},
    },
    async () => {
      try {
        const pair = generateX25519KeyPair();
        try {
          const publicKey = b64uEncode(pair.publicKey);
          const handle = vault.put(pair.privateKey, 'privkey');
          const keyId = await fingerprintPubKeyB64u(publicKey);
          return jsonContent({ public_key: publicKey, key_id: keyId, handle });
        } finally {
          secureWipeMultiple(pair.privateKey, pair.publicKey);
        }
      } catch (error) {
        return errorContent(error);
      }
    },
  );

  // ------------------------------------------------------------------
  // t2em_push — Mode B default, Mode A with recipient_pubkey
  // ------------------------------------------------------------------
  server.registerTool(
    't2em_push',
    {
      description:
        'Create a zero-knowledge drop on t2em. Mode B (symmetric) by default — the URL carries the key in its #fragment, so only URL holders can read. Pass recipient_pubkey (base64url X25519) for Mode A: the URL alone reveals nothing. TTL is 60..900 seconds.',
      inputSchema: {
        secret: z.string().min(1).describe('The payload to protect (never logged, never stored server-side in plaintext).'),
        ttl: z.number().int().min(MIN_TTL_SECONDS).max(MAX_TTL_SECONDS).optional()
          .describe(`Drop lifetime in seconds (${MIN_TTL_SECONDS}..${MAX_TTL_SECONDS}), default 300.`),
        recipient_pubkey: z.string().optional()
          .describe('Base64url X25519 public key of the recipient — switches to Mode A (no #fragment in the URL).'),
      },
    },
    async ({ secret, ttl = 300, recipient_pubkey }) => {
      try {
        const plaintext = encodeUtf8(secret);
        const dropPromise =
          recipient_pubkey === undefined
            ? packDropSym(plaintext).then(async ({ envelope, symKey }) => ({
                drop: await relay.drop(envelope, ttl),
                symKey,
              }))
            : packDropAsym(plaintext, b64uDecodeStrict(recipient_pubkey)).then(
                async ({ envelope }) => ({ drop: await relay.drop(envelope, ttl), symKey: undefined }),
              );
        const { drop, symKey } = await dropPromise;
        // Mode B: the key travels ONLY in the URL #fragment (RFC 3986 —
        // fragments are never sent to the server), appended client-side.
        const url = symKey === undefined ? drop.url : `${drop.url}#${symKey}`;
        return jsonContent({
          url,
          delete_token: drop.delete_token,
          expires_in: drop.expires_in,
          mode: symKey === undefined ? 'x25519' : 'sym',
        });
      } catch (error) {
        return errorContent(error);
      }
    },
  );

  // ------------------------------------------------------------------
  // t2em_pull — returns secret_handle, never the secret (§8.4)
  // ------------------------------------------------------------------
  server.registerTool(
    't2em_pull',
    {
      description:
        'Fetch and decrypt a drop, then store the plaintext in the in-process vault. Returns a secret_handle (sec_…) to use with t2em_http_request / t2em_wipe_secret — the secret value itself is NEVER returned to the LLM context. Mode B urls need their #fragment; Mode A urls need a keypair from t2em_keygen.',
      inputSchema: {
        url: z.string().describe('Drop URL, e.g. https://t2em.com/s/<id>#<key> (Mode B) or https://t2em.com/s/<id> (Mode A).'),
      },
    },
    async ({ url }) => {
      try {
        const parts = parseShareUrl(url);
        const envelope = validateEnvelope(await relay.consume(parts.id));

        let plaintext: Uint8Array;
        if (envelope.mode === 'sym') {
          if (!parts.fragment) throw new Error('Mode B url carries no #fragment — key is missing');
          plaintext = await unpackDropSym(envelope, parts.fragment);
        } else {
          const key = vault.latestPrivKey();
          if (!key) throw new Error('no keypair in vault — call t2em_keygen first');
          plaintext = await unpackDropAsym(envelope, key.bytes);
        }
        try {
          const handle = vault.put(plaintext, 'secret');
          return jsonContent({ secret_handle: handle, byte_length: plaintext.length });
        } finally {
          secureWipe(plaintext);
        }
      } catch (error) {
        return errorContent(error);
      }
    },
  );

  // ------------------------------------------------------------------
  // t2em_http_request — {{secret_handle}} substitution + SSRF guard
  // ------------------------------------------------------------------
  server.registerTool(
    't2em_http_request',
    {
      description:
        'Perform an HTTPS request with secrets substituted from the vault: write {{sec_…}} handles anywhere in headers or body and they are replaced by the actual values inside this process. SSRF-guarded: HTTPS only, private/metadata IP ranges denied, DNS pinned, redirects re-validated, response capped at 1 MiB.',
      inputSchema: {
        url: z.string().describe('Absolute https:// URL to request.'),
        method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']).optional()
          .describe('HTTP method, default GET.'),
        headers: z.record(z.string(), z.string()).optional()
          .describe('Request headers; values may contain {{sec_…}} handles.'),
        body: z.string().optional().describe('Request body; may contain {{sec_…}} handles.'),
      },
    },
    async ({ url, method, headers, body }) => {
      try {
        const substitutor = new HandleSubstitutor(vault);
        const safeHeaders = substituteRecord(headers ?? {}, substitutor);
        const safeBody = body === undefined ? undefined : substitutor.apply(body);

        const response = await guardedRequest(
          url,
          { method, headers: safeHeaders, body: safeBody },
          options.guarded,
        );
        const contentType = response.headers['content-type'] ?? '';
        const text = contentType.includes('json') || isProbablyText(response.body)
          ? decodeUtf8(response.body)
          : b64uEncode(response.body);
        return jsonContent({
          status: response.status,
          headers: response.headers,
          body: text,
          body_encoding: contentType.includes('json') || isProbablyText(response.body) ? 'utf8' : 'base64url',
          hops: response.hops,
          final_url: response.finalUrl,
        });
      } catch (error) {
        return errorContent(error);
      }
    },
  );

  // ------------------------------------------------------------------
  // t2em_wipe_secret — two-pass wipe (§4.4)
  // ------------------------------------------------------------------
  server.registerTool(
    't2em_wipe_secret',
    {
      description: 'Securely wipe a stored secret (two-pass overwrite) by its secret_handle.',
      inputSchema: {
        secret_handle: z.string().regex(/^sec_[0-9a-f-]{36}$/i, 'handle must look like sec_<uuid>'),
      },
    },
    async ({ secret_handle }) => {
      try {
        if (!vault.wipe(secret_handle)) {
          throw new Error(`unknown secret_handle: ${secret_handle}`);
        }
        return jsonContent({ ok: true });
      } catch (error) {
        return errorContent(error);
      }
    },
  );

  // ------------------------------------------------------------------
  // t2em_list_secrets — handles only, never values (§8.4)
  // ------------------------------------------------------------------
  server.registerTool(
    't2em_list_secrets',
    {
      description: 'List stored secret handles (metadata only — values never leave the vault).',
      inputSchema: {},
    },
    async () => {
      return jsonContent({ handles: vault.list() });
    },
  );

  return server;
}

/**
 * Resolves `{{sec_…}}` tokens lazily and wipes the concatenated
 * intermediates after use (§4.4).
 */
class HandleSubstitutor {
  constructor(private readonly vault: InMemorySecretVault) {}

  apply(template: string): string {
    return template.replace(HANDLE_TOKEN_RE, (_match, handle: string) => {
      const bytes = this.vault.get(handle);
      if (!bytes) throw new Error(`unknown secret_handle: ${handle}`);
      return decodeUtf8(bytes);
    });
  }
}

function substituteRecord(
  record: Record<string, string>,
  substitutor: HandleSubstitutor,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(record)) {
    out[key] = substitutor.apply(value);
  }
  return out;
}

function isProbablyText(bytes: Uint8Array): boolean {
  const probe = bytes.subarray(0, 512);
  let control = 0;
  for (const byte of probe) {
    if (byte === 0) return false;
    if (byte < 9 || (byte > 13 && byte < 32)) control += 1;
  }
  return control / Math.max(1, probe.length) < 0.1;
}

/** Parse `https://<host>/s/<id>[#<fragment>]` (mirrors the CLI rule). */
function parseShareUrl(raw: string): { id: string; fragment: string | undefined } {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`invalid url: ${raw}`);
  }
  const match = url.pathname.match(/^\/s\/([A-Za-z0-9_-]+)$/);
  if (!match) throw new Error('url must point to a drop: https://<host>/s/<id>[#<key>]');
  return { id: match[1]!, fragment: url.hash ? url.hash.slice(1) : undefined };
}

/** Re-export for tests that assert handle shapes. */
export { isSecretHandle, X25519_KEY_BYTES, RelayHttpError };
