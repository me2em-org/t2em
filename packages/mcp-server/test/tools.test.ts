/**
 * Full tool journeys over the official MCP SDK — in-process via
 * `InMemoryTransport`, against the REAL relay Hono app (no sockets)
 * and a fake guarded `connect` for `t2em_http_request`.
 *
 * Covers the §8.4 contract end-to-end: keygen → push → pull →
 * http_request substitution → wipe, plus the SSRF/error paths.
 */
import { describe, expect, it } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { createApp, InMemoryRelayStorage } from '@t2em/relay-server';
import { generateX25519KeyPair } from '@me2em/crypto';
import { packDropAsym } from '@t2em/protocol';
import { createT2emServer } from '../src/tools.js';
import { InMemorySecretVault } from '../src/vault.js';
import { RelayClient, type FetchLike } from '../src/relay.js';
import type { Connect } from '../src/http.js';

const BASE = 'https://test.local';
const B_URL = /^https:\/\/test\.local\/s\/[0-9a-f-]{36}#[A-Za-z0-9_-]{43}$/;
const HANDLE = /^sec_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

interface Rig {
  client: Client;
  vault: InMemorySecretVault;
  relay: RelayClient;
  connectCalls: Array<{ url: string; headers: Record<string, string>; body?: string }>;
}

async function makeRig(connectImpl?: Connect): Promise<Rig> {
  const app = createApp({ storage: new InMemoryRelayStorage(), publicOrigin: BASE });
  let ipSeq = 0;
  // Unique x-forwarded-for per request → §5.1 rate-limit buckets stay separate.
  const fetchFn: FetchLike = (input, init) => {
    const headers = new Headers(init?.headers);
    headers.set('x-forwarded-for', `203.0.113.${++ipSeq}`);
    return app.request(input, { ...init, headers });
  };

  const connectCalls: Rig['connectCalls'] = [];
  const connect: Connect =
    connectImpl ??
    (async (args) => {
      connectCalls.push({
        url: args.url.toString(),
        headers: args.headers,
        body: args.body === undefined ? undefined : new TextDecoder().decode(args.body),
      });
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        body: new TextEncoder().encode('{"ok":true}'),
      };
    });

  const vault = new InMemorySecretVault();
  const server: McpServer = createT2emServer({
    baseUrl: BASE,
    fetchFn,
    vault,
    guarded: {
      connect,
      // Deterministic resolver: hostname literals stay literal, names
      // resolve to a public address (SSRF logic is unit-tested in ssrf.test.ts).
      resolve: async () => ['93.184.216.34'],
    },
  });
  const client = new Client({ name: 'vitest', version: '0.0.0' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return { client, vault, relay: new RelayClient(BASE, fetchFn), connectCalls };
}

interface ToolResult {
  isError?: boolean;
  text: string;
  // Test-side untyped view of the tool's JSON payload.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  json: any;
}

async function call(rig: Rig, name: string, args: Record<string, unknown> = {}): Promise<ToolResult> {
  const result = (await rig.client.callTool({ name, arguments: args })) as {
    isError?: boolean;
    content: Array<{ type: string; text?: string }>;
  };
  const text = result.content?.map((c) => c.text ?? '').join('') ?? '';
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let json: any = null;
  try {
    json = JSON.parse(text);
  } catch {
    // error paths return plain text
  }
  return { isError: result.isError === true, text, json };
}

describe('t2em MCP server over the real relay app (ТЗ §8.4)', () => {
  it('exposes exactly the six ТЗ tools', async () => {
    const rig = await makeRig();
    const tools = await rig.client.listTools();
    expect(tools.tools.map((t) => t.name).sort()).toEqual(
      [
        't2em_keygen',
        't2em_push',
        't2em_pull',
        't2em_http_request',
        't2em_wipe_secret',
        't2em_list_secrets',
      ].sort(),
    );
  });

  it('Mode B journey: push → pull → substitute → list → wipe', async () => {
    const rig = await makeRig();

    // push (Mode B default)
    const pushed = await call(rig, 't2em_push', { secret: 'sk-live-journey', ttl: 300 });
    expect(pushed.isError).toBeFalsy();
    expect(pushed.json.url).toMatch(B_URL);
    expect(pushed.json.delete_token).toBeTruthy();

    // pull — returns a handle, never the value
    const pulled = await call(rig, 't2em_pull', { url: pushed.json.url });
    expect(pulled.isError).toBeFalsy();
    expect(pulled.json.secret_handle).toMatch(HANDLE);
    expect(pulled.text).not.toContain('sk-live-journey');
    expect(pulled.json.byte_length).toBe(15); // 'sk-live-journey'.length

    // http_request substitutes the handle with the real value
    const req = await call(rig, 't2em_http_request', {
      url: 'https://api.example.test/v1/me',
      method: 'POST',
      headers: { authorization: `Bearer {{${pulled.json.secret_handle}}}` },
      body: `{"api_key":"{{${pulled.json.secret_handle}}}"}`,
    });
    expect(req.isError).toBeFalsy();
    expect(req.json.status).toBe(200);
    expect(req.json.body).toBe('{"ok":true}');
    const sent = rig.connectCalls[0]!;
    expect(sent.headers['authorization']).toBe('Bearer sk-live-journey');
    expect(sent.body).toBe('{"api_key":"sk-live-journey"}');

    // list shows the handle; wipe removes it
    const listed = await call(rig, 't2em_list_secrets');
    expect(listed.json.handles.map((h: { handle: string }) => h.handle)).toContain(
      pulled.json.secret_handle,
    );
    const wiped = await call(rig, 't2em_wipe_secret', { secret_handle: pulled.json.secret_handle });
    expect(wiped.json).toEqual({ ok: true });
    expect(rig.vault.get(pulled.json.secret_handle)).toBeUndefined();
  });

  it('Mode A journey: keygen → push(sealed, no fragment) → pull via vault privkey', async () => {
    const rig = await makeRig();

    const key = await call(rig, 't2em_keygen');
    expect(key.isError).toBeFalsy();
    expect(key.json.public_key).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(key.json.key_id).toMatch(/^[A-Za-z0-9_-]{8}$/); // fingerprint §4.2.1
    expect(key.text).not.toMatch(/priv/); // privkey never surfaces in any tool output

    const pushed = await call(rig, 't2em_push', {
      secret: 'asym-journey-secret',
      recipient_pubkey: key.json.public_key,
      ttl: 300,
    });
    expect(pushed.isError).toBeFalsy();
    expect(pushed.json.url).not.toContain('#'); // Mode A: no fragment on the URL

    const pulled = await call(rig, 't2em_pull', { url: pushed.json.url });
    expect(pulled.isError).toBeFalsy();
    expect(pulled.json.secret_handle).toMatch(HANDLE);
    // the vault really holds the secret now (observable only from the process side)
    expect(new TextDecoder().decode(rig.vault.get(pulled.json.secret_handle)!)).toBe(
      'asym-journey-secret',
    );
  });

  it('t2em_pull reports a missing keypair before touching the fragment', async () => {
    const rig = await makeRig();
    const pair = generateX25519KeyPair();
    const { envelope } = await packDropAsym(new TextEncoder().encode('nokey'), pair.publicKey);
    const drop = await rig.relay.drop(envelope, 300);
    const res = await call(rig, 't2em_pull', { url: `${BASE}/s/${drop.id}` });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/keypair/);
  });

  it('rejects ttl out of the §4 bounds before any network call', async () => {
    const rig = await makeRig();
    const res = await call(rig, 't2em_push', { secret: 'x', ttl: 59 });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/ttl/i);
  });

  it('t2em_http_request is SSRF-guarded', async () => {
    const rig = await makeRig();

    const http = await call(rig, 't2em_http_request', { url: 'http://api.example.test/' });
    expect(http.isError).toBe(true);
    expect(http.text).toMatch(/SSRF blocked: only https/);

    const private_ = await call(rig, 't2em_http_request', { url: 'https://10.0.0.1/' });
    expect(private_.isError).toBe(true);
    expect(private_.text).toMatch(/SSRF blocked/);

    const metadata = await call(rig, 't2em_http_request', {
      url: 'https://169.254.169.254/latest/meta-data/',
    });
    expect(metadata.isError).toBe(true);
    expect(metadata.text).toMatch(/SSRF blocked/);

    const creds = await call(rig, 't2em_http_request', { url: 'https://user:pw@api.example.test/' });
    expect(creds.isError).toBe(true);
    expect(creds.text).toMatch(/credentials/);
  });

  it('t2em_http_request re-validates redirect hops', async () => {
    // First hop returns 302 → https://10.0.0.1/ (private). The second hop
    // must be rejected by validateTarget BEFORE any connection is made.
    const rig = await makeRig(async () => ({
      status: 302,
      headers: { location: 'https://10.0.0.1/' },
      body: new Uint8Array(0),
    }));
    const res = await call(rig, 't2em_http_request', { url: 'https://redirector.example/' });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/SSRF blocked/);
  });

  it('unknown secret_handle in substitution fails closed', async () => {
    const rig = await makeRig();
    const res = await call(rig, 't2em_http_request', {
      url: 'https://api.example.test/',
      headers: { authorization: 'Bearer {{sec_00000000-0000-0000-0000-000000000000}}' },
    });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/unknown secret_handle/);
  });

  it('wipe of an unknown handle errors instead of lying', async () => {
    const rig = await makeRig();
    const res = await call(rig, 't2em_wipe_secret', {
      secret_handle: 'sec_11111111-2222-3333-4444-555555555555',
    });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/unknown secret_handle/);
  });

  it('pull of an expired/unknown drop maps relay 404 to an error', async () => {
    const rig = await makeRig();
    const res = await call(rig, 't2em_pull', {
      url: `${BASE}/s/11111111-2222-3333-4444-555555555555#frag`,
    });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/404/);
    expect(res.text).not.toContain('#frag'); // the key never echoed back
  });

  it('delete via delete_token works after push', async () => {
    const rig = await makeRig();
    const pushed = await call(rig, 't2em_push', { secret: 'short-lived', ttl: 300 });
    const { id } = new URL(pushed.json.url).pathname.match(/^\/s\/(?<id>[^#]+)/)!.groups!;
    await rig.relay.destroy(id, pushed.json.delete_token);
    const pulled = await call(rig, 't2em_pull', { url: pushed.json.url });
    expect(pulled.isError).toBe(true);
    expect(pulled.text).toMatch(/404/);
  });
});
