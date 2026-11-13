/**
 * Integration tests: the full CLI command layer against the REAL
 * relay Hono app (createApp + InMemoryRelayStorage) via an injected
 * fetch — no sockets, no network, no live Upstash. Covers the §8.2
 * user journeys end-to-end including crypto roundtrips.
 *
 * Commands follow the main() contract: UsageError/HttpError propagate
 * OUT of run* (main maps them to exit codes), so failure paths here
 * assert on thrown errors and their describeError text.
 */
import { mkdtempSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createApp, InMemoryRelayStorage } from '@t2em/relay-server';
import { generateX25519KeyPair } from '@me2em/crypto';
import { b64uEncode, fingerprintPubKeyB64u } from '@t2em/protocol';
import { describe, expect, it } from 'vitest';
import { RelayClient, parseShareUrl, type FetchLike } from '../src/client.js';
import { HttpError } from '../src/errors.js';
import { describeError, runDelete, runKeygen, runPull, runPush, type CommandDeps, type Io } from '../src/commands.js';

/** One relay app + client shared by every rig within a test. */
function makeTransport() {
  const app = createApp({ storage: new InMemoryRelayStorage(), publicOrigin: 'https://test.local' });
  let ipSeq = 0;
  // Unique x-forwarded-for per request → the §5.1 rate-limit bucket is
  // never shared between test requests.
  const fetchFn: FetchLike = (input, init) => {
    const headers = new Headers(init?.headers);
    headers.set('x-forwarded-for', `203.0.113.${++ipSeq}`);
    return app.request(input, { ...init, headers });
  };
  return { deps: { client: new RelayClient('https://test.local', fetchFn) } as CommandDeps };
}

function makeRig(transport: CommandDeps, stdin: string) {
  const out: Uint8Array[] = [];
  const err: string[] = [];
  const io: Io = {
    stdin: () => Promise.resolve(new TextEncoder().encode(stdin)),
    stdout: (bytes) => out.push(bytes),
    stderr: (line) => err.push(line),
  };
  return { io, deps: transport.deps, err, text: () => Buffer.concat(out).toString('utf8'), bytes: () => Buffer.concat(out) };
}

async function expectHttpError(promise: Promise<number>, status: number): Promise<string> {
  try {
    await promise;
    throw new Error(`expected HttpError ${status}, but the command returned 0`);
  } catch (error) {
    expect(error).toBeInstanceOf(HttpError);
    expect((error as HttpError).status).toBe(status);
    return describeError(error);
  }
}

const B_URL = /^https:\/\/test\.local\/s\/[0-9a-f-]{36}#[A-Za-z0-9_-]{43}$/;

describe('CLI commands over the real relay app (ТЗ §8.2 journeys)', () => {
  it('Mode B: push from stdin → pull via #fragment → consumed once', async () => {
    const t = makeTransport();
    const secret = 'секрет в пайпе\nwith a second line';
    const push = makeRig(t, secret);
    expect(await runPush({ command: 'push', ttl: 120, to: undefined }, push.io, push.deps)).toBe(0);
    const url = push.text();
    expect(url).toMatch(B_URL);
    expect(push.err.join('\n')).toMatch(/delete token: \S+/);
    expect(push.err.join('\n')).toMatch(/drop [0-9a-f-]{36} expires in 120s/);

    const pull = makeRig(t, '');
    expect(await runPull({ command: 'pull', url, key: undefined }, pull.io, pull.deps)).toBe(0);
    expect(pull.bytes().toString('utf8')).toBe(secret);

    const again = makeRig(t, '');
    const message = await expectHttpError(
      runPull({ command: 'pull', url, key: undefined }, again.io, again.deps),
      404,
    );
    expect(message).toContain('not found, expired or already consumed');
  });

  it('Mode A: keygen → push --to (fingerprint in stderr) → pull --key', async () => {
    const t = makeTransport();
    const dir = mkdtempSync(join(tmpdir(), 't2em-cli-test-'));
    const keyPath = join(dir, 'agent.key');

    const gen = makeRig(t, '');
    expect(await runKeygen({ command: 'keygen', out: keyPath }, gen.io, gen.deps)).toBe(0);
    const pubB64u = gen.text();
    expect(statSync(keyPath).mode & 0o777).toBe(0o600); // §8.2 file rights
    expect(gen.err.join('\n')).toMatch(/fingerprint: [A-Za-z0-9_-]{8}/);
    expect(gen.err.join('\n')).toContain(`fingerprint: ${await fingerprintPubKeyB64u(pubB64u)}`);

    const secret = 'mode a — для адресата с ключом';
    const push = makeRig(t, secret);
    expect(await runPush({ command: 'push', ttl: 300, to: pubB64u }, push.io, push.deps)).toBe(0);
    const url = push.text();
    expect(url).not.toContain('#'); // Mode A carries no fragment
    expect(push.err.join('\n')).toContain(`fingerprint: ${await fingerprintPubKeyB64u(pubB64u)}`);

    const pull = makeRig(t, '');
    expect(await runPull({ command: 'pull', url, key: keyPath }, pull.io, pull.deps)).toBe(0);
    expect(pull.bytes().toString('utf8')).toBe(secret);
  });

  it('Mode B url opened with --key fails with a mode mismatch (exit 1)', async () => {
    const t = makeTransport();
    const dir = mkdtempSync(join(tmpdir(), 't2em-cli-test-'));
    const keyPath = join(dir, 'agent.key');
    await runKeygen({ command: 'keygen', out: keyPath }, makeRig(t, '').io, t.deps);

    const push = makeRig(t, 'x');
    await runPush({ command: 'push', ttl: 60, to: undefined }, push.io, push.deps);
    const url = push.text();

    const pull = makeRig(t, '');
    expect(await runPull({ command: 'pull', url, key: keyPath }, pull.io, pull.deps)).toBe(1);
    expect(pull.err.join('\n')).toContain("envelope is 'sym'");
  });

  it('delete: wrong token 403, right token destroys, repeat reads 404', async () => {
    const t = makeTransport();
    const push = makeRig(t, 'to be destroyed');
    await runPush({ command: 'push', ttl: 300, to: undefined }, push.io, push.deps);
    const url = push.text();
    const token = push.err.join('\n').match(/delete token: (\S+)/)?.[1] as string;
    const { id } = parseShareUrl(url);

    const wrongMessage = await expectHttpError(
      runDelete({ command: 'delete', url, token: 'bad-token' }, makeRig(t, '').io, t.deps),
      403,
    );
    expect(wrongMessage).toMatch(/HTTP 403/);

    const del = makeRig(t, '');
    expect(await runDelete({ command: 'delete', url, token }, del.io, del.deps)).toBe(0);
    expect(del.err.join('\n')).toContain(`drop ${id} destroyed`);

    const goneMessage = await expectHttpError(
      runDelete({ command: 'delete', url, token }, makeRig(t, '').io, t.deps),
      404,
    );
    expect(goneMessage).toContain('not found');
  });

  it('push with empty stdin fails with exit code 1', async () => {
    const t = makeTransport();
    const rig = makeRig(t, '');
    expect(await runPush({ command: 'push', ttl: 300, to: undefined }, rig.io, rig.deps)).toBe(1);
    expect(rig.err.join('\n')).toContain('stdin is empty');
  });

  it('pull of an unknown drop reports "not found or already consumed"', async () => {
    const t = makeTransport();
    const url = `https://test.local/s/${crypto.randomUUID()}#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`;
    const message = await expectHttpError(
      runPull({ command: 'pull', url, key: undefined }, makeRig(t, '').io, t.deps),
      404,
    );
    expect(message).toContain('not found, expired or already consumed');
  });

  it('keygen output pubkey works directly as push --to', async () => {
    const t = makeTransport();
    const pair = generateX25519KeyPair();
    const rig = makeRig(t, 'roundtrip via generated pair');
    expect(
      await runPush({ command: 'push', ttl: 60, to: b64uEncode(pair.publicKey) }, rig.io, rig.deps),
    ).toBe(0);
    expect(rig.text()).not.toContain('#');
  });
});
