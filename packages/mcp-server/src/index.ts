/**
 * `@t2em/mcp-server` — public API (ТЗ §8.4).
 *
 * Этап 0 skeleton fixed the tool registry; Этап 5 implements the six
 * tools on the official MCP SDK (`createT2emServer`). Any new tool
 * goes through a ТЗ revision — do not extend silently.
 */

export const MCP_SERVER_NAME = 't2em';
export const MCP_SERVER_VERSION = '0.5.0';

/** Descriptor of one MCP tool offered by the server. */
export interface McpToolDescriptor {
  /** Tool name as exposed over MCP (`t2em_*`). */
  name: string;
  /** One-line description surfaced to the MCP client. */
  description: string;
}

/**
 * The six tools of ТЗ §8.4, in the order fixed there.
 * Any tool added later goes through a ТЗ revision — do not extend here silently.
 */
export const T2EM_MCP_TOOLS: readonly McpToolDescriptor[] = [
  { name: 't2em_keygen', description: 'Generate an X25519 keypair; privkey stays in the in-process vault' },
  { name: 't2em_push', description: 'Create a drop (Mode A/B); returns { url, delete_token? }' },
  { name: 't2em_pull', description: 'Fetch a drop; returns a secret_handle, never the secret itself' },
  { name: 't2em_http_request', description: 'HTTPS request with {{secret_handle}} substitution and SSRF-guard' },
  { name: 't2em_wipe_secret', description: 'secureWipe a stored secret by handle' },
  { name: 't2em_list_secrets', description: 'List secret handles (never values)' },
];

export { createT2emServer, type T2emServerOptions } from './tools.js';
export { InMemorySecretVault, secureWipe, isSecretHandle, type VaultEntryMeta } from './vault.js';
export { RelayClient, RelayHttpError, type FetchLike } from './relay.js';
export { guardedRequest, nodeHttpsConnect, MAX_REDIRECTS, DEFAULT_MAX_BODY_BYTES, type Connect, type GuardedResponse } from './http.js';
export { SsrfError, classifyIp, validateTarget, defaultResolve, type Resolver } from './ssrf.js';
