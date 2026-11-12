/**
 * `@t2em/mcp-server` — tool registry of the t2em MCP server (ТЗ §8.4).
 *
 * Этап 0 skeleton: fixes the exact tool names and shapes so that Этап 5
 * (implementation on the MCP SDK) cannot drift from the ТЗ.
 */

export const MCP_SERVER_NAME = 't2em';
export const MCP_SERVER_VERSION = '0.1.0';

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
