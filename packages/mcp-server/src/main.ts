#!/usr/bin/env node
/**
 * `t2em-mcp` stdio entry point (ТЗ §8.4).
 *
 * Этап 0 skeleton. Этап 5 wires the MCP SDK server (stdio transport)
 * with the six tools from T2EM_MCP_TOOLS and the InMemorySecretVault.
 */
import { MCP_SERVER_NAME, MCP_SERVER_VERSION, T2EM_MCP_TOOLS } from './index.js';

console.error(
  `${MCP_SERVER_NAME} MCP server v${MCP_SERVER_VERSION}: stdio transport is not implemented yet (roadmap Этап 5, docs/TZ_t2em.md §14)`,
);
console.error(`planned tools: ${T2EM_MCP_TOOLS.map((t) => t.name).join(', ')}`);
process.exit(1);
