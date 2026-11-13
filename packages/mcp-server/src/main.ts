#!/usr/bin/env node
/**
 * `t2em-mcp` stdio entry point (ТЗ §8.4).
 *
 * Wire into Claude Code / Cursor / Windsurf:
 *
 *   { "mcpServers": { "t2em": { "command": "npx", "args": ["-y", "@t2em/mcp-server"] } } }
 *
 * Environment:
 *   T2EM_BASE_URL — relay origin, default https://t2em.com
 *
 * Zero-logging (§8.4): nothing about secrets is ever printed. stdout
 * belongs exclusively to the MCP JSON-RPC transport.
 */
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createT2emServer } from './tools.js';

const baseUrl = process.env.T2EM_BASE_URL || 'https://t2em.com';

const server = createT2emServer({ baseUrl });
await server.connect(new StdioServerTransport());
// Connected — the SDK now serves JSON-RPC over stdio; the process
// stays alive until the client closes the transport.
