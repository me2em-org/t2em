import { describe, expect, it } from 'vitest';
import { MCP_SERVER_NAME, MCP_SERVER_VERSION, T2EM_MCP_TOOLS } from '../src/index.js';

describe('MCP tool registry (ТЗ §8.4)', () => {
  it('exposes exactly the six tools of the ТЗ', () => {
    expect(T2EM_MCP_TOOLS.map((t) => t.name)).toEqual([
      't2em_keygen',
      't2em_push',
      't2em_pull',
      't2em_http_request',
      't2em_wipe_secret',
      't2em_list_secrets',
    ]);
  });

  it('keeps server metadata stable', () => {
    expect(MCP_SERVER_NAME).toBe('t2em');
    expect(MCP_SERVER_VERSION).toBe('0.1.0');
  });

  it('documents every tool with a non-empty description', () => {
    for (const tool of T2EM_MCP_TOOLS) {
      expect(tool.description.length).toBeGreaterThan(10);
    }
  });
});
