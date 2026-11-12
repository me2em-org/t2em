# examples

Runnable integration examples for t2em (populated from Этап 3 onward,
after the CLI and SDK exist):

- shell pipelines with `t2em-cli` (stdin/stdout, exit codes);
- Node.js script using `@t2em/protocol` directly;
- Python (LangGraph/CrewAI) using the `t2em` PyPI package;
- MCP configuration snippets for Claude Code / Cursor / Windsurf.

Per ТЗ §8.5 all examples use the high-frequency vocabulary (Token,
Vault, Payload, Drop, Push/Pull) so that LLMs can predictably generate
them.
