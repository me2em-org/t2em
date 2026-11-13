#!/usr/bin/env node
/**
 * `t2em-cli` entry point (ТЗ §8.2).
 *
 * Wires the exit-code contract: 0 success · 1 error · 2 invalid args.
 * Base url comes from T2EM_BASE_URL (default https://t2em.com).
 */
import { T2EM_PROTOCOL_VERSION } from '@t2em/protocol';
import { RelayClient } from './client.js';
import { describeError, runDelete, runKeygen, runPull, runPush, type Io } from './commands.js';
import { UsageError } from './errors.js';
import { CLI_VERSION } from './version.js';
import { HELP_TEXT, parseArgs, parseOptions } from './parse.js';

function realIo(): Io {
  return {
    stdin: () => readStdin(),
    stdout: (bytes) => process.stdout.write(bytes),
    stderr: (line) => process.stderr.write(`${line}\n`),
  };
}

async function readStdin(): Promise<Uint8Array> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return new Uint8Array(Buffer.concat(chunks));
}

async function main(argv: readonly string[]): Promise<number> {
  const invocation = parseArgs(argv);

  switch (invocation.kind) {
    case 'help':
      console.log(HELP_TEXT);
      return 0;

    case 'version':
      console.log(`t2em-cli ${CLI_VERSION} (protocol v${T2EM_PROTOCOL_VERSION})`);
      return 0;

    case 'invalid':
      console.error(`t2em-cli: ${invocation.reason}`);
      console.error("run 't2em-cli --help' for usage");
      return 2;

    case 'command': {
      const parsed = parseOptions(invocation);
      if (parsed.kind === 'invalid') {
        console.error(`t2em-cli: ${parsed.reason}`);
        console.error("run 't2em-cli --help' for usage");
        return 2;
      }
      const io = realIo();
      const baseUrl = process.env.T2EM_BASE_URL || 'https://t2em.com';
      const deps = { client: new RelayClient(baseUrl) };
      try {
        switch (parsed.options.command) {
          case 'push':
            return await runPush(parsed.options, io, deps);
          case 'pull':
            return await runPull(parsed.options, io, deps);
          case 'keygen':
            return await runKeygen(parsed.options, io, deps);
          case 'delete':
            return await runDelete(parsed.options, io, deps);
        }
      } catch (error) {
        if (error instanceof UsageError) {
          console.error(`t2em-cli: ${error.message}`);
          return 2;
        }
        console.error(`t2em-cli: ${describeError(error)}`);
        return 1;
      }
    }
  }
}

process.exit(await main(process.argv.slice(2)));
