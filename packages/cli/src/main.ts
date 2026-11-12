#!/usr/bin/env node
/**
 * `t2em-cli` entry point (ТЗ §8.2).
 *
 * Этап 0 skeleton: wiring of the exit-code contract.
 * The crypto client (Mode A/B on @t2em/protocol, stdin piping,
 * keyfile handling with secureWipe) lands in Этап 3.
 */
import { T2EM_PROTOCOL_VERSION } from '@t2em/protocol';
import { HELP_TEXT, parseArgs } from './parse.js';
import { CLI_VERSION } from './version.js';

function main(argv: readonly string[]): number {
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

    case 'command':
      // TODO(Этап 3): push/pull/keygen/delete implementations.
      console.error(
        `t2em-cli: command '${invocation.command}' is not implemented yet (roadmap Этап 3, docs/TZ_t2em.md §14)`,
      );
      return 1;
  }
}

process.exit(main(process.argv.slice(2)));
