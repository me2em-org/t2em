/** Programmatic surface of `@t2em/cli` (main.ts is the executable entry). */
export { HELP_TEXT, parseArgs, parseOptions, DEFAULT_TTL_SECONDS, type CommandName, type CommandOptions, type ParsedInvocation, type ParsedOptions } from './parse.js';
export { CLI_VERSION } from './version.js';
export { RelayClient, parseShareUrl, type CreatedDrop, type FetchLike, type WireEnvelope } from './client.js';
export { HttpError, UsageError } from './errors.js';
export { KEYFILE_KIND, keygenToFile, loadKeyFile, type KeyFileJson, type LoadedKey } from './keys.js';
export { describeError, runDelete, runKeygen, runPull, runPush, type CommandDeps, type Io } from './commands.js';
