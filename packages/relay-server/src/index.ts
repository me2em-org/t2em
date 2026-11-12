/**
 * Public surface of `@t2em/relay-server`.
 * (The binary entries `worker.ts` / `node.ts` are wired by deploy tooling.)
 */
export { createApp, type AppDeps } from './app.js';
export { T2EM_RELAY_VERSION } from './version.js';
export {
  InMemoryRelayStorage,
} from './storage/memory.js';
export {
  UpstashRelayStorage,
  type UpstashRelayStorageConfig,
} from './storage/upstash.js';
export {
  RATE_LIMIT_WINDOW_SECONDS,
  type DropId,
  type RelayStorage,
} from './storage/types.js';
