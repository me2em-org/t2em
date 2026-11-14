# t2em — Zero-Knowledge Token Transfer

[![CI & Security](https://github.com/me2em-org/t2em/actions/workflows/ci-security.yml/badge.svg)](https://github.com/me2em-org/t2em/actions/workflows/ci-security.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)

`t2em.com` — эфемерная zero-knowledge доставка токенов (Blind Relay):
сервер хранит только AES-GCM-конверт и никогда не видит plaintext.
Часть экосистемы [Me2eM](https://github.com/me2em-org) (Identity →
Handle → SubHandle, Ed25519-производные децентрализованные личности).

- **Нормативные документы:** [`docs/TZ_t2em.md`](./docs/TZ_t2em.md)
  (v2.0 Final) и [`docs/TZ_t2em_v2.1.md`](./docs/TZ_t2em_v2.1.md)
  (v2.1 — уточнения по итогам security-review), индекс —
  [`docs/README.md`](./docs/README.md).
- **Крипто-ядро:** примитивы `@me2em/crypto` (v1.1.0-rc.2); прямое
  использование `@noble/*` в прикладном коде запрещено (ТЗ §4.1).

## Клиентские контракты (ТЗ v2.1)

- **Fingerprint** — `base64url(sha256(pubkey))[0..16]`, **16 символов
  = 96 бит** (§4.2.1): CLI/MCP выводят его в stderr/диагностику,
  стороны сверяют вне канала перед Mode A.
- **Keyfile** (`t2em-cli keygen --out`) — формат §8.2 «уточнено»:
  `version/type/privateKey/publicKey/createdAt/fingerprint(16)`;
  fingerprint самоверифицируется при загрузке (сплайсинг → отказ),
  legacy-формат `v`/`kind` читается для совместимости. Валидация —
  одна на всех клиентов: `parseKeyFileJson` в `@t2em/protocol`.
- **Фасад §3.6** — интеграторы шифруют через `packDrop`/`unpackDrop`
  (TS: `@t2em/protocol`, Python: `t2em.pack_drop`/`t2em.unpack_drop`);
  конверт, открытый «чужим» режимом, отклоняется (`MALFORMED`, §4.5).
- **Ошибки** — единая поверхность `КОД: сообщение` по таксономии §4.5
  (`UNSUPPORTED_VERSION` / `MALFORMED` / `INVALID_LENGTH` /
  `INVALID_IV` / `DECRYPTION_FAILED`): CLI stderr и MCP `isError`
  форматируются одним модулем (`formatErrorLine`).
- **Тест-векторы** — `vectors/t2em-drop.v1.json`: 25 векторов + 2
  fingerprint-пина (positive с Ed25519-конверсией и подписью
  отправителя, negative, cross-mode, 64 KB), бит-в-бит TS↔Python.

## Как это работает

1. Клиент шифрует секрет **локально** (Mode A — X25519 на pubkey
   получателя; Mode B — симметрично, ключ живёт только в `#fragment`
   URL и по RFC 3986 не покидает браузер).
2. Relay сохраняет непрозрачный конверт в Redis с TTL 60..900 с
   (Upstash REST / RAM-only self-hosted Redis) и забывает его.
3. Получатель забирает конверт (`GETDEL` — ровно одно чтение при
   `burn_after_reading`) и расшифровывает локально.

Сервер не хранит: plaintext, ключи, метаданные, IP в plaintext,
User-Agent, тела запросов (zero-logging). Подробно — ТЗ §6.

## Структура монорепозитория (ТЗ §3.3)

```
t2em/
├── packages/
│   ├── protocol/       @t2em/protocol      — криптографическое ядро (Mode A/B)
│   ├── relay-server/   @t2em/relay-server  — Blind Relay (Workers + Node)
│   ├── cli/            @t2em/cli           — t2em-cli (push/pull/keygen/delete)
│   ├── mcp-server/     @t2em/mcp-server    — MCP-сервер (6 tools, SSRF-guard)
│   └── web-ui/         @t2em/web-ui        — Web UI (vanilla JS, без фреймворков)
├── python-sdk/         t2em                — Python SDK (PyPI, Этап 4)
├── docs/               ТЗ и документация
├── infra/              Wrangler / Docker конфиги
└── examples/           Примеры интеграции
```

**Правило зависимостей (ТЗ §3.5):** строго вверх
(`protocol → @me2em/crypto → @me2em/core`); внутри монорепо — только
`workspace:^` (DR-4). npm-зависимости между `@t2em/*` и `@we2em/*`
запрещены — интеграция с we2em.com только runtime (HTTP/OIDC).

## Разработка

Требования: Node ≥ 22.6, pnpm ≥ 10 (включён `packageManager`).

```bash
pnpm install
pnpm build       # топологическая сборка: protocol → остальные
pnpm test        # vitest во всех пакетах
pnpm typecheck
pnpm lint
```

Локальный запуск relay:

```bash
node packages/relay-server/dist/node.js   # http://localhost:8787/healthz
```

## Roadmap

| Этап | Содержание | Статус |
|---|---|---|
| 0 | Скелет монорепо, CI (gitleaks + build/test + CodeQL), freeze-константы протокола | **готово** |
| 1 | MVP: Mode B, Blind Relay API v1, Upstash, деплой Workers | **готово, live: t2em.com** |
| 2 | Mode A (X25519 + fingerprint), тест-векторы `vectors/t2em-drop.v1.json` | **готово** |
| 3 | `@t2em/cli` | **готово** |
| 4 | Python SDK (PyCA `cryptography`), bit-compat с векторами | **готово** |
| 5 | `@t2em/mcp-server` (6 tools, SSRF-guard, InMemorySecretVault) | **готово** |
| 6 | Приёмка по ТЗ §17, security review, прод | — |
| 7 | Доработка по ТЗ v2.1: P0 abuse-limits (§5.1/§5.2), P1 криптоконтракт (fingerprint 16, фасад §3.6, векторы, keyfile §8.2), P2 error surface + keyfile в MCP + доки | **готово** |

## License

[Apache-2.0](./LICENSE)
