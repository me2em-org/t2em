# docs/

Проектная документация продуктов экосистемы Me2eM.

| Документ | Версия | Статус | Описание |
|---|---|---|---|
| [`TZ_t2em.md`](./TZ_t2em.md) | 2.0 (Final) | Approved for implementation | ТЗ сервиса t2em.com — эфемерная zero-knowledge доставка секретов (Blind Relay, Mode A/B, CLI/SDK/MCP, Cloudflare Workers + Upstash) |
| [`TZ_we2em.md`](./TZ_we2em.md) | 2.0 (Final) | Approved for implementation | ТЗ сервиса we2em.com — Identity Provider, реестр публичных ключей, attestation registry, OIDC SSO |

## Как читать

- Оба документа самодостаточны; раздел «0. Сводка изменений относительно v1.0» в каждом перечисляет отличия от исходных черновиков ТЗ.
- Ключевые архитектурные решения, отличающие финальные версии от черновиков:
  - **we2em:** двухуровневая модель сессий (Tier-1 opaque / Tier-2 Me2eM, создаются только клиентом), домен-сепарированный challenge payload, анти-перечисление, discoverable-реестр.
  - **t2em:** жёсткий TTL 60..900 с в v1, распределение ключей получателя (fingerprint), SSRF-guard в MCP, PyCA `cryptography` в Python SDK.
- Интеграция продуктов — только runtime (HTTP/OIDC); npm-зависимости между `@t2em/*` и `@we2em/*` запрещены (см. `TZ_t2em.md` §3.5, `TZ_we2em.md` §3.5).

## Внешние зависимости

- `me2em-protocol` (нормативная спека: `specs/v1.0.md`; текущие npm-версии: `@me2em/core` 1.0.0-rc.4, `@me2em/crypto` 1.1.0-rc.2).
- Планируемые продукты экосистемы: `@me2em/pact`, `@me2em/x402`, w2em registry.
