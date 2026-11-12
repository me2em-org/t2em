# Техническое задание на разработку сервиса t2em.com

**Версия:** 2.0 (Final)
**Статус:** Approved for implementation
**Дата:** 2026-11-13
**Продукт:** t2em (Token / Trust / Transit to EM)
**Домен:** t2em.com
**Экосистема:** Me2eM
**Слой:** Вертикальный продукт (транспорт секретов)
**Лицензия:** Apache-2.0
**Связанные документы:** `TZ_we2em.md` (we2em.com, IdP), `me2em-protocol/specs/v1.0.md` (нормативная спека протокола)

---

## 0. Сводка изменений относительно v1.0

| № | Изменение | Раздел |
|---|---|---|
| 1 | Устранён конфликт TTL: лимит v1 жёстко 60..900 с; IoT-сценарий переведён на `--ttl 900`; долгоживущие managed secrets (до 7 дней) вынесены в v2.0 и требуют аутентификации через we2em | §5.2, §7.3, §14 |
| 2 | Удалены GDPR-эндпоинты `DELETE /entities/:id` и `/export` — t2em не хранит сущности; право на забвение обеспечивается архитектурно (нет данных) и через we2em в v2.0 | §13.1 |
| 3 | Python SDK: разрешена единственная криптозависимость PyCA `cryptography` (stdlib не содержит X25519/AES-GCM/HKDF; hand-rolled crypto запрещён). Сетевые вызовы — только stdlib `urllib` | §8.3 |
| 4 | MCP `t2em_http_request`: добавлена обязательная SSRF-защита (deny-list приватных диапазонов, pinning DNS, контроль редиректов) | §8.4, §11.4 |
| 5 | Добавлен подраздел «Распределение ключей получателя» (Mode A): keyfile, QR, отпечаток, v2.0 — реестр we2em | §4.2.1 |
| 6 | Список MCP-инструментов унифицирован (6 инструментов, включая `t2em_list_secrets`) | §8.4, §17.1 |
| 7 | Формулировка по IP приведена в соответствие с GDPR: `sha256(ip)` — псевдонимизированные персональные данные, хранятся ≤ 60 с | §6.3, §13.1 |
| 8 | Введено бренд-правило T2eM (человек) / t2em (машина); форма «T2em» запрещена | §2.2 |
| 9 | Закреплено правило freeze для HKDF info-строк: изменение — только через `/v2` | §4.5 |
| 10 | Ошибки приводятся к таксономии `CryptoError` из `@me2em/crypto` | §4.5 |
| 11 | Исправлено «w2em registry» → we2em (we2em.com — реальный продукт, см. TZ_we2em.md) | §14.5 |
| 12 | Зафиксирована политика зависимостей от экосистемы: `@me2em/crypto ^1.1.0`, интеграция только через npm, без workspace-ссылок | §3.5 |

---

## 1. Общие сведения

### 1.1. Назначение документа

Настоящее ТЗ описывает требования к разработке сервиса **t2em.com** — self-contained OpenSource-продукта для безопасной эфемерной доставки секретов (API-ключей, токенов доступа, PAT, .env-конфигураций, приватных ключей кошельков) автономным AI-агентам, ботам, IoT-устройствам, sandbox-окружениям и CI/CD-пайплайнам.

Документ **самодостаточен**: не требует обращения к другим спецификациям для понимания требований. Ссылки на экосистему Me2eM — информационные, для контекста интеграции.

### 1.2. Цели продукта

1. **Zero-Knowledge доставка секретов** — сервер не имеет криптографических ключей для расшифровки.
2. **Эфемерность** — данные живут в RAM, TTL ≤ 15 минут (v1), уничтожаются атомарно при первом чтении.
3. **API-First** — все операции через JSON-эндпоинты, без парсинга HTML.
4. **Agent-Friendly** — CLI, SDK, MCP-сервер, `llms.txt` для автономного обнаружения AI-агентами.
5. **DevSecOps-совместимость** — интеграция в CI/CD, UNIX-пайпы, переменные окружения.
6. **Edge-инфраструктура** — Cloudflare Workers + Upstash Redis, глобальная низкая задержка.
7. **Открытый исходный код** — Apache-2.0, self-hosted развёртывание.

### 1.3. Целевая аудитория

| Аудитория | Сценарий |
|---|---|
| **AI-агенты (LLM)** | Получение PAT/API-ключей через MCP без утечки в контекст |
| **DevOps-инженеры** | Передача секретов в CI/CD через CLI |
| **Разработчики ботов** | Передача токенов ботам (Telegram, Discord) |
| **IoT-инженеры** | Provisioning устройств |
| **Security-инженеры** | Аудит передачи секретов |
| **Self-hosted операторы** | Развёртывание on-premise |

### 1.4. Что t2em **не** делает

- **Не** является Identity Provider — аутентификация делегируется we2em.com (интеграция в v2.0, см. `TZ_we2em.md`).
- **Не** хранит секреты долговременно (только эфемерно, TTL ≤ 900 с в v1).
- **Не** заменяет Vault/KMS для постоянного хранения.
- **Не** выполняет шифрование на сервере (zero-knowledge).
- **Не** предоставляет UI для управления идентичностями.
- **Не** хранит персональные данные (см. §13.1).

---

## 2. Терминология

### 2.1. Термины протокола

Протокол использует **domain-neutral** термины для предсказуемости LLM-генерации (правило DR-1 из BACKLOG экосистемы).

| Термин | Определение |
|---|---|
| **Token** | Универсальная единица доступа: API token, auth token, session token, PAT |
| **Vault** | Эфемерное RAM-хранилище секретов (Redis с TTL) |
| **Payload** | Полезная нагрузка дропа (зашифрованный секрет) |
| **Entity** | Отправитель или получатель (человек, агент, устройство) |
| **Drop** | Одноразовая передача секрета (envelope + id + ttl) |
| **Envelope** | JSON-контейнер с ciphertext, iv, mode, ephemeralPubKey |
| **Relay** | Сервер-ретранслятор (Blind Relay) |
| **Mode A** | Асимметричный E2EE (X25519) |
| **Mode B** | Zero-Key Bootstrap (#fragment URL) |
| **Burn-after-reading** | Атомарное удаление после первого чтения |
| **TTL** | Time-To-Live, время жизни дропа |
| **Keyfile** | Файл с приватным ключом получателя (Mode A) |
| **Fingerprint** | Короткий отпечаток pubkey для верификации вне канала |
| **PreKeyBundle** | Публичные ключи для X3DH (v2.0) |

### 2.2. Бренд-правило

По аналогии с правилом DR-5 экосистемы (Me2eM/me2em) для t2em закреплены ровно две канонические формы:

- **T2eM** — человекочитаемая форма (заголовки, презентации);
- **t2em** — машиночитаемая форма (домены, пакеты, CLI, идентификаторы).

Форма **«T2em» запрещена** как опечатка. Исключение — идентификаторы кода (например, класс `T2emClient` в SDK), которые являются машиночитаемым текстом.

---

## 3. Архитектура

### 3.1. Общая схема

```
┌────────────────────────────────────────────────────────────────────────┐
│                          CLIENTS (Edge)                                │
│                                                                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│  │  Web UI  │  │   CLI    │  │ Python   │  │   MCP    │  │  Raw     │ │
│  │          │  │ (Node)   │  │   SDK    │  │  Server  │  │  HTTP    │ │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘ │
└───────┼─────────────┼─────────────┼─────────────┼─────────────┼───────┘
        │             │             │             │             │
        └─────────────┴─────────────┴─────────────┴─────────────┘
                                    │
                                    │ HTTPS (TLS 1.3)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     CLOUDFLARE (Edge Network)                          │
│                                                                        │
│  • DNSSEC enabled                                                      │
│  • Strict HSTS (max-age=63072000; includeSubDomains; preload)          │
│  • TLS 1.3 only, no TLS 1.0/1.1                                        │
│  • WAF + DDoS protection                                               │
│  • Rate limiting (per IP, per endpoint)                                │
│  • Bot management (allowlist для known agents)                         │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │              Cloudflare Workers (Edge Compute)                   │ │
│  │                                                                  │ │
│  │  • Hono framework (TypeScript)                                   │ │
│  │  • Zero-logging (no request body logging)                        │ │
│  │  • Cache-Control: no-store, no-cache, private                    │ │
│  │  • CORS: allowlist                                               │ │
│  │  • Security headers (CSP, X-Frame-Options, etc.)                 │ │
│  └──────────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ HTTPS (internal)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                    UPSTASH REDIS (Global, Multi-region)                │
│                                                                        │
│  • RAM-only (no persistence, no RDB, no AOF)                           │
│  • TLS 1.3                                                            │
│  • Private network (no public exposure)                                │
│  • Automatic TTL enforcement                                          │
│  • Atomic GETDEL (Redis 6.2+)                                         │
│                                                                        │
│  Keys:                                                                 │
│    drop:{id}       → Envelope JSON       EX {ttl}                     │
│    delete:{id}     → delete_token_hash   EX {ttl}                     │
│    ratelimit:{ip}  → counter             EX 60                        │
└────────────────────────────────────────────────────────────────────────┘
```

### 3.2. Компоненты

| Компонент | Технология | Назначение |
|---|---|---|
| **Edge Compute** | Cloudflare Workers + Hono | Обработка HTTP-запросов |
| **Storage** | Upstash Redis (REST) | Эфемерное хранение дропов |
| **DNS/CDN** | Cloudflare | DNSSEC, CDN, WAF, DDoS |
| **CLI** | Node.js ≥ 22 (TypeScript) | Командная строка для DevOps |
| **Python SDK** | Python ≥ 3.10 | SDK для LangGraph/CrewAI/AutoGen |
| **MCP Server** | Node.js ≥ 22 (TypeScript) | Интеграция с Claude Code/Cursor/Windsurf |
| **Web UI** | Vanilla JS (no framework) | Браузерная расшифровка (Mode B) |
| **Crypto Core** | `@me2em/crypto` | X25519, HKDF, AES-GCM, secureWipe |

### 3.3. Монорепозиторий (pnpm workspace)

```
t2em/
├── packages/
│   ├── protocol/          @t2em/protocol      — криптографическое ядро
│   ├── relay-server/      @t2em/relay-server  — Blind Relay (Workers + Node)
│   ├── cli/               @t2em/cli           — CLI (t2em-cli)
│   ├── mcp-server/        @t2em/mcp-server    — MCP сервер
│   └── web-ui/            @t2em/web-ui        — Web UI (embedded в relay)
├── python-sdk/            t2em                — Python SDK (PyPI)
├── docs/                  Документация (VitePress + ТЗ)
├── infra/                 Terraform / Wrangler конфиги
└── examples/              Примеры интеграции
```

### 3.4. Режимы развёртывания

**1. Cloudflare Workers (managed, $0/мес)**

- Точка входа: `packages/relay-server/src/worker.ts`.
- Storage: Upstash Redis (REST API).
- Deploy: GitHub Actions + `wrangler-action`.

**2. Self-hosted Docker**

- Точка входа: `packages/relay-server/src/node.ts` (`@hono/node-server`).
- Storage: Redis (local, RAM-only: `--save "" --appendonly no`).
- Deploy: `docker compose up -d`.

**Требование:** обе точки входа используют **один** Hono-app (`packages/relay-server/src/app.ts`), различия — только в адаптере storage.

### 3.5. Место в экосистеме и границы интеграции

| Продукт | Роль | Интеграция с t2em |
|---|---|---|
| `@me2em/crypto` | Горизонтальный слой | npm-зависимость `packages/protocol` |
| `@me2em/core` | Горизонтальный слой | npm-зависимость (v2.0: Attestation, Session) |
| **we2em.com** | Layer 0/1 (IdP) | **Только runtime (HTTP/OIDC)**, без npm-зависимостей |
| `@me2em/pact` | Криптоаудит | Внешняя зависимость, когда выйдет |
| `@me2em/x402` | Платежи | Внешняя зависимость, когда выйдет |

**Правило зависимостей** (наследует BACKLOG экосистемы): зависимости между пакетами строго вверх (`protocol → @me2em/crypto → @me2em/core`). Между продуктами t2em и we2em — **только runtime-интеграция по HTTP**; npm-зависимость `@t2em/* → @we2em/*` и наоборот запрещена. Это сохраняет независимость монорепозиториев и совместимость с правилом экосистемы «verticals never depend on each other».

**Версионная политика:** `@me2em/crypto` — `^1.1.0` (текущий npm latest: 1.1.0-rc.2), `@me2em/core` — `^1.0.0-rc.4` с последующим обновлением до stable 1.0.0. Range `workspace:*` внутри монорепо t2em не используется — только `workspace:^` (правило DR-4).

---

## 4. Криптографическая спецификация (Protocol v1)

### 4.1. Стандарты

- **X25519** — RFC 7748.
- **HKDF-SHA256** — RFC 5869.
- **AES-256-GCM** — NIST SP 800-38D.
- **Ed25519** — RFC 8032 (для подписей, опционально).
- **Base64URL** — RFC 4648 §5 (без padding).

Реализация — исключительно на примитивах `@me2em/crypto` (v1.1.0-rc.2): `generateX25519KeyPair`, `x25519SharedSecret`, `ed25519PubToX25519`, `ed25519PrivToX25519`, `hkdfWithInfo`, `importAeadKey`, `encryptAead`, `decryptAead`, `signRaw`, `secureWipe`, `secureWipeMultiple`, `withSecureWipe`. Прямое использование `@noble/*` в прикладном коде запрещено — только через прослойку `@t2em/protocol`.

### 4.2. Mode A: Асимметричный E2EE (X25519)

**Когда:** получатель имеет публичный ключ (X25519 или Ed25519, конвертируемый в X25519).

**Алгоритм:**

```
1. Отправитель генерирует эфемерную пару X25519 (eph_priv, eph_pub).
2. Если ключ получателя — Ed25519, конвертировать в X25519:
   recipient_x25519_pub = ed25519PubToX25519(recipient_ed25519_pub)
3. shared_secret = X25519(eph_priv, recipient_x25519_pub)   // 32 байта
4. salt = eph_pub || recipient_x25519_pub                    // 64 байта (UKS-safe)
5. aes_key = HKDF-SHA256(
     ikm = shared_secret,
     salt = salt,
     info = "me2em/crypto/v1/t2em-drop",
     len = 32
   )
6. iv = randomBytes(12)
7. ciphertext = AES-256-GCM(aes_key, iv, plaintext)          // включает 16B tag
8. (опционально) senderSignature = Ed25519(sender_priv, ...)
9. secureWipe(eph_priv, shared_secret, aes_key, plaintext)
```

**Envelope:**

```json
{
  "v": 1,
  "mode": "x25519",
  "ephemeralPubKey": "<base64url 32B>",
  "ciphertext": "<base64url, AES-GCM ciphertext + 16B tag>",
  "iv": "<base64url 12B>",
  "senderSignature": "<base64url 64B, optional>",
  "senderPubKey": "<base64url 32B, optional>"
}
```

#### 4.2.1. Распределение ключей получателя (новое)

Mode A требует, чтобы отправитель достоверно знал pubkey получателя. В v1 поддерживаются каналы:

| Канал | Механизм | Достоверность |
|---|---|---|
| **Keyfile** | `t2em-cli keygen --out ./agent.key` печатает pubkey; получатель передаёт pubkey любым каналом | Ручная сверка отпечатка |
| **QR (Web UI)** | Web UI показывает pubkey и его QR-код | Визуальная сверка |
| **Отпечаток (fingerprint)** | `fingerprint = base64url(sha256(pubkey))[0..8]` — 8 символов для сверки голосом/в чате | Защита от подмены/MITM при сверке вне канала |
| **Реестр we2em (v2.0)** | `GET https://we2em.com/api/v1/keys/:pubkey` — pubkey, привязанный аттестацией владельца (см. `TZ_we2em.md` §5.6) | Криптографическая (attestation) |

**Требование:** CLI при `push --to <pubkey>` выводит отпечаток получателя в stderr. `t2em-cli pull` в Mode A выводит отпечаток отправителя, если присутствует `senderPubKey`.

### 4.3. Mode B: Zero-Key Bootstrap (#fragment URL)

**Когда:** получатель не имеет предварительного обмена ключами (чистый инстанс).

**Алгоритм:**

```
1. Клиент генерирует sym_key = randomBytes(32).
2. iv = randomBytes(12).
3. ciphertext = AES-256-GCM(sym_key, iv, plaintext).
4. Клиент → Relay: POST /api/v1/drop { envelope: {v, mode: "sym", ciphertext, iv}, ttl }
5. Relay → Клиент: { id, url: "https://t2em.com/s/{id}" }
6. Клиент формирует финальный URL: "https://t2em.com/s/{id}#{base64url(sym_key)}"
7. По RFC 3986, фрагмент после # НЕ передаётся на сервер.
8. Получатель: GET /s/{id} → envelope, локально расшифровывает sym_key из #fragment.
```

**Envelope:**

```json
{
  "v": 1,
  "mode": "sym",
  "ciphertext": "<base64url, AES-GCM ciphertext + 16B tag>",
  "iv": "<base64url 12B>"
}
```

### 4.4. Гигиена памяти

**Требование:** все секретные буферы (`eph_priv`, `shared_secret`, `aes_key`, `sym_key`, `plaintext`) затираются двухпроходным `secureWipe` из `@me2em/crypto`:

1. Заполнить случайными байтами (`crypto.getRandomValues`).
2. Заполнить нулями.

Для композиции использовать `withSecureWipe(data, operation)` — автоматическое затирание в `finally`.

**Ограничение (фиксируется честно, согласно JSDoc `@me2em/crypto`):** JavaScript GC может сохранять копии. `secureWipe` — **mitigation**, не гарантия. Для строгих гарантий — non-extractable `CryptoKey` или hardware-backed keys.

### 4.5. Версионирование и таксономия ошибок

- **Freeze-правило** (наследует §4 PLAN-LTS-v1 экосистемы): HKDF info-строка `"me2em/crypto/v1/t2em-drop"`, поле `envelope.v` и любые строки, влияющие на деривацию ключей, изменяются **только** через новую версию `/v2` (новая info-строка, новое поле `v`, отдельный `mode`). Изменение существующих строк — breaking change, запрещено.
- **Таксономия ошибок:** криптографические ошибки выбрасываются как `CryptoError` из `@me2em/crypto` с полями `code`/`level`. Ожидаемые коды: `UNSUPPORTED_VERSION` (чужой `envelope.v`), `MALFORMED` (структура). Интеграция — по полям `code`/`level`, не по тексту сообщения.
- **Тест-векторы:** `@t2em/protocol` публикует `vectors/t2em-drop.v1.json` (Mode A и Mode B), бит-в-бит совместимые между TypeScript и Python-реализациями.

---

## 5. API-спецификация

### 5.1. Общие требования

- **Base URL:** `https://t2em.com/api/v1`
- **Content-Type:** `application/json`
- **Character encoding:** UTF-8
- **Auth:** не требуется для `POST /drop` (zero-knowledge); опционально — для приватных дропов (v2.0, через we2em SSO).
- **Rate limit:** 60 запросов/минуту на IP (настраивается). Ответы 429 включают заголовки `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `Retry-After`.
- **Max payload:** 64 KB.
- **Cache:** `Cache-Control: no-store, no-cache, private`.
- **Logging:** тела запросов **не логируются** (zero-logging).

### 5.2. `POST /api/v1/drop` — создание дропа

**Request:**

```http
POST /api/v1/drop HTTP/1.1
Host: t2em.com
Content-Type: application/json

{
  "envelope": {
    "v": 1,
    "mode": "x25519",
    "ephemeralPubKey": "<base64url 32B>",
    "ciphertext": "<base64url>",
    "iv": "<base64url 12B>",
    "senderSignature": "<base64url 64B, optional>",
    "senderPubKey": "<base64url 32B, optional>"
  },
  "ttl": 300,
  "burn_after_reading": true
}
```

**Параметры:**

| Поле | Тип | Обязательно | Описание |
|---|---|---|---|
| `envelope` | object | Да | Зашифрованный контейнер |
| `envelope.v` | number | Да | Версия протокола (1) |
| `envelope.mode` | string | Да | `"x25519"` или `"sym"` |
| `envelope.ciphertext` | string | Да | Base64url AES-GCM ciphertext |
| `envelope.iv` | string | Да | Base64url 12B IV |
| `envelope.ephemeralPubKey` | string | Mode A | Base64url 32B |
| `envelope.senderSignature` | string | Нет | Base64url 64B Ed25519 |
| `envelope.senderPubKey` | string | Нет | Base64url 32B Ed25519 |
| `ttl` | number | Да | **60..900 секунд (жёсткий лимит v1)** |
| `burn_after_reading` | boolean | Нет | Default `true` |

**Response (201 Created):**

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "url": "https://t2em.com/s/550e8400-e29b-41d4-a716-446655440000",
  "expires_in": 300,
  "delete_token": "<base64url 32B>"
}
```

**Ошибки:**

| Код | Причина |
|---|---|
| `400 Bad Request` | Невалидный JSON, отсутствуют поля, неверный `ttl`, `envelope.v` ≠ 1 |
| `413 Payload Too Large` | Envelope > 64 KB |
| `429 Too Many Requests` | Rate limit |
| `500 Internal Server Error` | Ошибка Redis |

### 5.3. `GET /s/:id` — получение дропа

**Request:**

```http
GET /s/550e8400-e29b-41d4-a716-446655440000 HTTP/1.1
Host: t2em.com
Accept: application/json
```

**Response (200 OK, `Accept: application/json`):**

```json
{
  "envelope": {
    "v": 1,
    "mode": "x25519",
    "ephemeralPubKey": "<base64url 32B>",
    "ciphertext": "<base64url>",
    "iv": "<base64url 12B>",
    "senderSignature": "<base64url 64B, optional>",
    "senderPubKey": "<base64url 32B, optional>"
  }
}
```

**Поведение:**
- Если `burn_after_reading: true` (default) — атомарный `GETDEL` (Redis 6.2+ или Lua).
- Если `burn_after_reading: false` — `GET` без удаления (TTL продолжает тикать).

**Response (200 OK, `Accept: text/html`):**

Web UI (embedded HTML + JS для браузерной расшифровки Mode B).

**Ошибки:**

| Код | Причина |
|---|---|
| `404 Not Found` | Дроп не существует / истёк / уже прочитан |
| `429 Too Many Requests` | Rate limit |

**Примечание (анти-перечисление):** 404 для «не существует», «истёк» и «уже прочитан» — идентичен по телу и времени ответа (constant-time путь).

### 5.4. `DELETE /api/v1/drop/:id` — досрочное уничтожение

**Request:**

```http
DELETE /api/v1/drop/550e8400-e29b-41d4-a716-446655440000 HTTP/1.1
Host: t2em.com
X-Delete-Token: <base64url 32B>
```

**Response (200 OK):**

```json
{ "deleted": true }
```

**Ошибки:**

| Код | Причина |
|---|---|
| `401 Unauthorized` | Отсутствует `X-Delete-Token` |
| `403 Forbidden` | Неверный `X-Delete-Token` |
| `404 Not Found` | Дроп не существует |

### 5.5. `GET /llms.txt` — документация для AI-агентов

Полный текст — Приложение C. **Требование:** `llms.txt` генерируется автоматически из OpenAPI + шаблона при сборке (не редактируется вручную — защита от рассинхронизации).

### 5.6. `GET /health` — health check

**Response (200 OK):**

```json
{
  "status": "ok",
  "redis": "ok",
  "version": "1.0.0"
}
```

**Response (503 Service Unavailable):**

```json
{
  "status": "degraded",
  "redis": "unavailable"
}
```

### 5.7. OpenAPI 3.1 спецификация

**Требование:** публиковать `GET /openapi.json` — полная OpenAPI 3.1 спецификация для генерации клиентов. `Cache-Control: public, max-age=300`.

---

## 6. Модель данных (Zero-Knowledge)

### 6.1. Redis-схема

```
# Дроп (основной)
KEY: drop:{id}
VALUE: JSON string (Envelope)
TTL: {ttl} seconds (60..900)
TYPE: string

# Токен для удаления (хэш)
KEY: delete:{id}
VALUE: hex(sha256(delete_token))
TTL: {ttl} seconds
TYPE: string

# Rate limit (per IP)
KEY: ratelimit:{ip_hash}:{minute}
VALUE: counter
TTL: 60 seconds
TYPE: string (INCR + EXPIRE)
```

Примечание: ключ rate limit использует `sha256(ip)` (не plaintext IP) — см. §6.3.

### 6.2. Что хранится

| Данные | Где | Шифрование | TTL |
|---|---|---|---|
| Envelope (ciphertext) | Redis `drop:{id}` | AES-GCM (клиентом) | ≤ 900 s |
| Delete token hash | Redis `delete:{id}` | sha256 | ≤ 900 s |
| Rate limit counter | Redis `ratelimit:*` | — | 60 s |

### 6.3. Что **не** хранится (Zero-Knowledge)

| Данные | Почему |
|---|---|
| Plaintext секрета | Zero-knowledge: сервер не видит |
| `sym_key` (Mode B) | В `#fragment` URL, не передаётся |
| `eph_priv`, `shared_secret`, `aes_key` | Только у клиента |
| Тела запросов | Zero-logging |
| User-Agent | Zero-logging (в security-логах — только `sha256(user-agent)`, опционально) |
| Метаданные (кто, кому) | Не хранятся |
| IP-адреса в plaintext | Не хранятся. Для rate limit — ключ `sha256(ip)`, живёт 60 с |

**Формулировка для GDPR (уточнено в v2.0):** `sha256(ip)` — псевдонимизированные персональные данные (хэш перебираем для IPv4). Хранятся исключительно в ключе rate limit с TTL 60 с, не выгружаются в логи и не коррелируют между окнами. Это минимум, необходимый для защиты сервиса (legitimate interest, ст. 6(1)(f) GDPR); более длительного хранения нет.

### 6.4. Гарантии

- **Атомарность:** `GETDEL` гарантирует, что дроп будет прочитан ровно один раз (при `burn_after_reading: true`).
- **Эфемерность:** Redis без persistence (RDB/AOF отключены). Даже при компромиссе Redis — только ciphertext, TTL ≤ 15 мин.
- **Zero-logging:** Cloudflare Workers не логируют тела запросов. Upstash Redis не логирует значения.

---

## 7. Сценарии использования

### 7.1. User Journey: человек → AI-агент (через Web UI)

**Персона:** Алиса — разработчица, хочет передать GitHub PAT своему AI-агенту (Claude Code), который работает в sandbox.

**Шаги:**

1. **Алиса открывает** `https://t2em.com` в браузере.
2. **Вставляет PAT** в поле «Secret».
3. **Выбирает TTL** (5 минут, по умолчанию).
4. **Нажимает «Create Drop»**.
5. **Сервер возвращает** URL: `https://t2em.com/s/abc123#xyz789`.
6. **Алиса копирует URL** и вставляет в чат с агентом.
7. **Агент (Claude Code)** получает URL, вызывает MCP-tool `t2em_pull(url)`.
8. **MCP-сервер** делает `GET /s/abc123` → envelope.
9. **MCP-сервер** расшифровывает envelope с `xyz789` (из `#fragment`) → PAT.
10. **MCP-сервер** сохраняет PAT в `InMemorySecretVault`, возвращает агенту `secret_handle`.
11. **Агент** вызывает `t2em_http_request` с `{{secret_handle}}` → GitHub API.
12. **MCP-сервер** подставляет PAT, делает запрос, возвращает ответ.
13. **Агент** вызывает `t2em_wipe_secret` → PAT уничтожен.
14. **Сервер** уже удалил envelope (GETDEL).

**Гарантии:**
- Алиса **не** отправляет PAT в чат (только URL).
- Агент **не** видит PAT (только `secret_handle`).
- Сервер **не** видит PAT (только ciphertext).
- PAT живёт ≤ 5 минут.

### 7.2. User Journey: CI/CD → deployment

**Персона:** Боб — DevOps, хочет передать `DB_PASSWORD` в production deployment.

**Шаги:**

1. **Боб** запускает в терминале:
   ```bash
   $ echo "$DB_PASSWORD" | t2em-cli push --ttl 300
   https://t2em.com/s/abc123#xyz789
   ```
2. **Боб** сохраняет URL в CI/CD secret (GitHub Actions secret, GitLab variable).
3. **CI/CD pipeline** (на production runner):
   ```bash
   $ export DB_PASSWORD=$(t2em-cli pull "$T2EM_URL")
   $ ./deploy.sh
   ```
4. **`t2em-cli pull`** делает `GET /s/abc123`, расшифровывает, выводит в stdout.
5. **Envelope** удалён (GETDEL).
6. **`DB_PASSWORD`** в переменной окружения, используется deployment-скриптом.

**Гарантии:**
- Пароль **не** в CI/CD логах (только URL).
- Пароль **не** на сервере (только ciphertext).
- Пароль живёт ≤ 5 минут.

### 7.3. User Journey: IoT device provisioning

**Персона:** Карл — IoT-инженер, хочет provision 1000 устройств с уникальными API-ключами.

**Шаги:**

1. **Карл** генерирует 1000 ключей, для каждого:
   ```bash
   $ echo "$API_KEY" | t2em-cli push --ttl 900 --out urls/device-$i.txt
   ```
   *(Исправлено в v2.0: лимит v1 — 900 с. Устройство обязано выполнить первый boot и pull в течение 15 минут; для отложенного provisioning — повторный push на устройстве или v2.0 managed secrets.)*
2. **Устройства** при первом boot:
   ```bash
   $ API_KEY=$(t2em-cli pull "$(cat /boot/t2em-url.txt)")
   $ echo "API_KEY=$API_KEY" >> /etc/device.conf
   ```
3. **Envelope** удалён после pull.

**Гарантии:**
- Ключи **не** в прошивке (только URL).
- Ключи **не** на сервере (только ciphertext).
- Каждый ключ живёт ≤ 15 минут (v1).

### 7.4. User Journey: agent → agent (MCP federation)

**Персона:** Агент A (research) хочет передать intermediate results Агенту B (writer).

**Шаги:**

1. **Агент A** вызывает MCP-tool `t2em_push(payload, ttl=300)`.
2. **MCP-сервер A** шифрует payload на pubkey Агента B (Mode A).
3. **MCP-сервер A** возвращает URL.
4. **Агент A** передаёт URL Агенту B (через общий чат или shared memory).
5. **Агент B** вызывает MCP-tool `t2em_pull(url)`.
6. **MCP-сервер B** расшифровывает, сохраняет в vault, возвращает `secret_handle`.

**Гарантии:**
- Payload **не** в общем чате (только URL).
- Payload **не** на сервере (только ciphertext).
- Payload живёт ≤ 5 минут.

---

## 8. Требования к реализации

### 8.1. API-First

- **Все операции** — через JSON-эндпоинты (`POST /api/v1/drop`, `GET /s/:id`, `DELETE /api/v1/drop/:id`).
- **Никакого парсинга HTML** для программного доступа.
- **OpenAPI 3.1** спецификация на `GET /openapi.json`.
- **Content negotiation:** `Accept: application/json` → JSON, `Accept: text/html` → Web UI.

### 8.2. CLI (`t2em-cli`)

**Установка:**

```bash
npm install -g @t2em/cli
# или
npx @t2em/cli
```

**Команды:**

```bash
# Создать дроп (Mode B, симметричный)
$ echo "secret" | t2em-cli push --ttl 300
https://t2em.com/s/abc123#xyz789

# Создать дроп (Mode A, на pubkey получателя)
$ echo "secret" | t2em-cli push --to <base64url-pubkey> --ttl 300
t2em: recipient fingerprint: 9f86d08e (stderr)
https://t2em.com/s/abc123

# Получить дроп
$ t2em-cli pull "https://t2em.com/s/abc123#xyz789"
secret

# Получить дроп (Mode A, с privkey)
$ t2em-cli pull "https://t2em.com/s/abc123" --key ./agent.key
secret

# Генерация keypair
$ t2em-cli keygen --out ./agent.key
<base64url-pubkey>

# Удалить дроп
$ t2em-cli delete "https://t2em.com/s/abc123" --token <delete_token>
```

**Требования:**

- **UNIX-пайпы:** stdin/stdout для интеграции в shell-скрипты. Диагностика (отпечатки, прогресс) — только в stderr.
- **Переменные окружения:** `T2EM_BASE_URL` (default `https://t2em.com`).
- **Exit codes:** 0 — успех, 1 — ошибка, 2 — невалидный аргумент.
- **Секреты не в аргументах:** `--secret` запрещён, только stdin.
- **Права файлов:** `0600` для keyfile.
- **`secureWipe`** после использования ключей.

### 8.3. Python SDK (`t2em`)

**Установка:**

```bash
pip install t2em
```

**API:**

```python
from t2em import T2emClient, generate_x25519_keypair

client = T2emClient("https://t2em.com")

# Mode B (симметричный)
drop = client.push(secret="sk-live-...", ttl=300)
print(drop.url)  # https://t2em.com/s/abc123#xyz789

secret = client.pull_text(drop.url)

# Mode A (асимметричный)
keys = generate_x25519_keypair()
drop = client.push(secret="sk-live-...", recipient_pubkey=keys.public_key, ttl=300)
secret = client.pull_text(drop.url, recipient_privkey=keys.private_key)
```

**Требования (уточнено в v2.0):**

- **Сетевые вызовы:** только stdlib `urllib` — никаких `requests`/`httpx`.
- **Криптография:** единственная внешняя криптозависимость — **PyCA `cryptography`** (аудированная, де-факто стандарт). Stdlib Python не содержит X25519/AES-GCM, а hand-rolled crypto запрещён (§11.2). HKDF допускается на `cryptography`-примитивах либо на `hmac`/`hashlib` строго по RFC 5869 с обязательной проверкой против тест-векторов RFC.
- **Bit-compatible** с TypeScript-протоколом: те же base64url, HKDF, AES-GCM; проверка на общих тест-векторах `vectors/t2em-drop.v1.json`.
- **Type hints:** полные аннотации.
- **Python ≥ 3.10.**

### 8.4. MCP Server (`@t2em/mcp-server`)

**Установка:**

```bash
npm install -g @t2em/mcp-server
```

**Tools (полный список — 6):**

| Tool | Параметры | Возвращает |
|---|---|---|
| `t2em_keygen` | — | `{ public_key, key_id, fingerprint }` (privkey в vault) |
| `t2em_push` | `{ secret, ttl?, recipient_pubkey? }` | `{ url, delete_token? }` |
| `t2em_pull` | `{ url }` | `{ secret_handle }` |
| `t2em_http_request` | `{ url, method, headers?, body? }` | `{ status, headers, body }` |
| `t2em_wipe_secret` | `{ secret_handle }` | `{ ok }` |
| `t2em_list_secrets` | — | `{ handles: string[] }` |

**Требования:**

- **InMemorySecretVault:** секреты в RAM процесса MCP, не в LLM-контексте.
- **`secret_handle`:** строка `sec_<uuid>`, не сам секрет.
- **`t2em_http_request`:** подстановка `{{secret_handle}}` в headers/body.
- **SSRF-защита `t2em_http_request` (новое, обязательно):**
  - Запрещённые сети назначения: `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16` (cloud metadata), `0.0.0.0/8`, `100.64.0.0/10`, `192.0.0.0/24`, `198.18.0.0/15`, `::1/128`, `fc00::/7`, `fe80::/10`, `::ffff:0:0/96`.
  - Схема — только `https`.
  - DNS pinning: разрешённое имя фиксируется за первым A/AAAA-ответом; соединение — к тому же IP (защита от DNS rebinding).
  - Редиректы: не следовать автоматически; каждый редирект — новое решение с повторной проверкой назначения.
- **Zero-logging:** MCP не логирует секреты.
- **`secureWipe`** после `t2em_wipe_secret`.

### 8.5. Токенизация для LLM

**Требование:** документация (`llms.txt`, README) использует **высокочастотные** термины, чтобы LLM могли предсказуемо генерировать запросы (правило DR-1 экосистемы).

**Словарь:**

| Использовать | Не использовать |
|---|---|
| Token | Credential, secret, key |
| Vault | Store, repository |
| Payload | Data, content |
| Entity | Subject, party, actor |
| Drop | Transfer, share, message |
| Pull / Push | Fetch / Send, Get / Put |
| URL | Link, address |

### 8.6. Инфраструктура (Cloudflare)

**Требования:**

- **DNSSEC:** включён.
- **HSTS:** `max-age=63072000; includeSubDomains; preload`.
- **TLS 1.3 only:** no TLS 1.0/1.1.
- **WAF:** Cloudflare Managed Rules + OWASP Core Ruleset.
- **DDoS protection:** Cloudflare Automatic (L3/L4/L7).
- **Bot management:** allowlist для known AI-агентов (по User-Agent + IP ranges), challenge для остальных.
- **Rate limiting:** Cloudflare Rate Limiting Rules (per IP, per endpoint) + Redis-based (per pubkey, для v2.0).
- **Cache rules:** `Cache-Control: no-store` для всех API-ответов; кэширование только статики (`/llms.txt`, `/openapi.json`, `/health` — с коротким TTL).
- **Transform Rules:** принудительный HTTPS redirect; удаление `Server` header; добавление `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`.
- **Cloudflare Workers:**
  - Runtime: `workerd` (V8 isolates).
  - Framework: Hono.
  - Cold start: ≤ 50ms (цель).
  - Bundle size: ≤ 1 MB (Workers limit — 10 MB, но цель — минимальный bundle).
- **Upstash Redis:**
  - REST API (без TCP-сокетов).
  - Global replication (multi-region).
  - TLS 1.3.
  - No persistence (RDB/AOF off).
- **Cloudflare R2 (опционально, для v2.0):**
  - Managed secrets с TTL до 7 дней (аутентифицированный режим, см. §14.5).
  - Private buckets, presigned URLs (TTL 60s).

### 8.7. Мониторинг и наблюдаемость

- **Метрики (Cloudflare Analytics):**
  - Request rate, error rate (4xx/5xx), latency (p50, p95, p99).
  - Drop creation rate, drop fetch rate, drop expiry rate.
  - Rate limit hits.
- **Логи (структурированные, без секретов):**
  - `{ timestamp, level, event, dropId, mode, ttl, status, latencyMs }`.
  - **Никогда:** plaintext, ciphertext, `sym_key`, plaintext IP (только `sha256(ip)` для security-событий), plaintext User-Agent.
- **Алерты:**
  - Error rate > 1% (5 min window).
  - Latency p99 > 500ms.
  - Redis unavailable.
  - Rate limit hits > 1000/min.
- **Distributed tracing (опционально):** OpenTelemetry + Cloudflare Workers Trace Events.

### 8.8. CI/CD

- **GitHub Actions:**
  - Lint (ESLint, Prettier).
  - Test (Vitest, coverage ≥ 80%).
  - Build (TypeScript, `wrangler build`).
  - Deploy (staging → production, manual approval).
- **Wrangler:**
  - `wrangler deploy` для Workers.
  - `wrangler secret put` для secrets (Redis URL).
- **Docker (self-hosted):**
  - `docker build` + `docker push` (GHCR).
  - `docker compose up -d` для self-hosted.
- **Versioning:** SemVer, CHANGELOG.md, Git tags (`<pkg>-v<version>` — конвенция экосистемы).
- **Release process:**
  1. PR → CI (lint, test, build).
  2. Merge to `main` → deploy to staging.
  3. Smoke tests (E2E: create drop → fetch drop → verify).
  4. Manual approval → deploy to production.
  5. Post-deploy: health check, canary (5% traffic).
- **Supply chain:** `pnpm audit` blocking (практика экосистемы, BL-34), gitleaks, CodeQL, SBOM (CycloneDX), npm Provenance.

---

## 9. Тестирование

### 9.1. Unit-тесты

**Покрытие:** ≥ 80% (строки), ≥ 70% (ветки).

**Что тестируется:**

- `@t2em/protocol`:
  - `packDrop` / `unpackDrop` (Mode A, Mode B).
  - X25519 ECDH, HKDF, AES-GCM (на векторах `vectors/t2em-drop.v1.json`).
  - Ed25519↔X25519 конверсия.
  - `secureWipe` (проверка, что буферы занулены).
  - Envelope validation (невалидные поля, `v` ≠ 1).
- `@t2em/relay-server`:
  - API handlers (mock Redis).
  - Rate limiting logic.
  - Error handling (4xx/5xx).
  - `GETDEL` atomicity (mock Redis).
- `@t2em/cli`:
  - Argument parsing.
  - stdin/stdout, диагностика в stderr.
  - Exit codes.
- `@t2em/mcp-server`:
  - Tool handlers.
  - `InMemorySecretVault` (add, get, delete, wipe).
  - `secret_handle` generation.
  - **SSRF-guard:** deny-list IPv4/IPv6, DNS pinning, redirect policy.

### 9.2. Integration-тесты

- E2E: `POST /drop` → `GET /s/:id` → decrypt → verify plaintext.
- E2E: `POST /drop` (burn_after_reading) → `GET /s/:id` → `GET /s/:id` (404).
- E2E: `DELETE /drop/:id` с правильным/неправильным `X-Delete-Token`.
- Rate limit: 61 запрос → 429 (+ заголовки `X-RateLimit-*`).
- TTL expiry: drop с TTL 60s → через 61s → 404.
- Payload size: 65 KB → 413.
- TTL bounds: `ttl=59` → 400; `ttl=901` → 400.
- Concurrent GETDEL: 10 параллельных `GET /s/:id` → 1 успех, 9 × 404.

**Инструменты:** Vitest + Miniflare + Redis mock (или testcontainers).

### 9.3. Security-тесты

- **Fuzzing:** `POST /drop` с случайными payload (10 000 итераций).
- **Replay:** повторный `GET /s/:id` → 404.
- **Timing attack:** constant-time compare для delete token.
- **XSS:** Web UI (`Accept: text/html`) — санитизация.
- **CSRF:** API не использует cookies (только заголовки), CSRF не применим.
- **Injection:** JSON parse с `__proto__` → отклоняется (`safeJsonParse`).
- **DoS:** Rate limit, max payload, max TTL.
- **SSRF (новое):** наборы атак на `t2em_http_request` — metadata-эндпоинты (`169.254.169.254`), localhost, приватные диапазоны, DNS rebinding, redirect в приватную сеть → все отклоняются.

### 9.4. Load-тесты

**Инструменты:** k6, Artillery.

**Сценарии:**

- **Baseline:** 100 RPS, 1 минута, p95 < 100ms.
- **Peak:** 1000 RPS, 1 минута, p95 < 500ms.
- **Spike:** 0 → 5000 RPS за 10 секунд, p95 < 1s.

**Цели:** error rate < 0.1%; latency p99 < 1s; no memory leaks.

### 9.5. Chaos-тесты

- **Redis unavailable:** API возвращает 503, не падает.
- **Redis slow:** p99 > 1s → timeout, 503.
- **Network partition:** retry с exponential backoff (CLI/SDK).
- **Worker crash:** Cloudflare auto-restart, no data loss (Redis external).

### 9.6. E2E-тесты (Playwright)

- **Web UI:** создание дропа (Mode B) → URL с `#fragment`; fetch → расшифровка в браузере; burn-after-reading (второй fetch → 404); `#fragment` auto-clear.
- **CLI:** `push` → URL; `pull` → plaintext; `keygen` → keypair; fingerprint в stderr.
- **MCP:** `t2em_keygen` → pubkey + fingerprint; `t2em_pull` → `secret_handle`; `t2em_http_request` → mock HTTPS server (и отклонение SSRF-целей); `t2em_wipe_secret` → handle removed; `t2em_list_secrets` → список.

---

## 10. Документация

### 10.1. Обязательные документы

| Документ | Формат | Аудитория |
|---|---|---|
| `README.md` | Markdown | Разработчики, DevOps |
| `docs/` | VitePress | Все |
| `llms.txt` | Plain text | AI-агенты |
| `openapi.json` | OpenAPI 3.1 | Разработчики |
| `SECURITY.md` | Markdown | Security-инженеры |
| `CONTRIBUTING.md` | Markdown | Контрибьюторы |
| `CHANGELOG.md` | Markdown | Все |
| `LICENSE` | Apache-2.0 | Все |

### 10.2. Структура `docs/`

```
docs/
├── index.md                      — Overview
├── getting-started/
│   ├── quickstart.md             — 5-минутный старт
│   ├── cli.md                    — CLI guide
│   ├── python-sdk.md             — Python SDK
│   └── mcp.md                    — MCP integration
├── concepts/
│   ├── zero-knowledge.md         — Zero-Knowledge model
│   ├── modes.md                  — Mode A vs Mode B
│   ├── key-distribution.md       — Распределение ключей получателя (новое)
│   ├── ttl.md                    — TTL и burn-after-reading
│   └── threat-model.md           — Threat model
├── api/
│   ├── reference.md              — OpenAPI reference
│   ├── errors.md                 — Error codes
│   └── rate-limits.md            — Rate limits
├── deployment/
│   ├── cloudflare.md             — Cloudflare Workers
│   ├── docker.md                 — Self-hosted Docker
│   └── configuration.md          — Config reference
├── security/
│   ├── audit.md                  — Security audit (planned)
│   ├── reporting.md              — Vulnerability reporting
│   └── best-practices.md         — Best practices
└── guides/
    ├── ai-agents.md              — AI agent integration
    ├── ci-cd.md                  — CI/CD integration
    ├── iot.md                    — IoT provisioning
    └── agent-to-agent.md         — Agent-to-agent transfer
```

(Настоящее ТЗ хранится как `docs/TZ_t2em.md`; в VitePress-сборку публикация ТЗ не входит.)

### 10.3. `llms.txt` (расширенный)

Полная версия `llms.txt` (Приложение C) должна содержать: overview; quick start (3 шага); endpoints с примерами; Mode A vs Mode B; распределение ключей (fingerprint, keyfile); криптографию (кратко); error codes; rate limits; examples (curl, Python, TypeScript); common pitfalls (не логировать URL с `#fragment`, не кэшировать URL, не переиспользовать `sym_key`, не отправлять секреты в query-параметрах).

**Требование:** `llms.txt` генерируется автоматически из OpenAPI + шаблона.

### 10.4. Примеры (examples/)

| Пример | Язык | Назначение |
|---|---|---|
| `basic-push-pull/` | TypeScript | Простой push/pull |
| `mode-a-x25519/` | TypeScript | Mode A с X25519 + fingerprint-сверка |
| `cli-ci-cd/` | Bash | GitHub Actions integration |
| `mcp-claude-code/` | TypeScript | Claude Code integration |
| `python-langgraph/` | Python | LangGraph agent |
| `iot-provisioning/` | Bash | IoT provisioning (TTL ≤ 900 с) |
| `agent-to-agent/` | TypeScript | Agent → Agent transfer |

---

## 11. Требования к безопасности (детально)

### 11.1. Zero-Knowledge

- **Сервер не имеет ключей** для расшифровки envelope (Mode A/B).
- **Сервер не логирует** тела запросов.
- **Сервер не хранит** plaintext IP (только `sha256(ip)` в ключе rate limit, TTL 60 с — см. §6.3).
- **Сервер не хранит** User-Agent (в security-логах — только `sha256(user-agent)`, опционально).

### 11.2. Криптография

- **X25519:** RFC 7748, через `@me2em/crypto` (`@noble/curves` внутри).
- **HKDF-SHA256:** RFC 5869, `hkdfWithInfo` из `@me2em/crypto`.
- **AES-256-GCM:** NIST SP 800-38D, WebCrypto (`importAeadKey` — ровно 32 байта).
- **Ed25519:** RFC 8032, `signRaw` из `@me2em/crypto`.
- **Random:** `crypto.getRandomValues` (WebCrypto), обёртка `randomBytes` из `@me2em/crypto`.
- **Base64URL:** `@scure/base` (audited).

**Запрещено:**

- Hand-rolled crypto (только audited libs).
- `Math.random()` для секретов.
- ECB mode.
- IV reuse (AES-GCM).
- Truncated MAC (< 128 bit).
- Прямое использование `@noble/*` в прикладном коде вне `@t2em/protocol`.

### 11.3. Гигиена памяти

- **`secureWipe` / `withSecureWipe`:** двухпроходное затирание (random + zeros) для всех секретов.
- **`mlock`:** опционально для CLI (предотвращение swap).
- **Non-extractable `CryptoKey`:** для Web UI (если возможно).

### 11.4. Защита от атак

| Атака | Защита |
|---|---|
| **Replay** | `GETDEL` (атомарно), `burn_after_reading` |
| **MITM** | TLS 1.3, HSTS, DNSSEC, `senderSignature` (опционально), fingerprint-сверка (§4.2.1) |
| **Timing** | Constant-time compare (delete token); идентичный 404-путь (§5.3) |
| **XSS** | CSP, `X-Content-Type-Options: nosniff` |
| **CSRF** | Bearer-заголовки (не cookies) |
| **Injection** | `safeJsonParse` (`__proto__` отклоняется) |
| **DoS** | Rate limit, max payload, max TTL |
| **SSRF (новое)** | Deny-list сетей, DNS pinning, контроль редиректов в `t2em_http_request` (§8.4) |
| **Enumeration** | UUID v4 (не sequential); идентичный 404 |
| **Fingerprinting** | Удаление `Server` header |
| **Prompt injection** | MCP `secret_handle` (не plaintext в LLM) |
| **Key substitution** | Fingerprint pubkey, выводимый CLI в stderr (§4.2.1) |

### 11.5. Supply chain

- **Dependencies:** `@me2em/crypto` (транзитивно `@noble/*`, `@scure/*`, `hash-wasm`), PyCA `cryptography` (Python).
- **Audit:** `pnpm audit` blocking в CI, Snyk/Dependabot.
- **Lockfile:** `pnpm-lock.yaml` коммитится.
- **SBOM:** генерируется в CI (CycloneDX).
- **Signing:** npm packages signed (Provenance).

### 11.6. Аудит

- **Внешний аудит:** перед v1.0 (Trail of Bits / Cure53 / NCC Group).
- **Bug bounty:** HackerOne / Immunefi (после v1.0).
- **Responsible disclosure:** `SECURITY.md` с контактом.
- **CVE:** регистрация в MITRE.

---

## 12. Производительность

### 12.1. Цели

| Метрика | Цель |
|---|---|
| **Latency p50** | < 50ms |
| **Latency p95** | < 100ms |
| **Latency p99** | < 500ms |
| **Throughput** | ≥ 1000 RPS (per region) |
| **Cold start** | < 50ms (Workers) |
| **Bundle size** | < 1 MB |
| **Memory** | < 128 MB (Workers limit) |
| **Uptime** | ≥ 99.9% |

### 12.2. Оптимизации

- **Edge compute:** Cloudflare Workers (глобально распределены).
- **Redis:** Upstash (multi-region replication).
- **Bundle:** tree-shaking, minification, no heavy deps.
- **Caching:** `GET /llms.txt`, `GET /openapi.json` — `Cache-Control: public, max-age=300`.
- **Compression:** Brotli (Cloudflare automatic).

---

## 13. Соответствие (Compliance)

### 13.1. GDPR (переработано в v2.0)

**Ключевой тезис:** t2em в v1 **не обрабатывает персональные данные в значимом объёме** — по построению (data minimization через отсутствие данных):

- Нет учётных записей, сущностей, email, телефонов, plaintext IP (§6.3).
- Единственная категория — псевдонимизированные данные `sha256(ip)` в ключах rate limit (TTL 60 с, не логируются) — обосновано legitimate interest (ст. 6(1)(f) GDPR) для защиты сервиса от злоупотреблений.
- Права на доступ/забвение/переносимость (ст. 15–20) выполняются **архитектурно**: персональных данных, подлежащих выдаче/удалению, не существует.

**v2.0 (аутентифицированный режим через we2em):** субъекты идентифицируются через we2em.com (IdP); учётные записи, удаление аккаунта и экспорт данных — зона ответственности we2em (см. `TZ_we2em.md`). t2em при этом по-прежнему не хранит профилей: сессии валидируются stateless, привязки «аккаунт → дроп» не существует.

- **Audit retention:** security-логи без plaintext IP/UA — 90 дней (настраивается).

### 13.2. SOC 2 (планируется)

- **Security:** TLS 1.3, WAF, rate limit, audit.
- **Availability:** 99.9% uptime, multi-region.
- **Confidentiality:** zero-knowledge, zero-logging.
- **Privacy:** GDPR compliance (§13.1).

### 13.3. Open Source

- **License:** Apache-2.0.
- **Contributing:** `CONTRIBUTING.md`, DCO.
- **Code of Conduct:** Contributor Covenant.
- **Governance:** BDFL → foundation (future); RFC-процесс по образцу GOVERNANCE.md экосистемы.

---

## 14. Roadmap (детально)

### 14.1. v0.1 — Alpha (внутренний)

- **Цель:** proof of concept.
- **Функции:** `@t2em/protocol` (Mode A, Mode B, тест-векторы), `@t2em/relay-server` (Workers, Hono), Redis (Upstash), unit-тесты (≥ 60%).
- **Срок:** 4 недели.

### 14.2. v0.5 — Beta (закрытый)

- **Цель:** первые пользователи (5-10).
- **Функции:** CLI, Python SDK, MCP server, Web UI (базовый), `llms.txt`, integration-тесты.
- **Срок:** 8 недель.

### 14.3. v1.0 — Production (публичный)

- **Цель:** публичный запуск.
- **Функции:** всё из v0.5; security-аудит (внешний); load-тесты; E2E-тесты; документация (VitePress); Docker (self-hosted); Cloudflare Workers (managed).
- **Срок:** 12 недель.

### 14.4. v1.1 — Enhancements

- **Функции:**
  - Mode A с PreKeyBundle (X3DH, offline recipients) — через `wrapKeyForRecipient` из `@me2em/crypto` (уже реализован).
  - MCP: доработки `t2em_list_secrets`.
  - Web UI: QR-код для URL и для pubkey (Mode A).
  - CLI: `--json` output.
- **Срок:** 6 недель.

### 14.5. v2.0 — Ecosystem

- **Функции:**
  - **we2em SSO (OIDC RP):** «Login with we2em» для приватных дропов и managed secrets (PKCE S256; см. `TZ_we2em.md` §5.9).
  - **Key discovery через we2em:** разрешение pubkey получателя по entityId с аттестационной привязкой (`GET /api/v1/keys/:pubkey`); Mode A без ручного обмена ключами.
  - **Верификация Me2eM-сессий:** приём session token'ов с `aud=t2em.com`; верификация `Session.verifyAttested` (root pubkey из реестра we2em) + `RevocationChecker` на `GET we2em.com/api/v1/revocations/:jti`.
  - **Managed secrets:** долговременные секреты (TTL до 7 дней) — только в аутентифицированном режиме, хранение в Cloudflare R2 с клиентским шифрованием.
  - Интеграция с `@me2em/core` (Attestation, Session) — npm-зависимость.
  - `@me2em/pact` (криптографический аудит), `@me2em/x402` (платежи) — как внешние зависимости, когда выйдут.
  - Multi-region replication.
- **Срок:** 12 недель.

---

## 15. Риски и митигация

| Риск | Вероятность | Влияние | Митигация |
|---|---|---|---|
| **Redis compromise** | Низкая | Среднее | TTL ≤ 15 мин, RAM-only, TLS |
| **Workers cold start** | Средняя | Низкое | Bundle optimization, warm-up |
| **Rate limit bypass** | Средняя | Среднее | Multi-layer (Cloudflare + Redis) |
| **Supply chain attack** | Низкая | Высокое | Lockfile, audit, SBOM, signing |
| **Zero-day in crypto lib** | Низкая | Высокое | Audited libs (`@me2em/crypto`), monitor CVEs |
| **Cloudflare outage** | Низкая | Высокое | Multi-region (Upstash), status page |
| **GDPR violation** | Низкая | Высокое | Data minimization по построению (§13.1) |
| **Prompt injection** | Средняя | Среднее | MCP `secret_handle`, no plaintext in LLM |
| **SSRF через MCP** | Средняя | Высокое | Deny-list + DNS pinning + redirect policy (§8.4, §11.4) |
| **URL leakage** | Средняя | Среднее | `#fragment` not sent to server, `Cache-Control: no-store` |
| **Browser history** | Средняя | Среднее | Web UI: `#fragment` auto-clear, warning |
| **Key substitution (Mode A)** | Средняя | Высокое | Fingerprint-сверка, we2em-реестр в v2.0 |
| **Рассинхронизация TS/Python** | Средняя | Среднее | Общие тест-векторы в CI (§4.5) |

---

## 16. Команда и ресурсы

### 16.1. Роли (минимальная команда)

| Роль | FTE | Ответственность |
|---|---|---|
| **Tech Lead** | 1.0 | Архитектура, code review, roadmap |
| **Backend Engineer** | 1.0 | Relay server, API, Redis |
| **Frontend Engineer** | 0.5 | Web UI |
| **DevOps Engineer** | 0.5 | Cloudflare, CI/CD, monitoring |
| **Security Engineer** | 0.5 | Threat model, audit, pen-test |
| **Tech Writer** | 0.5 | Docs, `llms.txt`, examples |
| **QA Engineer** | 0.5 | E2E, load, chaos tests |

**Итого:** ~4.5 FTE.

### 16.2. Timeline (12 недель до v1.0)

| Неделя | Milestone |
|---|---|
| 1-2 | Setup, `@t2em/protocol` (Mode A/B, тест-векторы), unit tests |
| 3-4 | `@t2em/relay-server` (Workers), Redis, integration tests |
| 5-6 | CLI, Python SDK, MCP server (с SSRF-guard) |
| 7-8 | Web UI, `llms.txt`, docs |
| 9-10 | Security audit, load tests, chaos tests |
| 11 | Bug fixes, polish, Docker |
| 12 | Release v1.0, announcement |

### 16.3. Бюджет (оценка)

| Статья | Стоимость |
|---|---|
| **Cloudflare Workers** | $5/мес (paid plan) + $0.30/млн запросов |
| **Upstash Redis** | $0.20/100K команд (pay-as-you-go) |
| **Cloudflare R2** | $0.015/GB/мес (v2.0, managed secrets) |
| **Домен** | $10/год |
| **Security audit** | $20K-50K (внешний) |
| **Bug bounty** | $10K-50K/год |
| **Команда** | $500K-800K/год (4.5 FTE) |
| **Итого (год 1)** | ~$600K-900K |

**Note:** OpenSource + self-hosted → managed version бесплатна; монетизация — enterprise support, SLA, managed secrets (v2.0).

---

## 17. Критерии приёмки (v1.0)

### 17.1. Функциональные

- [ ] `POST /api/v1/drop` работает (Mode A, Mode B).
- [ ] `GET /s/:id` работает (JSON, HTML).
- [ ] `DELETE /api/v1/drop/:id` работает.
- [ ] `GET /llms.txt` доступен и сгенерирован из OpenAPI.
- [ ] `GET /openapi.json` доступен (OpenAPI 3.1).
- [ ] `GET /health` доступен.
- [ ] CLI: `push`, `pull`, `keygen`, `delete`; fingerprint получателя/отправителя в stderr.
- [ ] Python SDK: `push`, `pull_text`, `generate_x25519_keypair`; тест-векторы TS↔Python бит-в-бит.
- [ ] MCP: все 6 инструментов — `t2em_keygen`, `t2em_push`, `t2em_pull`, `t2em_http_request`, `t2em_wipe_secret`, `t2em_list_secrets`.
- [ ] Web UI: создание, fetch, расшифровка, QR-код pubkey.

### 17.2. Нефункциональные

- [ ] Latency p95 < 100ms (baseline 100 RPS).
- [ ] Throughput ≥ 1000 RPS (per region).
- [ ] Uptime ≥ 99.9% (30 дней).
- [ ] Unit-тесты ≥ 80% coverage.
- [ ] Integration-тесты проходят (включая TTL bounds 59/901 → 400).
- [ ] E2E-тесты проходят (Playwright).
- [ ] Load-тесты проходят (k6).
- [ ] Chaos-тесты проходят.
- [ ] Security-аудит пройден (no critical/high).
- [ ] Документация опубликована (VitePress).
- [ ] Docker image опубликован (GHCR).
- [ ] npm packages опубликованы (Provenance).
- [ ] PyPI package опубликован.

### 17.3. Безопасность

- [ ] Zero-knowledge подтверждён (audit).
- [ ] Zero-logging подтверждён (audit).
- [ ] `secureWipe` / `withSecureWipe` используются везде.
- [ ] TLS 1.3 only; HSTS preload; DNSSEC.
- [ ] Rate limit работает (+ заголовки `X-RateLimit-*`, `Retry-After`).
- [ ] `safeJsonParse` защищает от `__proto__`.
- [ ] Constant-time compare для delete token.
- [ ] `GETDEL` атомарен.
- [ ] No secrets in logs.
- [ ] No plaintext IP/UA; `sha256(ip)` только в rate-limit ключе с TTL 60 с.
- [ ] SSRF-guard: deny-list, DNS pinning, redirect policy — покрыты тестами.
- [ ] Тест-векторы `vectors/t2em-drop.v1.json` проходят в TS и Python.

### 17.4. OpenSource

- [ ] Apache-2.0 license.
- [ ] `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`.
- [ ] GitHub issues / PR templates.
- [ ] CI/CD публичный.
- [ ] SBOM генерируется.

---

## 18. Приложения

### A. Пример `docker-compose.yml` (self-hosted)

```yaml
version: "3.9"

services:
  relay:
    image: ghcr.io/me2em-org/t2em-relay:1.0.0
    ports:
      - "8080:8080"
    environment:
      - REDIS_URL=redis://redis:6379
      - BASE_URL=https://t2em.example.com
      - RATE_LIMIT_PER_MINUTE=60
      - MAX_PAYLOAD_BYTES=65536
      - TTL_MIN=60
      - TTL_MAX=900
    depends_on:
      - redis
    restart: unless-stopped
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL

  redis:
    image: redis:7-alpine
    command: redis-server --save "" --appendonly no --maxmemory 256mb --maxmemory-policy allkeys-lru
    restart: unless-stopped
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    tmpfs:
      - /data
```

### B. Пример GitHub Actions (CI/CD)

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v2
        with:
          version: 9
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: pnpm
      - run: pnpm install --frozen-lockfile
      - run: pnpm lint
      - run: pnpm test --coverage
      - run: pnpm build

  deploy-staging:
    needs: test
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: cloudflare/wrangler-action@v3
        with:
          apiToken: ${{ secrets.CLOUDFLARE_API_TOKEN }}
          environment: staging

  deploy-production:
    needs: deploy-staging
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
      - uses: cloudflare/wrangler-action@v3
        with:
          apiToken: ${{ secrets.CLOUDFLARE_API_TOKEN }}
          environment: production
```

### C. Пример `llms.txt` (полный)

```markdown
# t2em.com — Zero-Knowledge Token Transfer

## What is t2em?
t2em is a zero-knowledge relay for transferring tokens (API keys, PATs, secrets)
between entities. The server NEVER sees plaintext. Data lives in RAM-only Redis
with TTL <= 15 minutes and is destroyed atomically on first read (burn-after-reading).

## Quick Start (Agent)

1. Receive a URL: `https://t2em.com/s/{id}#{key}`
2. Fetch: `GET /s/{id}` with `Accept: application/json`
3. Decrypt locally:
   - If `mode == "sym"`: `AES-256-GCM(key, iv, ciphertext)`
   - If `mode == "x25519"`: `X25519 + HKDF-SHA256 + AES-256-GCM`

## Endpoints

### POST /api/v1/drop
Create a drop. Body: `{ envelope, ttl, burn_after_reading }`.
Returns: `{ id, url, expires_in, delete_token }`.
ttl: 60..900 seconds.

### GET /s/{id}
Fetch a drop. If `burn_after_reading: true`, atomic GETDEL.
Returns: `{ envelope }`.

### DELETE /api/v1/drop/{id}
Delete a drop. Header: `X-Delete-Token: {delete_token}`.
Returns: `{ deleted: true }`.

### GET /llms.txt
This file.

### GET /health
Health check.

## Envelope Format (Mode A)
{
  "v": 1,
  "mode": "x25519",
  "ephemeralPubKey": "<base64url 32B>",
  "ciphertext": "<base64url>",
  "iv": "<base64url 12B>"
}

## Envelope Format (Mode B)
{
  "v": 1,
  "mode": "sym",
  "ciphertext": "<base64url>",
  "iv": "<base64url 12B>"
}

## Recipient Keys (Mode A)
- Sender needs the recipient public key (X25519 or Ed25519).
- Verify key authenticity by comparing the fingerprint:
  `base64url(sha256(pubkey))[0..8]`.
- (v2.0) Resolve keys via we2em registry with attestation binding.

## Error Codes
- `400`: malformed request (bad JSON, missing fields, ttl out of 60..900, unknown envelope.v)
- `404`: not found / expired / already read (identical response for all three)
- `413`: payload too large (> 64 KB)
- `429`: rate limited (see X-RateLimit-* headers and Retry-After)
- `500`: internal error

## Rate Limits
- 60 req/min per IP
- Max payload: 64 KB
- TTL: 60..900 seconds

## CLI
$ echo "secret" | t2em-cli push --ttl 300
https://t2em.com/s/abc123#xyz789

$ t2em-cli pull "https://t2em.com/s/abc123#xyz789"
secret

## MCP
Tools: `t2em_keygen`, `t2em_push`, `t2em_pull`, `t2em_http_request`,
`t2em_wipe_secret`, `t2em_list_secrets`.
Secrets stay in `InMemorySecretVault`, never in LLM context.
`t2em_http_request` blocks private networks (SSRF guard); https only.

## Common Pitfalls
- DO NOT log the URL with `#fragment` (contains `sym_key`).
- DO NOT cache the URL (use `Cache-Control: no-store`).
- DO NOT reuse `sym_key` for multiple drops.
- DO NOT send secrets in query parameters (use POST body).
- DO NOT trust a recipient pubkey without fingerprint comparison.
```

### D. Глоссарий

| Термин | Определение |
|---|---|
| **Token** | Универсальная единица доступа: API token, PAT, session token |
| **Vault** | Эфемерное RAM-хранилище секретов |
| **Payload** | Полезная нагрузка дропа (зашифрованный секрет) |
| **Entity** | Отправитель или получатель |
| **Drop** | Одноразовая передача секрета |
| **Envelope** | JSON-контейнер с ciphertext |
| **Relay** | Сервер-ретранслятор (Blind Relay) |
| **Mode A** | Асимметричный E2EE (X25519) |
| **Mode B** | Zero-Key Bootstrap (#fragment URL) |
| **Burn-after-reading** | Атомарное удаление после первого чтения |
| **TTL** | Time-To-Live (v1: 60..900 с) |
| **Keyfile** | Файл с приватным ключом получателя (Mode A) |
| **Fingerprint** | `base64url(sha256(pubkey))[0..8]` — короткий отпечаток ключа |
| **PreKeyBundle** | Публичные ключи для X3DH (v2.0) |
| **Blind Relay** | Сервер, который передаёт ciphertext, не имея ключей расшифровки |

---

**Конец документа.**
