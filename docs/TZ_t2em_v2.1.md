# Техническое задание на разработку сервиса t2em.com

**Версия:** 2.1 (Final, revised)
**Статус:** Approved for implementation
**Дата:** 2026-11-13
**Продукт:** t2em (Token / Trust / Transit to EM)
**Домен:** t2em.com
**Экосистема:** Me2eM
**Слой:** Вертикальный продукт (транспорт секретов)
**Лицензия:** Apache-2.0
**Связанные документы:** `TZ_we2em.md` (we2em.com, IdP), `me2em-protocol/specs/v1.0.md` (нормативная спека протокола)

---

## 0. Сводка изменений относительно v2.0

| № | Изменение | Раздел |
|---|---|---|
| 1 | SSRF deny-list расширен до полного покрытия IPv4/IPv6 + альтернативных форматов; обязательное использование audited-библиотеки, а не ручного списка | §8.4, §11.4 |
| 2 | DNS pinning уточнён: резолв CNAME-chain до конца, игнор DNS TTL, pin всех A/AAAA, запрет прокси | §8.4 |
| 3 | `t2em_list_secrets` возвращает метаданные (`created_at`, `expires_at`, `label`) вместо голых handles | §8.4 |
| 4 | Fingerprint увеличен с 8 до **16 символов** base64url (96 бит; коллизия при ~2⁴⁸ ключей) | §4.2.1 |
| 5 | Python SDK: HKDF — **только** через PyCA `cryptography.hazmat.primitives.kdf.hkdf.HKDF`; альтернатива `hmac`/`hashlib` **удалена** | §8.3 |
| 6 | Rate limit: отдельный лимит на `POST /drop` (10/мин, 100/час на IP) + глобальный лимит активных дропов (1 млн) + лимит полей envelope | §5.1, §5.2 |
| 7 | GDPR-формулировка исправлена: `sha256(ip)` для IPv4 — **не** псевдонимизация, а персональные данные (legitimate interest) | §6.3, §13.1 |
| 8 | `@me2em/crypto` range уточнён: `>=1.1.0-rc.2 <2.0.0` (prerelease не удовлетворяет `^1.1.0`) | §3.5 |
| 9 | Публичный API `@t2em/protocol` зафиксирован явно | §3.6 |
| 10 | `ttl` — явно integer, `required` | §5.2 |
| 11 | `t2em-cli pull` — поведение newline зафиксировано (`--no-newline` флаг) | §8.2 |
| 12 | `t2em-cli keygen` — формат keyfile зафиксирован (raw 32B, base64url-encoded, JSON-wrapper) | §8.2 |
| 13 | `t2em_http_request` — HTTP-клиент зафиксирован (`undici` с pinned DNS) | §8.4 |
| 14 | `GET /s/:id` — content negotiation уточнён (default JSON, q-values) | §5.3 |
| 15 | Web UI — `#fragment` auto-clear + предупреждение зафиксированы | §9.6 |
| 16 | Добавлен раздел «Migration & Deprecation Policy» | §14.6 |
| 17 | Добавлен раздел «Disaster Recovery» | §14.7 |
| 18 | Добавлен раздел «Abuse Handling» | §14.8 |
| 19 | Добавлен раздел «Key Rotation» | §14.9 |
| 20 | Добавлен раздел «SLO / Error Budget» | §12.3 |
| 21 | Timeline увеличен с 12 до **16 недель** | §16.2 |
| 22 | Бюджет уточнён (assumptions: senior full-time) | §16.3 |
| 23 | Тест-векторы расширены (negative, edge, cross-mode) | §4.5 |
| 24 | `ttl` bounds: `ttl=59`/`ttl=901` → 400; `ttl` отсутствует → 400 | §5.2, §9.2 |
| 25 | Constant-time compare зафиксирован: `crypto.timingSafeEqual` | §5.4, §11.4 |

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
- **Не** хранит персональные данные в значимом объёме (см. §13.1).

---

## 2. Терминология

### 2.1. Термины протокола

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
| **TTL** | Time-To-Live, время жизни дропа (integer, 60..900 с) |
| **Keyfile** | JSON-файл с приватным ключом получателя (Mode A) |
| **Fingerprint** | 16-символьный base64url отпечаток pubkey для верификации вне канала |
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

**Правило зависимостей:** зависимости между пакетами строго вверх (`protocol → @me2em/crypto → @me2em/core`). Между продуктами t2em и we2em — **только runtime-интеграция по HTTP**; npm-зависимость `@t2em/* → @we2em/*` и наоборот запрещена.

**Версионная политика (уточнено):**

- `@me2em/crypto`: `>=1.1.0-rc.2 <2.0.0` — **не** `^1.1.0`, поскольку prerelease `1.1.0-rc.2` не удовлетворяет caret-range.
- `@me2em/core`: `>=1.0.0-rc.4 <2.0.0` — аналогично.
- Range `workspace:*` внутри монорепо t2em не используется — только `workspace:^`.

### 3.6. Публичный API `@t2em/protocol`

Пакет `@t2em/protocol` экспортирует **ровно** следующие функции (semver-major при изменении):

```typescript
// Envelope types
export interface EnvelopeV1 {
  v: 1;
  mode: 'x25519' | 'sym';
  ciphertext: string;        // base64url
  iv: string;                // base64url 12B
  ephemeralPubKey?: string;  // base64url 32B (Mode A only)
  senderSignature?: string;  // base64url 64B (optional)
  senderPubKey?: string;     // base64url 32B (optional)
}

// Pack: encrypt plaintext → envelope
export function packDrop(
  plaintext: Uint8Array,
  options:
    | { mode: 'sym' }
    | { mode: 'x25519'; recipientPubkey: Uint8Array }
): Promise<{ envelope: EnvelopeV1; symKey?: Uint8Array }>;

// Unpack: decrypt envelope → plaintext
export function unpackDrop(
  envelope: EnvelopeV1,
  options:
    | { mode: 'sym'; symKey: Uint8Array }
    | { mode: 'x25519'; recipientPrivkey: Uint8Array }
): Promise<Uint8Array>;

// Fingerprint: 16-char base64url of sha256(pubkey)
export function generateFingerprint(pubkey: Uint8Array): string;

// Validate envelope structure (throws CryptoError on invalid)
export function validateEnvelope(envelope: unknown): EnvelopeV1;

// Version constant (frozen)
export const PROTOCOL_VERSION = 1 as const;
export const HKDF_INFO_DROP = 'me2em/crypto/v1/t2em-drop' as const;
```

**Требование:** любое изменение сигнатуры или семантики — **breaking change** (semver-major 2.0.0) и **только** через новый envelope `v: 2` и новую HKDF info-строку.

---

## 4. Криптографическая спецификация (Protocol v1)

### 4.1. Стандарты

- **X25519** — RFC 7748.
- **HKDF-SHA256** — RFC 5869.
- **AES-256-GCM** — NIST SP 800-38D.
- **Ed25519** — RFC 8032 (для подписей, опционально).
- **Base64URL** — RFC 4648 §5 (без padding).

Реализация — исключительно на примитивах `@me2em/crypto`: `generateX25519KeyPair`, `x25519SharedSecret`, `ed25519PubToX25519`, `ed25519PrivToX25519`, `hkdfWithInfo`, `importAeadKey`, `encryptAead`, `decryptAead`, `signRaw`, `secureWipe`, `secureWipeMultiple`, `withSecureWipe`. Прямое использование `@noble/*` в прикладном коде запрещено — только через прослойку `@t2em/protocol`.

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

#### 4.2.1. Распределение ключей получателя

Mode A требует, чтобы отправитель достоверно знал pubkey получателя. В v1 поддерживаются каналы:

| Канал | Механизм | Достоверность |
|---|---|---|
| **Keyfile** | `t2em-cli keygen --out ./agent.key` печатает pubkey; получатель передаёт pubkey любым каналом | Ручная сверка отпечатка |
| **QR (Web UI)** | Web UI показывает pubkey и его QR-код | Визуальная сверка |
| **Fingerprint** | `fingerprint = base64url(sha256(pubkey))[0..16]` — **16 символов** для сверки голосом/в чате | Защита от подмены/MITM при сверке вне канала |
| **Реестр we2em (v2.0)** | `GET https://we2em.com/api/v1/keys/:pubkey` — pubkey, привязанный аттестацией владельца | Криптографическая (attestation) |

**Обоснование длины fingerprint:** 16 символов base64url = 96 бит. Коллизия при ~2⁴⁸ ≈ 281 трлн ключей (birthday paradox). Для сравнения: 8 символов (48 бит) дают коллизию уже при ~16 млн ключей, что делает fingerprint бесполезным для больших систем.

**Требование:** CLI при `push --to <pubkey>` выводит отпечаток получателя в stderr. `t2em-cli pull` в Mode A выводит отпечаток отправителя, если присутствует `senderPubKey`.

### 4.3. Mode B: Zero-Key Bootstrap (#fragment URL)

**Когда:** получатель не имеет предварительного обмена ключами.

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

**Ограничение (фиксируется честно):** JavaScript GC может сохранять копии. `secureWipe` — **mitigation**, не гарантия. Для high-security use cases — non-extractable `CryptoKey` или hardware-backed keys (HSM/Secure Enclave).

### 4.5. Версионирование, тест-векторы и таксономия ошибок

- **Freeze-правило:** HKDF info-строка `"me2em/crypto/v1/t2em-drop"`, поле `envelope.v` и любые строки, влияющие на деривацию ключей, изменяются **только** через новую версию `/v2`. Изменение существующих строк — breaking change, запрещено.
- **Таксономия ошибок:** криптографические ошибки выбрасываются как `CryptoError` из `@me2em/crypto` с полями `code`/`level`. Ожидаемые коды: `UNSUPPORTED_VERSION`, `MALFORMED`, `INVALID_LENGTH`, `INVALID_IV`, `DECRYPTION_FAILED`. Интеграция — по полям `code`/`level`.
- **Тест-векторы:** `@t2em/protocol` публикует `vectors/t2em-drop.v1.json` (Mode A и Mode B), бит-в-бит совместимые между TypeScript и Python-реализациями.

**Обязательный набор тест-векторов:**

| Категория | Векторы |
|---|---|
| **Positive** | Mode A (X25519, Ed25519-converted), Mode B (sym), с `senderSignature`, с `senderPubKey` |
| **Negative** | Невалидный `v` (0, 2, "1", null), невалидный `mode` ("ecies", "", null), ciphertext короче 16B (нет tag), iv ≠ 12B, ephemeralPubKey ≠ 32B (Mode A), sym envelope с `ephemeralPubKey` |
| **Edge cases** | Пустой plaintext (0 байт), plaintext 64 KB (максимум), plaintext 64 KB + 1 байт (должен упасть на уровне API) |
| **Cross-mode** | Mode A envelope, переданный как Mode B (должен упасть на `unpackDrop`), Mode B envelope с `recipientPrivkey` (должен упасть) |

---

## 5. API-спецификация

### 5.1. Общие требования

- **Base URL:** `https://t2em.com/api/v1`
- **Content-Type:** `application/json`
- **Character encoding:** UTF-8
- **Auth:** не требуется для `POST /drop` (zero-knowledge); опционально — для приватных дропов (v2.0, через we2em SSO).
- **Rate limit (уточнено):**
  - `POST /api/v1/drop`: **10/мин** на IP, **100/час** на IP.
  - `GET /s/:id`: 60/мин на IP.
  - `DELETE /api/v1/drop/:id`: 60/мин на IP.
  - Глобальный лимит активных дропов: **1 000 000** (алерт при 80%).
  - Ответы 429 включают заголовки `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `Retry-After`.
- **Max payload:** 64 KB. **Max fields in envelope:** 10 (защита от JSON-бомб).
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
| `envelope` | object | Да | Зашифрованный контейнер (≤ 10 полей) |
| `envelope.v` | number | Да | Версия протокола (1) |
| `envelope.mode` | string | Да | `"x25519"` или `"sym"` |
| `envelope.ciphertext` | string | Да | Base64url AES-GCM ciphertext (≥ 16B tag) |
| `envelope.iv` | string | Да | Base64url 12B IV |
| `envelope.ephemeralPubKey` | string | Mode A | Base64url 32B |
| `envelope.senderSignature` | string | Нет | Base64url 64B Ed25519 |
| `envelope.senderPubKey` | string | Нет | Base64url 32B Ed25519 |
| `ttl` | integer | **Да** | **60..900** секунд. Отсутствие → 400. Дробное → 400. `59`/`901` → 400 |
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
| `400 Bad Request` | Невалидный JSON, отсутствуют поля, неверный `ttl`, `envelope.v` ≠ 1, envelope > 10 полей |
| `413 Payload Too Large` | Envelope > 64 KB |
| `429 Too Many Requests` | Rate limit (`X-RateLimit-*`, `Retry-After`) |
| `503 Service Unavailable` | Глобальный лимит активных дропов исчерпан |
| `500 Internal Server Error` | Ошибка Redis |

### 5.3. `GET /s/:id` — получение дропа

**Request:**

```http
GET /s/550e8400-e29b-41d4-a716-446655440000 HTTP/1.1
Host: t2em.com
Accept: application/json
```

**Content negotiation:**

- `Accept: application/json` или `Accept: */*` или отсутствует → JSON (default).
- `Accept: text/html` (q-value > JSON) → Web UI.
- `Accept: text/html;q=0.9, application/json;q=0.1` → Web UI (q-values соблюдаются).

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

**Анти-перечисление:** 404 для «не существует», «истёк» и «уже прочитан» — идентичен по телу **и времени ответа** (constant-time path; тест в §9.3).

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

**Поведение:** `X-Delete-Token` сравнивается с `sha256(delete_token)` через **`crypto.timingSafeEqual`** (constant-time). Неверный токен → 403, отсутствует → 401, дроп не существует → 404.

**Ошибки:**

| Код | Причина |
|---|---|
| `401 Unauthorized` | Отсутствует `X-Delete-Token` |
| `403 Forbidden` | Неверный `X-Delete-Token` |
| `404 Not Found` | Дроп не существует |

### 5.5. `GET /llms.txt` — документация для AI-агентов

Полный текст — Приложение C. **Требование:** `llms.txt` генерируется автоматически из OpenAPI + шаблона `docs/llms.template.md` при сборке (не редактируется вручную — защита от рассинхронизации).

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

**Требование:** публиковать `GET /openapi.json` — полная OpenAPI 3.1 спецификация. `Cache-Control: public, max-age=300`.

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
KEY: ratelimit:{ip_hash}:{endpoint}:{window}
VALUE: counter
TTL: 60 (minute window) или 3600 (hour window)
TYPE: string (INCR + EXPIRE)

# Глобальный счётчик активных дропов
KEY: global:active_drops
VALUE: counter
TYPE: string (INCR/DECR при создании/удалении)
```

### 6.2. Что хранится

| Данные | Где | Шифрование | TTL |
|---|---|---|---|
| Envelope (ciphertext) | Redis `drop:{id}` | AES-GCM (клиентом) | ≤ 900 s |
| Delete token hash | Redis `delete:{id}` | sha256 | ≤ 900 s |
| Rate limit counter | Redis `ratelimit:*` | — | 60 s / 3600 s |
| Global active drops | Redis `global:active_drops` | — | — |

### 6.3. Что **не** хранится (Zero-Knowledge)

| Данные | Почему |
|---|---|
| Plaintext секрета | Zero-knowledge: сервер не видит |
| `sym_key` (Mode B) | В `#fragment` URL, не передаётся |
| `eph_priv`, `shared_secret`, `aes_key` | Только у клиента |
| Тела запросов | Zero-logging |
| User-Agent | Zero-logging (в security-логах — только `sha256(user-agent)`, опционально) |
| Метаданные (кто, кому) | Не хранятся |
| IP-адреса в plaintext | Не хранятся. Для rate limit — ключ `sha256(ip)`, живёт 60 с / 3600 с |

**GDPR-формулировка (исправлено):** `sha256(ip)` **не является** псевдонимизацией в смысле ст. 4(5) GDPR для IPv4 (перебирается за секунды на GPU: 2³² = 4 млрд). Это **полные персональные данные**, обрабатываемые на основании **legitimate interest** (ст. 6(1)(f) GDPR) исключительно для защиты сервиса от злоупотреблений. TTL 60 с (minute window) / 3600 с (hour window) — минимум, необходимый для rate limit. Данные не выгружаются в логи, не коррелируют между окнами, не передаются третьим лицам. Для IPv6 (`2¹²⁸`) хэш **является** псевдонимизацией.

### 6.4. Гарантии

- **Атомарность:** `GETDEL` гарантирует, что дроп будет прочитан ровно один раз (при `burn_after_reading: true`).
- **Эфемерность:** Redis без persistence (RDB/AOF отключены). Даже при компромиссе Redis — только ciphertext, TTL ≤ 15 мин.
- **Zero-logging:** Cloudflare Workers не логируют тела запросов. Upstash Redis не логирует значения.
- **Durability:** **не гарантируется.** При падении Redis все активные дропы теряются (см. §14.7).

---

## 7. Сценарии использования

### 7.1. User Journey: человек → AI-агент (через Web UI)

**Персона:** Алиса — разработчица, хочет передать GitHub PAT своему AI-агенту (Claude Code) в sandbox.

1. **Алиса открывает** `https://t2em.com`.
2. **Вставляет PAT**, выбирает TTL (5 мин, default).
3. **Нажимает «Create Drop»**.
4. **Сервер возвращает** URL: `https://t2em.com/s/abc123#xyz789`.
5. **Алиса копирует URL** и вставляет в чат с агентом.
6. **Агент (Claude Code)** вызывает MCP-tool `t2em_pull(url)`.
7. **MCP-сервер** делает `GET /s/abc123` → envelope.
8. **MCP-сервер** расшифровывает envelope с `xyz789` (из `#fragment`) → PAT.
9. **MCP-сервер** сохраняет PAT в `InMemorySecretVault`, возвращает `secret_handle`.
10. **Агент** вызывает `t2em_http_request` с `{{secret_handle}}` → GitHub API.
11. **MCP-сервер** подставляет PAT, делает запрос, возвращает ответ.
12. **Агент** вызывает `t2em_wipe_secret` → PAT уничтожен.
13. **Сервер** уже удалил envelope (GETDEL).

**Гарантии:** PAT **не** в чате, **не** в LLM, **не** на сервере. Живёт ≤ 5 мин.

### 7.2. User Journey: CI/CD → deployment

**Персона:** Боб — DevOps, передаёт `DB_PASSWORD` в production deployment.

1. **Боб** запускает:
   ```bash
   $ echo "$DB_PASSWORD" | t2em-cli push --ttl 300
   https://t2em.com/s/abc123#xyz789
   ```
2. **Боб** сохраняет URL в CI/CD secret.
3. **Pipeline**:
   ```bash
   $ export DB_PASSWORD=$(t2em-cli pull "$T2EM_URL")
   $ ./deploy.sh
   ```
4. **`t2em-cli pull`** делает `GET /s/abc123`, расшифровывает, выводит в stdout (без trailing newline).
5. **Envelope** удалён (GETDEL).

**Гарантии:** пароль **не** в логах, **не** на сервере. Живёт ≤ 5 мин.

### 7.3. User Journey: IoT device provisioning

**Персона:** Карл — IoT-инженер, provision 1000 устройств.

1. **Карл** генерирует 1000 ключей:
   ```bash
   $ echo "$API_KEY" | t2em-cli push --ttl 900 --out urls/device-$i.txt
   ```
   *(Лимит v1 — 900 с. Устройство обязано выполнить первый boot и pull в течение 15 минут. Для отложенного provisioning — повторный push или v2.0 managed secrets.)*
2. **Устройства** при первом boot:
   ```bash
   $ API_KEY=$(t2em-cli pull "$(cat /boot/t2em-url.txt)")
   $ echo "API_KEY=$API_KEY" >> /etc/device.conf
   ```
3. **Envelope** удалён.

**Гарантии:** ключи **не** в прошивке, **не** на сервере. Живут ≤ 15 мин.

### 7.4. User Journey: agent → agent (MCP federation)

**Персона:** Агент A (research) передаёт intermediate results Агенту B (writer).

1. **Агент A** вызывает `t2em_push(payload, ttl=300)`.
2. **MCP-сервер A** шифрует payload на pubkey Агента B (Mode A).
3. **MCP-сервер A** возвращает URL.
4. **Агент A** передаёт URL Агенту B.
5. **Агент B** вызывает `t2em_pull(url)`.
6. **MCP-сервер B** расшифровывает, сохраняет в vault, возвращает `secret_handle`.

**Гарантии:** payload **не** в общем чате, **не** на сервере. Живёт ≤ 5 мин.

---

## 8. Требования к реализации

### 8.1. API-First

- **Все операции** — через JSON-эндпоинты.
- **Никакого парсинга HTML** для программного доступа.
- **OpenAPI 3.1** спецификация на `GET /openapi.json`.
- **Content negotiation** (см. §5.3).

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
t2em: recipient fingerprint: 9f86d08e1a2b3c4d (stderr)
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

**Формат keyfile (уточнено):**

```json
{
  "version": 1,
  "type": "x25519",
  "privateKey": "<base64url 32B>",
  "publicKey": "<base64url 32B>",
  "createdAt": "2026-11-13T14:32:00Z",
  "fingerprint": "<16-char base64url>"
}
```

Права файла: `0600`. При чтении — проверка прав; если > `0600` — предупреждение в stderr.

**Поведение `pull` (уточнено):**

- По умолчанию: пишет **ровно** plaintext в stdout, **без** добавления newline.
- Если plaintext заканчивается newline — сохраняется как есть.
- Флаг `--newline` — добавляет `\n` после plaintext (для `$(...)` use cases, где newline нужен).
- Диагностика (fingerprint, прогресс) — **только** в stderr.

**Требования:**

- **UNIX-пайпы:** stdin/stdout для shell-скриптов.
- **Переменные окружения:** `T2EM_BASE_URL` (default `https://t2em.com`).
- **Exit codes:** 0 — успех, 1 — ошибка, 2 — невалидный аргумент.
- **Секреты не в аргументах:** `--secret` запрещён, только stdin.
- **`secureWipe`** после использования ключей.
- **`mlock`** — опционально (флаг `--mlock`, Linux only).

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

**Требования (уточнено):**

- **Сетевые вызовы:** только stdlib `urllib` — никаких `requests`/`httpx`.
- **Криптография:** единственная внешняя криптозависимость — **PyCA `cryptography`** (version range: `>=42,<44`). Все криптопримитивы — **только** через `cryptography`:
  - X25519: `cryptography.hazmat.primitives.asymmetric.x25519`
  - AES-GCM: `cryptography.hazmat.primitives.ciphers.aead.AESGCM`
  - HKDF: `cryptography.hazmat.primitives.kdf.hkdf.HKDF` (RFC 5869)
  - Random: `secrets.token_bytes`
  - **Альтернатива `hmac`/`hashlib` для HKDF — ЗАПРЕЩЕНА** (дублирует audited реализацию, нарушает §11.2).
- **Bit-compatible** с TypeScript-протоколом: те же base64url, HKDF, AES-GCM; проверка на общих тест-векторах `vectors/t2em-drop.v1.json` в CI.
- **Type hints:** полные аннотации.
- **Python ≥ 3.10.**

### 8.4. MCP Server (`@t2em/mcp-server`)

**Установка:**

```bash
npm install -g @t2em/mcp-server
```

**Tools (6):**

| Tool | Параметры | Возвращает |
|---|---|---|
| `t2em_keygen` | — | `{ public_key, key_id, fingerprint }` (privkey в vault) |
| `t2em_push` | `{ secret, ttl?, recipient_pubkey?, label? }` | `{ url, delete_token? }` |
| `t2em_pull` | `{ url, label? }` | `{ secret_handle }` |
| `t2em_http_request` | `{ url, method, headers?, body? }` | `{ status, headers, body }` |
| `t2em_wipe_secret` | `{ secret_handle }` | `{ ok }` |
| `t2em_list_secrets` | — | `{ secrets: [{ handle, label?, created_at, expires_at }] }` |

**Требования:**

- **InMemorySecretVault:** секреты в RAM процесса MCP, не в LLM-контексте.
- **`secret_handle`:** строка `sec_<uuid>`.
- **`label`:** опциональная метка (например, `"github-token"`), задаётся при `t2em_pull`/`t2em_push`, возвращается в `t2em_list_secrets`. **Не** секрет.
- **`t2em_http_request`:** подстановка `{{secret_handle}}` в headers/body.
- **HTTP-клиент:** **`undici`** (Node.js stdlib `fetch` не даёт контроля над DNS). Pinned DNS через `undici.Agent({ connect: { lookup: pinnedLookup } })`.

**SSRF-защита `t2em_http_request` (обязательно):**

- **Схема:** только `https`.
- **Deny-list (полный):**

  **IPv4:**
  ```
  0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8,
  169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24,
  192.88.99.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24,
  203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4, 255.255.255.255/32
  ```

  **IPv6:**
  ```
  ::/128, ::1/128, ::ffff:0:0/96, 64:ff9b::/96, 100::/64,
  2001:db8::/32, 2002::/16, fc00::/7, fe80::/10, ff00::/8
  ```

- **Альтернативные форматы IP:** decimal (`2130706433`), octal (`0177.0.0.1`), hex (`0x7f.0.0.1`), mixed — **все** конвертируются в canonical IPv4/IPv6 **до** проверки deny-list.
- **Библиотека:** **обязательно** использовать audited-библиотеку (например, `ssrf-req-filter` или эквивалент), а не ручной deny-list. Ручной список **всегда** будет неполным.
- **DNS pinning:**
  - Резолв CNAME-chain до конца (не только первый ответ).
  - Игнорировать DNS TTL (всегда использовать pinned IP).
  - Pin **все** A и AAAA записи.
  - Соединение — только к pinned IP.
- **Прокси:** **запрещён** для `t2em_http_request` (pinning обходится через `HTTP_PROXY`/`HTTPS_PROXY`).
- **Редиректы:** не следовать автоматически; каждый редирект — новое решение с повторной проверкой назначения (полный SSRF-цикл).
- **Timeout:** connect 5s, total 30s.
- **Max response size:** 10 MB.

- **Zero-logging:** MCP не логирует секреты.
- **`secureWipe`** после `t2em_wipe_secret`.

### 8.5. Токенизация для LLM

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
- **Bot management:** allowlist для known AI-агентов, challenge для остальных.
- **Rate limiting:** Cloudflare Rate Limiting Rules (per IP, per endpoint) + Redis-based (per IP, per endpoint — см. §5.1).
- **Cache rules:** `Cache-Control: no-store` для API; кэширование только `/llms.txt`, `/openapi.json`, `/health` (короткий TTL).
- **Transform Rules:** HTTPS redirect; удаление `Server` header; `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`.
- **Cloudflare Workers:**
  - Runtime: `workerd`.
  - Framework: Hono.
  - Cold start: ≤ 50ms (цель).
  - Bundle size: ≤ 1 MB.
- **Upstash Redis:**
  - REST API.
  - Global replication.
  - TLS 1.3.
  - No persistence.
- **Cloudflare R2 (опционально, v2.0):**
  - Managed secrets (TTL до 7 дней, аутентифицированный режим).
  - Private buckets, presigned URLs (TTL 60s).

### 8.7. Мониторинг и наблюдаемость

- **Метрики (Cloudflare Analytics):**
  - Request rate, error rate, latency (p50, p95, p99).
  - Drop creation/fetch/expiry rate.
  - Rate limit hits (per endpoint).
  - Active drops count (для глобального лимита).
- **Логи (структурированные, без секретов):**
  - `{ timestamp, level, event, dropId, mode, ttl, status, latencyMs }`.
  - **Никогда:** plaintext, ciphertext, `sym_key`, plaintext IP (только `sha256(ip)`), plaintext User-Agent.
- **Алерты:**
  - Error rate > 1% (5 min window).
  - Latency p99 > 500ms.
  - Redis unavailable.
  - Active drops > 800 000 (80% от глобального лимита).
  - Rate limit hits > 1000/min.
- **Distributed tracing (опционально):** OpenTelemetry + Cloudflare Workers Trace Events.

### 8.8. CI/CD

- **GitHub Actions:**
  - Lint (ESLint, Prettier).
  - Test (Vitest, coverage ≥ 80%).
  - **Cross-language test-vectors:** TS↔Python на `vectors/t2em-drop.v1.json`.
  - Build (TypeScript, `wrangler build`).
  - Deploy (staging → production, manual approval).
- **Wrangler:** `wrangler deploy`, `wrangler secret put`.
- **Docker:** `docker build` + `docker push` (GHCR), `docker compose up -d`.
- **Versioning:** SemVer, CHANGELOG.md, Git tags (`<pkg>-v<version>`).
- **Release process:**
  1. PR → CI (lint, test, build, test-vectors).
  2. Merge to `main` → deploy to staging.
  3. Smoke tests (E2E: create → fetch → verify).
  4. Manual approval → deploy to production.
  5. Post-deploy: health check, canary (5% traffic).
- **Supply chain:** `pnpm audit` blocking, gitleaks, CodeQL, SBOM (CycloneDX), npm Provenance.

---

## 9. Тестирование

### 9.1. Unit-тесты

**Покрытие:** ≥ 80% (строки), ≥ 70% (ветки).

**Что тестируется:**

- `@t2em/protocol`:
  - `packDrop`/`unpackDrop` (Mode A, Mode B) — на **всех** тест-векторах (§4.5).
  - X25519 ECDH, HKDF, AES-GCM.
  - Ed25519↔X25519 конверсия.
  - `secureWipe` (буферы занулены).
  - `validateEnvelope` (negative vectors).
  - `generateFingerprint` (16 символов, детерминизм).
- `@t2em/relay-server`:
  - API handlers (mock Redis).
  - Rate limiting (drop/fetch/delete — разные лимиты).
  - Global active drops counter.
  - Error handling (4xx/5xx).
  - `GETDEL` atomicity.
  - Constant-time compare (`timingSafeEqual`).
- `@t2em/cli`: argument parsing, stdin/stdout, newline behavior, exit codes.
- `@t2em/mcp-server`: tool handlers, `InMemorySecretVault`, `secret_handle`, `label`, SSRF-guard (deny-list, альтернативные форматы IP, CNAME, redirects, proxies).

### 9.2. Integration-тесты

- E2E: `POST /drop` → `GET /s/:id` → decrypt → verify plaintext.
- E2E: `POST /drop` (burn_after_reading) → `GET /s/:id` → `GET /s/:id` (404).
- E2E: `DELETE /drop/:id` с правильным/неправильным/отсутствующим `X-Delete-Token`.
- Rate limit: 11-й `POST /drop` за минуту → 429 (не 61-й — отдельный лимит).
- Rate limit: 101-й `POST /drop` за час → 429.
- TTL expiry: drop с TTL 60s → через 61s → 404.
- Payload size: 65 KB → 413.
- **TTL bounds:** `ttl=59` → 400; `ttl=901` → 400; `ttl` отсутствует → 400; `ttl=300.5` → 400.
- **Envelope fields:** 11 полей → 400.
- Concurrent GETDEL: 10 параллельных `GET /s/:id` → 1 успех, 9 × 404.
- Global active drops: достижение 1 000 000 → 503 на `POST /drop`.

**Инструменты:** Vitest + Miniflare + Redis mock (или testcontainers).

### 9.3. Security-тесты

- **Fuzzing:** `POST /drop` с случайными payload (10 000 итераций).
- **Replay:** повторный `GET /s/:id` → 404.
- **Timing attack:**
  - Delete token: constant-time compare (`timingSafeEqual`).
  - 404 path: одинаковое время ответа для «не существует»/«истёк»/«прочитан» (статистический тест, 10 000 запросов, p < 0.01).
- **XSS:** Web UI — санитизация.
- **CSRF:** API не использует cookies (только заголовки) — CSRF не применим.
- **Injection:** JSON parse с `__proto__` → отклоняется (`safeJsonParse`).
- **DoS:** Rate limit, max payload, max TTL, envelope field limit.
- **SSRF (расширено):**
  - Metadata-эндпоинты (`169.254.169.254`).
  - Localhost (`127.0.0.1`, `::1`).
  - Приватные диапазоны (полный deny-list §8.4).
  - Альтернативные форматы IP (`2130706433`, `0177.0.0.1`, `0x7f.0.0.1`).
  - DNS rebinding (CNAME chain, TTL=0, разные A/AAAA).
  - Redirect в приватную сеть (первый хоп публичный, второй — приватный).
  - Прокси (`HTTP_PROXY` env — должен игнорироваться).
  - Все → отклоняются.

### 9.4. Load-тесты

**Инструменты:** k6, Artillery.

**Сценарии:**

- **Baseline:** 100 RPS, 1 минута, p95 < 100ms.
- **Peak:** 1000 RPS, 1 минута, p95 < 500ms.
- **Spike:** 0 → 5000 RPS за 10 секунд, p95 < 1s.

**Цели:** error rate < 0.1%; latency p99 < 1s; no memory leaks.

### 9.5. Chaos-тесты

- Redis unavailable → 503, не падает.
- Redis slow (p99 > 1s) → timeout, 503.
- Network partition → retry с exponential backoff (CLI/SDK).
- Worker crash → Cloudflare auto-restart, no data loss (Redis external).
- **Global active drops overflow** → 503 на `POST /drop`, 200 на `GET`/`DELETE`.

### 9.6. E2E-тесты (Playwright)

- **Web UI:**
  - Создание дропа (Mode B) → URL с `#fragment`.
  - Fetch → расшифровка в браузере.
  - Burn-after-reading (второй fetch → 404).
  - **`#fragment` auto-clear:** после расшифровки URL в адресной строке заменяется на `https://t2em.com/s/{id}` (без `#fragment`); history entry **не содержит** `sym_key`.
  - **Предупреждение:** перед показом plaintext — модальное окно «URL содержит ключ расшифровки. Не делитесь им.»
  - QR-код pubkey (Mode A).
- **CLI:** `push` → URL; `pull` → plaintext (без trailing newline); `pull --newline` → с newline; `keygen` → keypair (JSON-формат §8.2); fingerprint в stderr.
- **MCP:** `t2em_keygen` → pubkey + fingerprint; `t2em_pull(url, label)` → `secret_handle` + label; `t2em_list_secrets` → список с метаданными; `t2em_http_request` → mock HTTPS server + отклонение SSRF-целей; `t2em_wipe_secret` → handle removed.

---

## 10. Документация

### 10.1. Обязательные документы

| Документ | Формат | Аудитория |
|---|---|---|
| `README.md` | Markdown | Разработчики, DevOps |
| `docs/` | VitePress | Все |
| `llms.txt` | Plain text | AI-агенты |
| `llms.template.md` | Markdown | (шаблон для генерации) |
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
│   ├── quickstart.md
│   ├── cli.md
│   ├── python-sdk.md
│   └── mcp.md
├── concepts/
│   ├── zero-knowledge.md
│   ├── modes.md
│   ├── key-distribution.md       — Распределение ключей (fingerprint, keyfile, QR)
│   ├── ttl.md
│   └── threat-model.md
├── api/
│   ├── reference.md
│   ├── errors.md
│   └── rate-limits.md
├── deployment/
│   ├── cloudflare.md
│   ├── docker.md
│   └── configuration.md
├── security/
│   ├── audit.md
│   ├── reporting.md
│   └── best-practices.md
└── guides/
    ├── ai-agents.md
    ├── ci-cd.md
    ├── iot.md
    └── agent-to-agent.md
```

### 10.3. `llms.txt`

Генерируется автоматически из OpenAPI + шаблона `docs/llms.template.md`. Полный текст — Приложение C. Содержит: overview; quick start (3 шага); endpoints с примерами; Mode A vs Mode B; распределение ключей (fingerprint 16 chars, keyfile); криптографию (кратко); error codes; rate limits; examples (curl, Python, TypeScript); common pitfalls.

### 10.4. Примеры (examples/)

| Пример | Язык | Назначение |
|---|---|---|
| `basic-push-pull/` | TypeScript | Простой push/pull |
| `mode-a-x25519/` | TypeScript | Mode A с X25519 + fingerprint-сверка |
| `cli-ci-cd/` | Bash | GitHub Actions |
| `mcp-claude-code/` | TypeScript | Claude Code |
| `python-langgraph/` | Python | LangGraph agent |
| `iot-provisioning/` | Bash | IoT provisioning (TTL ≤ 900 с) |
| `agent-to-agent/` | TypeScript | Agent → Agent transfer |

---

## 11. Требования к безопасности

### 11.1. Zero-Knowledge

- **Сервер не имеет ключей** для расшифровки envelope.
- **Сервер не логирует** тела запросов.
- **Сервер не хранит** plaintext IP (только `sha256(ip)` в rate-limit ключе, TTL 60/3600 с — см. §6.3).
- **Сервер не хранит** User-Agent (в security-логах — только `sha256(user-agent)`, опционально).

### 11.2. Криптография

- **X25519:** RFC 7748, через `@me2em/crypto`.
- **HKDF-SHA256:** RFC 5869, `hkdfWithInfo`.
- **AES-256-GCM:** NIST SP 800-38D, WebCrypto.
- **Ed25519:** RFC 8032, `signRaw`.
- **Random:** `crypto.getRandomValues` (обёртка `randomBytes`).
- **Base64URL:** `@scure/base` (audited).

**Запрещено:** hand-rolled crypto; `Math.random()` для секретов; ECB mode; IV reuse; truncated MAC (< 128 bit); прямое использование `@noble/*` вне `@t2em/protocol`; альтернатива `hmac`/`hashlib` для HKDF в Python SDK.

### 11.3. Гигиена памяти

- **`secureWipe`/`withSecureWipe`:** двухпроходное затирание (random + zeros).
- **`mlock`:** опционально для CLI (`--mlock`).
- **Non-extractable `CryptoKey`:** для Web UI (если возможно).

### 11.4. Защита от атак

| Атака | Защита |
|---|---|
| **Replay** | `GETDEL` (атомарно), `burn_after_reading` |
| **MITM** | TLS 1.3, HSTS, DNSSEC, `senderSignature`, fingerprint-сверка (16 chars) |
| **Timing** | `timingSafeEqual` (delete token); идентичный 404-путь (тест §9.3) |
| **XSS** | CSP, `X-Content-Type-Options: nosniff` |
| **CSRF** | Bearer-заголовки (не cookies) |
| **Injection** | `safeJsonParse` (`__proto__`) |
| **DoS** | Rate limit (drop/fetch/delete — разные), max payload, max TTL, envelope field limit, global active drops |
| **SSRF** | Полный deny-list (IPv4/IPv6, альтернативные форматы), DNS pinning (CNAME chain, TTL ignore, все A/AAAA), redirect policy, proxy ban, audited библиотека |
| **Enumeration** | UUID v4; идентичный 404 (тело + время) |
| **Fingerprinting** | Удаление `Server` header |
| **Prompt injection** | MCP `secret_handle` (не plaintext в LLM) |
| **Key substitution** | Fingerprint 16 chars + we2em-реестр (v2.0) |

### 11.5. Supply chain

- **Dependencies:** `@me2em/crypto` (транзитивно `@noble/*`, `@scure/*`, `hash-wasm`), PyCA `cryptography` (`>=42,<44`), `undici`.
- **Audit:** `pnpm audit` blocking, Snyk/Dependabot.
- **Lockfile:** `pnpm-lock.yaml` коммитится.
- **SBOM:** CycloneDX в CI.
- **Signing:** npm Provenance.

### 11.6. Аудит

- **Внешний аудит:** перед v1.0 (Trail of Bits / Cure53 / NCC Group).
- **Bug bounty:** HackerOne / Immunefi (после v1.0).
- **Responsible disclosure:** `SECURITY.md`.
- **CVE:** MITRE.

---

## 12. Производительность и SLO

### 12.1. Цели производительности

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

- Edge compute (Workers).
- Redis multi-region (Upstash).
- Bundle: tree-shaking, minification.
- Caching: `/llms.txt`, `/openapi.json` — `public, max-age=300`.
- Compression: Brotli.

### 12.3. SLO / Error Budget

| SLO | Цель | Error budget (30 дней) |
|---|---|---|
| **Availability** | 99.9% | 43 минуты |
| **Latency p95** | < 100ms | 5% запросов |
| **Error rate** | < 0.1% | 0.1% запросов |

**При исчерпании error budget:**

1. **Freeze feature releases** — только bug fixes и reliability improvements.
2. **Post-mortem** — обязательный, с action items.
3. **Уведомление** — status page + email подписчикам.

---

## 13. Соответствие (Compliance)

### 13.1. GDPR

**Ключевой тезис:** t2em в v1 **не обрабатывает персональные данные в значимом объёме** — по построению:

- Нет учётных записей, сущностей, email, телефонов, plaintext IP.
- Единственная категория — `sha256(ip)` в rate-limit ключах (TTL 60/3600 с, не логируются). Для IPv4 — **персональные данные** (перебирается), обрабатываются на основании **legitimate interest** (ст. 6(1)(f) GDPR) для защиты сервиса. Для IPv6 — псевдонимизация.
- Права на доступ/забвение/переносимость (ст. 15–20) выполняются **архитектурно**: персональных данных, подлежащих выдаче/удалению, не существует.

**v2.0 (аутентифицированный режим через we2em):** субъекты идентифицируются через we2em.com (IdP); учётные записи, удаление и экспорт — зона ответственности we2em. t2em по-прежнему не хранит профилей: сессии валидируются stateless, привязки «аккаунт → дроп» нет.

- **Audit retention:** security-логи без plaintext IP/UA — 90 дней (настраивается).

### 13.2. SOC 2 (планируется)

- Security, Availability, Confidentiality, Privacy — см. §11, §12, §13.1.

### 13.3. Open Source

- **License:** Apache-2.0.
- **Contributing:** `CONTRIBUTING.md`, DCO.
- **Code of Conduct:** Contributor Covenant.
- **Governance:** BDFL → foundation (future); RFC-процесс.

---

## 14. Roadmap

### 14.1. v0.1 — Alpha (внутренний)

- `@t2em/protocol` (Mode A, Mode B, тест-векторы §4.5), `@t2em/relay-server` (Workers, Hono), Redis, unit-тесты (≥ 60%).
- **Срок:** 5 недель.

### 14.2. v0.5 — Beta (закрытый)

- CLI, Python SDK, MCP server (с SSRF-guard), Web UI (базовый), `llms.txt`, integration-тесты.
- **Срок:** 10 недель.

### 14.3. v1.0 — Production (публичный)

- Всё из v0.5; security-аудит; load-тесты; E2E-тесты; документация; Docker; Cloudflare Workers.
- **Срок:** 16 недель.

### 14.4. v1.1 — Enhancements

- Mode A с PreKeyBundle (X3DH) через `wrapKeyForRecipient`.
- MCP: доработки `t2em_list_secrets`.
- Web UI: QR-код для URL и pubkey.
- CLI: `--json` output.
- **Срок:** 6 недель.

### 14.5. v2.0 — Ecosystem

- **we2em SSO (OIDC RP):** «Login with we2em» для приватных дропов и managed secrets (PKCE S256).
- **Key discovery через we2em:** `GET /api/v1/keys/:pubkey`; Mode A без ручного обмена ключами.
- **Верификация Me2eM-сессий:** `Session.verifyAttested` + `RevocationChecker` на `GET we2em.com/api/v1/revocations/:jti`.
- **Managed secrets:** TTL до 7 дней, только аутентифицированный режим, Cloudflare R2.
- Интеграция с `@me2em/core`, `@me2em/pact`, `@me2em/x402`.
- Multi-region replication.
- **Срок:** 12 недель.

### 14.6. Migration & Deprecation Policy

- **v1 поддерживается 12 месяцев** после выхода v2.0.
- **Envelope `v: 1` принимается** до `2028-11-13`. После — `410 Gone`.
- **Breaking changes** — только через новую версию envelope (`v: 2`) и новую HKDF info-строку.
- **Deprecation notice** — за 6 месяцев до удаления, через:
  - `Deprecation` HTTP header.
  - `Sunset` HTTP header.
  - Email подписчикам (если есть).
  - CHANGELOG.
- **Client migration:** SDK/CLI поддерживают **обе** версии envelope в течение transition period.

### 14.7. Disaster Recovery

- **Durability:** **не гарантируется.** Redis (Upstash) — ephemeral. При падении Redis все активные дропы теряются.
- **RTO (Recovery Time Objective):** ≤ 5 минут (Workers auto-restart, Redis failover).
- **RPO (Recovery Point Objective):** ≤ 15 минут (все активные дропы, но они ephemeral — потеря приемлема).
- **Отправитель:** при ошибке `push` или недоступности сервиса — **повторяет** `push`. Идемпотентность не гарантируется (каждый `push` создаёт новый drop).
- **Уведомление:** status page (`status.t2em.com`) при инцидентах.

### 14.8. Abuse Handling

- **t2em не сканирует содержимое** (zero-knowledge).
- **Legal requests** (court order): t2em **не может** расшифровать. Может только **удалить** дроп по `id` (без знания содержимого).
- **Reporting:** `abuse@t2em.com` — для жалоб.
- **Response:**
  - Valid report → удаление дропа (если `id` известен).
  - Malicious reports → игнорируются.
- **Transparency report:** ежегодно, публично (количество запросов, действий).

### 14.9. Key Rotation

- **`@me2em/crypto`:** обновление — **только** при security fix. Тест-векторы гарантируют совместимость.
- **HKDF info-строка:** **frozen.** Изменение — только через `/v2`.
- **Cloudflare Workers secrets** (Redis URL): ротация — раз в 90 дней, или при подозрении на компромисс.
- **TLS-сертификаты:** автоматическая ротация (Cloudflare).
- **npm Provenance:** при каждом релизе.

---

## 15. Риски и митигация

| Риск | Вероятность | Влияние | Митигация |
|---|---|---|---|
| **Redis compromise** | Низкая | Среднее | TTL ≤ 15 мин, RAM-only, TLS |
| **Workers cold start** | Средняя | Низкое | Bundle optimization, warm-up |
| **Rate limit bypass** | Средняя | Среднее | Multi-layer (Cloudflare + Redis) |
| **Supply chain attack** | Низкая | Высокое | Lockfile, audit, SBOM, signing |
| **Zero-day in crypto lib** | Низкая | Высокое | Audited libs, monitor CVEs |
| **Cloudflare outage** | Низкая | Высокое | Multi-region (Upstash), status page |
| **GDPR violation** | Низкая | Высокое | Data minimization, legitimate interest |
| **Prompt injection** | Средняя | Среднее | MCP `secret_handle` |
| **SSRF через MCP** | Средняя | Высокое | Deny-list (полный), DNS pinning, redirect policy, proxy ban, audited lib |
| **URL leakage** | Средняя | Среднее | `#fragment` not sent to server, `Cache-Control: no-store` |
| **Browser history** | Средняя | Среднее | Web UI: `#fragment` auto-clear, warning |
| **Key substitution (Mode A)** | Средняя | Высокое | Fingerprint 16 chars, we2em-реестр (v2.0) |
| **TS↔Python рассинхронизация** | Средняя | Среднее | Общие тест-векторы в CI |
| **Redis OOM (глобальный лимит)** | Средняя | Высокое | Global active drops limit (1M), alert 80% |

---

## 16. Команда и ресурсы

### 16.1. Роли

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

### 16.2. Timeline (16 недель до v1.0)

| Неделя | Milestone |
|---|---|
| 1-3 | Setup, `@t2em/protocol` (Mode A/B, тест-векторы), unit tests |
| 4-6 | `@t2em/relay-server` (Workers), Redis, rate limits, integration tests |
| 7-9 | CLI, Python SDK, MCP server (с SSRF-guard), cross-language test-vectors |
| 10-12 | Web UI (`#fragment` auto-clear, warning, QR), `llms.txt`, docs |
| 13-14 | Security audit, load tests, chaos tests |
| 15 | Bug fixes, polish, Docker, self-hosted |
| 16 | Release v1.0, announcement |

### 16.3. Бюджет (уточнено)

**Assumptions:** senior full-time инженеры, рыночные зарплаты (US/EU remote).

| Статья | Стоимость |
|---|---|
| **Cloudflare Workers** | $5/мес + $0.30/млн запросов |
| **Upstash Redis** | $0.20/100K команд |
| **Cloudflare R2** | $0.015/GB/мес (v2.0) |
| **Домен** | $10/год |
| **Security audit** | $30K-50K |
| **Bug bounty** | $10K-50K/год |
| **Команда** | $800K-1M/год (4.5 FTE × $180K-220K) |
| **Итого (год 1)** | **~$850K-1.1M** |

**Нижняя граница $850K** — при условии, что команда **senior full-time** (не part-time, не volunteer). Для OpenSource с volunteer-компонентом — возможно **$400K-600K**, но с риском задержек.

**Монетизация:** enterprise support, SLA, managed secrets (v2.0).

---

## 17. Критерии приёмки (v1.0)

### 17.1. Функциональные

- [ ] `POST /api/v1/drop` работает (Mode A, Mode B).
- [ ] `GET /s/:id` работает (JSON, HTML, content negotiation).
- [ ] `DELETE /api/v1/drop/:id` работает (timingSafeEqual).
- [ ] `GET /llms.txt` доступен и сгенерирован из OpenAPI + шаблона.
- [ ] `GET /openapi.json` доступен (OpenAPI 3.1).
- [ ] `GET /health` доступен.
- [ ] CLI: `push`, `pull` (без newline), `pull --newline`, `keygen` (JSON-формат), `delete`; fingerprint в stderr.
- [ ] Python SDK: `push`, `pull_text`, `generate_x25519_keypair`; тест-векторы TS↔Python бит-в-бит; HKDF только через `cryptography`.
- [ ] MCP: 6 инструментов; `t2em_list_secrets` с метаданными; SSRF-guard (полный deny-list, альтернативные IP, CNAME, redirects, proxy ban).
- [ ] Web UI: создание, fetch, расшифровка, `#fragment` auto-clear, warning, QR.

### 17.2. Нефункциональные

- [ ] Latency p95 < 100ms (baseline 100 RPS).
- [ ] Throughput ≥ 1000 RPS (per region).
- [ ] Uptime ≥ 99.9% (30 дней).
- [ ] Unit-тесты ≥ 80% coverage.
- [ ] Integration-тесты (включая TTL bounds 59/901/отсутствует/дробное → 400; envelope > 10 полей → 400; global active drops overflow → 503).
- [ ] E2E-тесты (Playwright, включая `#fragment` auto-clear).
- [ ] Load-тесты (k6).
- [ ] Chaos-тесты.
- [ ] Security-аудит (no critical/high).
- [ ] Документация (VitePress).
- [ ] Docker (GHCR).
- [ ] npm packages (Provenance).
- [ ] PyPI package.

### 17.3. Безопасность

- [ ] Zero-knowledge подтверждён (audit).
- [ ] Zero-logging подтверждён (audit).
- [ ] `secureWipe`/`withSecureWipe` везде.
- [ ] TLS 1.3 only; HSTS preload; DNSSEC.
- [ ] Rate limit (drop/fetch/delete — разные; + `X-RateLimit-*`, `Retry-After`).
- [ ] `safeJsonParse` (`__proto__`).
- [ ] `timingSafeEqual` (delete token).
- [ ] Идентичный 404-путь (тело + время).
- [ ] `GETDEL` атомарен.
- [ ] No secrets in logs.
- [ ] No plaintext IP/UA; `sha256(ip)` только в rate-limit ключе, TTL 60/3600 с.
- [ ] SSRF-guard: полный deny-list, альтернативные IP, DNS pinning, redirects, proxy ban — покрыты тестами.
- [ ] Тест-векторы `vectors/t2em-drop.v1.json` (positive, negative, edge, cross-mode) проходят в TS и Python.

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
      - RATE_LIMIT_DROP_PER_MINUTE=10
      - RATE_LIMIT_DROP_PER_HOUR=100
      - RATE_LIMIT_FETCH_PER_MINUTE=60
      - RATE_LIMIT_DELETE_PER_MINUTE=60
      - MAX_PAYLOAD_BYTES=65536
      - MAX_ENVELOPE_FIELDS=10
      - TTL_MIN=60
      - TTL_MAX=900
      - GLOBAL_ACTIVE_DROPS_LIMIT=1000000
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
      - run: pnpm test:vectors  # TS↔Python cross-language test-vectors
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
ttl: 60..900 seconds (integer, required).

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
- Verify key authenticity by comparing the fingerprint (16 chars):
  `base64url(sha256(pubkey))[0..16]`.
- (v2.0) Resolve keys via we2em registry with attestation binding.

## Error Codes
- `400`: malformed request (bad JSON, missing fields, ttl out of 60..900, unknown envelope.v, >10 fields)
- `404`: not found / expired / already read (identical response for all three)
- `413`: payload too large (> 64 KB)
- `429`: rate limited (see X-RateLimit-* headers and Retry-After)
- `503`: global active drops limit reached
- `500`: internal error

## Rate Limits
- POST /drop: 10/min, 100/hour per IP
- GET /s/:id: 60/min per IP
- DELETE /drop/:id: 60/min per IP
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
`t2em_http_request` blocks private networks (SSRF guard: full deny-list,
DNS pinning, redirect policy, proxy ban); https only.

## Common Pitfalls
- DO NOT log the URL with `#fragment` (contains `sym_key`).
- DO NOT cache the URL (use `Cache-Control: no-store`).
- DO NOT reuse `sym_key` for multiple drops.
- DO NOT send secrets in query parameters (use POST body).
- DO NOT trust a recipient pubkey without fingerprint comparison (16 chars).
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
| **TTL** | Time-To-Live (v1: integer, 60..900 с) |
| **Keyfile** | JSON-файл с приватным ключом получателя (Mode A) |
| **Fingerprint** | `base64url(sha256(pubkey))[0..16]` — 16-символьный отпечаток ключа |
| **PreKeyBundle** | Публичные ключи для X3DH (v2.0) |
| **Blind Relay** | Сервер, который передаёт ciphertext, не имея ключей расшифровки |

---

**Конец документа.**