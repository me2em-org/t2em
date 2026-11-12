# Техническое задание на разработку сервиса we2em.com

**Версия:** 2.0 (Final)
**Статус:** Approved for implementation
**Дата:** 2026-11-13
**Продукт:** we2em (We accept Me)
**Домен:** we2em.com
**Экосистема:** Me2eM
**Слой:** Layer 0/1 (Identity Provider, реестр публичных ключей, SSO)
**Лицензия:** Apache-2.0
**Связанные документы:** `TZ_t2em.md` (t2em.com, транспорт секретов), `me2em-protocol/specs/v1.0.md` (нормативная спека протокола)

---

## 0. Сводка изменений относительно v1.0

| № | Изменение | Раздел |
|---|---|---|
| 1 | **Устранена криптографическая ошибка v1.0:** сервер не может вызывать `Session.create` из `@me2em/core` (метод требует приватный ключ Handle, который никогда не покидает клиента). Введена двухуровневая модель сессий: Tier-1 — opaque-токены, выпускаемые сервером; Tier-2 — Me2eM-сессии, создаваемые клиентом и верифицируемые через `Session.verifyAttested` | §4.6, §5.4, §5.5 |
| 2 | Challenge-response: определён канонический домен-сепарированный подписываемый payload (`we2em/challenge/v1`) — защита от cross-protocol replay | §5.2.0 |
| 3 | Анти-перечисление: `register/init` и `login/init` возвращают одинаковый ответ независимо от существования pubkey; конфликт вскрывается только на `complete` и только легитимному владельцу ключа | §5.2, §5.3, §9.2 |
| 4 | SSO: scope `email` удалён (we2em не хранит email — противоречие с no-PII); scopes = `openid`, `profile`, `entity` | §5.9 |
| 5 | SSO: специфицированы cookies (`__Host-` префикс, HttpOnly, Secure, SameSite=Lax) и CSRF-защита (state + SameSite + PKCE) — web-флоу SSO использует cookies, в отличие от чистого Bearer API | §5.9.0, §9.4 |
| 6 | Cloud Backup: устранено дублирование — единственный источник истины `encrypted_seed` в PostgreSQL; R2 — опциональное зеркало/история версий в v2.0 | §4.5 |
| 7 | Удалена таблица `rate_limits` в PostgreSQL (избыточна: Redis fast path + Cloudflare edge; плюс артефакт «跨-region» в исходнике) | §4.2 |
| 8 | `audit_log`: удалена фиктивная CHECK-конструкция, задан retention 90 дней, определена процедура анонимизации при erasure | §4.7, §13 |
| 9 | Реестр ключей: добавлен флаг `discoverable` (opt-in) — поиск `GET /keys?type=...` возвращает только согласившихся; lookup по точному pubkey работает всегда | §4.1, §5.7 |
| 10 | Модель entity: добавлен `key_kind` (`identity` — корневой ключ Identity, `handle` — pubkey аттестованного Handle); устранена неоднозначность «что именно регистрируется» | §4.1 |
| 11 | Python SDK: разрешены зависимости PyCA `cryptography` и (optional extra) `argon2-cffi`; stdlib не содержит Ed25519/Argon2id | §7.3 |
| 12 | MCP `we2em_http_request`: обязательная SSRF-защита (как в t2em) | §7.4, §9.6 |
| 13 | Все 10 открытых вопросов v1.0 получили резолюции (Приложение E) | §11 |
| 14 | Бренд-правило: We2eM (человек) / we2em (машина); форма «We2em» запрещена | §2.2 |
| 15 | Backup API требует аутентификации (в v1.0 `POST /backup/init` принимал pubkey без auth — риск подмены/порчи чужого backup) | §5.8 |

---

## 1. Общие сведения

### 1.1. Назначение документа

Настоящее ТЗ описывает требования к разработке сервиса **we2em.com** — Identity Provider (IdP) и реестра публичных ключей для экосистемы Me2eM. Документ **самодостаточен**: не требует обращения к другим спецификациям для понимания требований. Ссылки на экосистему — информационные, для контекста.

### 1.2. Позиционирование в экосистеме

```
┌─────────────────────────────────────────────────────────────────────┐
│                    ВЕРТИКАЛЬНЫЕ ПРОДУКТЫ                            │
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │  t2em.com    │  │  we2em.com   │  │  другие      │              │
│  │  Транспорт   │  │  Идентичность│  │  продукты    │              │
│  │  секретов    │  │  + SSO       │  │              │              │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘              │
└─────────┼─────────────────┼─────────────────┼─────────────────────┘
          │                 │                 │
          │ использует      │ использует      │ использует
          ▼                 ▼                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  ГОРИЗОНТАЛЬНЫЙ СЛОЙ (@me2em/*)                     │
│                                                                     │
│  • @me2em/core   — Identity, Handle, SubHandle, Attestation, Session│
│  • @me2em/crypto — X25519, X3DH, HKDF, AES-GCM, SLIP-0010, secureWipe│
│  • @me2em/pact   — Криптографические договоры (план)                │
│  • @me2em/x402   — Платёжный транспорт (план)                       │
└─────────────────────────────────────────────────────────────────────┘
```

**we2em** — это **Layer 0/1**: стерильный инфраструктурный слой. «We» (сеть) принимает «Me» (идентификатор). Точка входа (SSO) в экосистему.

**Важно о зависимостях** (согласовано с `TZ_t2em.md` §3.5): в терминах npm-пакетов we2em — такой же вертикальный монорепозиторий, как t2em; он зависит только от `@me2em/core` и `@me2em/crypto`. Между `@we2em/*` и `@t2em/*` npm-зависимостей нет — интеграция продуктов только runtime (HTTP/OIDC).

### 1.3. Цели продукта

1. **Унифицированная идентичность для всех сущностей** — люди, AI-агенты, боты, IoT-устройства, роботы — равноправные участники с криптографическими идентичностями.
2. **Реестр публичных ключей** — глобальный каталог `pubkey → entity metadata` с аттестационными привязками.
3. **SSO** — единый вход во все продукты экосистемы (`t2em.com`, `@me2em/*`).
4. **Attestation registry** — хранение, разрешение и верификация делегаций (Owner → Agent).
5. **Challenge-response аутентификация** — без паролей, без seed на сервере.
6. **Zero-Knowledge** — сервер не видит приватные ключи, seed (кроме opt-in Cloud Backup в зашифрованном виде), секреты.
7. **API-First** — все операции через JSON-эндпоинты.
8. **Agent-Friendly** — MCP-сервер, `llms.txt`, SDK для AI-агентов.

### 1.4. Что we2em **не** делает

- **Не** передаёт секреты (это `t2em.com`).
- **Не** хранит долговременные секреты (только opt-in encrypted seed для Cloud Backup).
- **Не** выполняет платежи (это `@me2em/x402`).
- **Не** заменяет Vault/KMS для приложений.
- **Не** предоставляет UI для сложных сценариев (только базовый Web UI для регистрации/входа).
- **Не** создаёт Me2eM-сессии за клиента — у сервера нет приватных ключей клиентов (см. §4.6).

### 1.5. Целевая аудитория

| Аудитория | Сценарий |
|---|---|
| **Люди** | Регистрация Identity, вход в продукты экосистемы |
| **AI-агенты** | Регистрация, получение session token, верификация |
| **Боты** | Регистрация pubkey, аутентификация |
| **IoT-устройства** | Provisioning, аутентификация |
| **Разработчики** | Интеграция через SDK/MCP |
| **Операторы** | Self-hosted развёртывание |

---

## 2. Терминология

### 2.1. Термины

| Термин | Определение |
|---|---|
| **Entity** | Любая сущность: человек, AI-агент, бот, IoT-устройство, робот |
| **Identity** | Корневая идентичность (Ed25519 keypair), derived from seed |
| **Handle** | Контекстная идентичность (derived from Identity) |
| **SubHandle** | Leaf-идентичность (derived from Handle, MAX_DEPTH=2) |
| **Attestation** | Подписанный владельцем грант (делегация прав); `typ: me2em/attestation/v1`, payload ≤ 2048 B |
| **Session (Tier-1)** | Opaque bearer-токен, выпущенный сервером we2em (`wem_...`), хранится хэшем |
| **Session (Tier-2)** | Stateless Me2eM-токен `base64url(payload).base64url(sig)`, созданный **клиентом** через `Session.create` |
| **Seed** | BIP39 seed (64 байта), корень деривации |
| **Self Custody** | Пользователь хранит seed сам |
| **Cloud Backup** | Seed зашифрован паролем на клиенте (Argon2id + AES-256-GCM), хранится на сервере |
| **Challenge-Response** | Аутентификация через подпись домен-сепарированного nonce |
| **Revocation** | Отзыв attestation/session по `jti` |
| **SSO** | Single Sign-On (OAuth 2.0 / OIDC) |
| **Entity Matrix** | Матрица сущностей: человек × агент × устройство × бот |
| **key_kind** | Признак зарегистрированного ключа: `identity` (корень) или `handle` (аттестованный) |
| **discoverable** | Opt-in флаг присутствия в публичном поиске `/keys` |

### 2.2. Бренд-правило

По аналогии с правилом DR-5 экосистемы (Me2eM/me2em) для we2em закреплены ровно две канонические формы:

- **We2eM** — человекочитаемая форма (заголовки, презентации);
- **we2em** — машиночитаемая форма (домены, пакеты, CLI, идентификаторы).

Форма **«We2em» запрещена** как опечатка. Исключение — идентификаторы кода (например, класс `We2emClient`), являющиеся машиночитаемым текстом.

### 2.3. Совместимость с GLOSSARY экосистемы

Термины Handle, SubHandle, Attestation, Session, Seed используются в значениях из `me2em-protocol/GLOSSARY.md`. Имена Handle подчиняются каноническому правилу ядра: NFKC → lowercase → trim, паттерн `/^[a-z0-9][a-z0-9._@-]{0,62}$/` (имя **не может начинаться** с `@`; `@`-нотация из маркетинговых материалов Me2eM — иллюстративная). Примеры корректных имён: `agent-github-bot`, `station-001`, `alice.work`.

---

## 3. Архитектура

### 3.1. Общая схема

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          ENTITIES (Clients)                             │
│                                                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │  Human   │  │ AI Agent │  │   Bot    │  │   IoT    │  │  Robot   │  │
│  │ (Web UI) │  │  (MCP)   │  │  (SDK)   │  │  (CLI)   │  │  (SDK)   │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  │
└───────┼─────────────┼─────────────┼─────────────┼─────────────┼────────┘
        │             │             │             │             │
        └─────────────┴─────────────┴─────────────┴─────────────┘
                                    │
                                    │ HTTPS (TLS 1.3)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     CLOUDFLARE (Edge Network)                           │
│                                                                         │
│  • DNSSEC enabled                                                       │
│  • Strict HSTS (max-age=63072000; includeSubDomains; preload)           │
│  • TLS 1.3 only                                                         │
│  • WAF + DDoS protection                                                │
│  • Rate limiting (per IP, per pubkey)                                   │
│  • Bot management                                                       │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                Cloudflare Workers (Edge Compute)                  │  │
│  │                                                                   │  │
│  │  • Hono framework (TypeScript)                                    │  │
│  │  • Zero-logging (no request body logging)                         │  │
│  │  • Cache-Control: no-store, no-cache, private                     │  │
│  │  • CORS: allowlist                                                │  │
│  │  • Security headers (CSP, X-Frame-Options, etc.)                  │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
                    ▼               ▼               ▼
        ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
        │  POSTGRES    │  │  UPSTASH     │  │  S3/R2       │
        │  (primary)   │  │  REDIS       │  │  (v2.0:      │
        │              │  │              │  │   mirror/    │
        │  • Entities  │  │  • Nonce     │  │   history    │
        │  • Sessions  │  │  • Revocation│  │   Cloud      │
        │  • Pubkeys   │  │    cache     │  │   Backup)    │
        │  • Attest.   │  │  • Rate lim  │  │              │
        │  • Revocation│  │              │  │              │
        │  • Backup    │  │              │  │              │
        │  • Audit     │  │              │  │              │
        └──────────────┘  └──────────────┘  └──────────────┘
```

### 3.2. Компоненты

| Компонент | Технология | Назначение |
|---|---|---|
| **Edge Compute** | Cloudflare Workers + Hono | HTTP-обработка |
| **Primary DB** | PostgreSQL 16 (Neon/Supabase) | Entities, sessions, pubkeys, attestations, revocation, backups, audit |
| **Cache** | Upstash Redis (REST) | Nonce, revocation cache, rate limit |
| **Object Storage** | Cloudflare R2 / S3 | v2.0: mirror/история Cloud Backup, multi-device sync |
| **CLI** | Node.js ≥ 22 (TypeScript) | `we2em-cli` |
| **Python SDK** | Python ≥ 3.10 | `we2em` (PyPI) |
| **MCP Server** | Node.js ≥ 22 (TypeScript) | `@we2em/mcp-server` |
| **Web UI** | Vanilla JS + minimal framework | Регистрация, вход, управление |
| **Crypto Core** | `@me2em/core`, `@me2em/crypto` | Identity, Attestation, Session-verify, X25519, Argon2id, secureWipe |

### 3.3. Монорепозиторий (pnpm workspace)

```
we2em/
├── packages/
│   ├── idp-core/          @we2em/idp-core       — ядро IdP (entities, attestations, sessions)
│   ├── relay-server/      @we2em/relay-server   — HTTP server (Workers + Node)
│   ├── cli/               @we2em/cli            — CLI (we2em-cli)
│   ├── mcp-server/        @we2em/mcp-server     — MCP сервер
│   ├── web-ui/            @we2em/web-ui         — Web UI
│   └── sdk-js/            @we2em/sdk-js         — JS SDK
├── python-sdk/            we2em                 — Python SDK (PyPI)
├── docs/                  Документация (VitePress + ТЗ)
├── infra/                 Terraform / Wrangler
└── examples/              Примеры интеграции
```

### 3.4. Режимы развёртывания

**1. Cloudflare Workers + Managed DB (managed)**

- Edge: Cloudflare Workers.
- DB: Neon/Supabase (Postgres) + Upstash Redis (+ R2 в v2.0).
- Deploy: GitHub Actions + `wrangler-action`.

**2. Self-hosted Docker**

- Edge: Nginx + Node.js (`@hono/node-server`).
- DB: Postgres + Redis (+ MinIO в v2.0).
- Deploy: `docker compose up -d`.

**3. Hybrid (managed)**

- Edge: Cloudflare.
- DB: self-hosted Postgres + Redis (+ MinIO).

**Требование:** все режимы используют **один** код (`packages/relay-server/src/app.ts`), различия — только в адаптерах storage.

### 3.5. Границы интеграции

- t2em.com → we2em.com: OIDC SSO (web), реестр ключей (`GET /keys/:pubkey`), revocation checker (`GET /revocations/:jti`), verify-as-service (`POST /verify/session`) — только HTTP.
- Прочие продукты экосистемы — те же интерфейсы.
- npm-зависимости: `@we2em/idp-core` → `@me2em/core`, `@me2em/crypto` (версии: `@me2em/core ^1.0.0-rc.4`, `@me2em/crypto ^1.1.0`).

---

## 4. Модель данных

### 4.1. PostgreSQL-схема

#### 4.1.1. `entities` — сущности

```sql
CREATE TABLE entities (
  entity_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  pubkey BYTEA NOT NULL UNIQUE,                  -- Ed25519 pubkey (32B)
  key_kind TEXT NOT NULL DEFAULT 'identity',     -- 'identity' | 'handle' (см. §4.1.1.1)
  entity_type TEXT NOT NULL,                     -- 'human' | 'agent' | 'bot' | 'iot' | 'robot'
  display_name TEXT,                             -- human-readable (optional)
  discoverable BOOLEAN NOT NULL DEFAULT false,   -- opt-in в публичный поиск /keys (новое)
  metadata JSONB DEFAULT '{}',                   -- entity-specific (без секретов)
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMPTZ,
  status TEXT NOT NULL DEFAULT 'active',         -- 'active' | 'suspended' | 'revoked'
  has_cloud_backup BOOLEAN NOT NULL DEFAULT false,
  CONSTRAINT valid_type CHECK (entity_type IN ('human', 'agent', 'bot', 'iot', 'robot')),
  CONSTRAINT valid_status CHECK (status IN ('active', 'suspended', 'revoked')),
  CONSTRAINT valid_pubkey_len CHECK (octet_length(pubkey) = 32),
  CONSTRAINT valid_key_kind CHECK (key_kind IN ('identity', 'handle'))
);

CREATE INDEX idx_entities_pubkey ON entities(pubkey);
CREATE INDEX idx_entities_type ON entities(entity_type);
CREATE INDEX idx_entities_status ON entities(status);
CREATE INDEX idx_entities_discoverable ON entities(discoverable) WHERE discoverable = true;
```

**4.1.1.1. Семантика `key_kind` (новое):**

| key_kind | Что зарегистрировано | Кто подписывает сессии Tier-2 | Типовой сценарий |
|---|---|---|---|
| `identity` | Корневой pubkey Identity (из seed) | Handle'ы, производные этим Identity (верификация через verifyStateless у владельца / verifyAttested у ресурса) | Self Custody человек, IoT-шлюз |
| `handle` | Pubkey Handle, аттестованного владельцем (`Attestation.issue` / `identity.attestHandle`) | Сам Handle (приватный ключ у агента/устройства) | Делегированный AI-агент, устройство |

Правило: сущность с `key_kind = 'handle'` **обязана** иметь хотя бы одну аттестацию в `attestations` (enforced приложением при регистрации через §5.6).

#### 4.1.2. `attestations` — делегации

```sql
CREATE TABLE attestations (
  attestation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  issuer_entity_id UUID NOT NULL REFERENCES entities(entity_id),
  subject_entity_id UUID REFERENCES entities(entity_id),  -- NULL до первой регистрации subject
  token TEXT NOT NULL,                            -- full Attestation token (base64url)
  subject_id_base64url TEXT NOT NULL,             -- subject pubkey (base64url)
  payload JSONB NOT NULL,                         -- decoded AttestationPayload
  jti TEXT NOT NULL UNIQUE,                       -- attestation jti (для revocation)
  issued_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  revoked_reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT valid_issuer_subject CHECK (issuer_entity_id != subject_entity_id)
);

CREATE INDEX idx_attestations_issuer ON attestations(issuer_entity_id);
CREATE INDEX idx_attestations_subject ON attestations(subject_entity_id);
CREATE INDEX idx_attestations_subject_key ON attestations(subject_id_base64url);
CREATE INDEX idx_attestations_jti ON attestations(jti);
CREATE INDEX idx_attestations_expires ON attestations(expires_at) WHERE revoked_at IS NULL;
```

**Поведение:** аттестация — публичный документ (не секрет). Если subject ещё не зарегистрирован, `subject_entity_id` = NULL; при регистрации subject с совпадающим pubkey — связь проставляется. Это позволяет агенту, получившему attestation до собственной регистрации, пройти onboarding по цепочке (§6.4).

#### 4.1.3. `server_sessions` — Tier-1 сессии (новое)

```sql
CREATE TABLE server_sessions (
  session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),   -- публичный jti для revocation
  token_hash BYTEA NOT NULL UNIQUE,               -- sha256(opaque token)
  entity_id UUID NOT NULL REFERENCES entities(entity_id),
  client_id TEXT,                                 -- OAuth client для SSO-сессий, NULL для direct
  scopes TEXT[] NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  revoked_reason TEXT,
  CONSTRAINT valid_ttl CHECK (expires_at > created_at)
);

CREATE INDEX idx_server_sessions_entity ON server_sessions(entity_id);
CREATE INDEX idx_server_sessions_expires ON server_sessions(expires_at);
```

Opaque-токен: `wem_<base64url 32B случайных байт>`. Хранится только `sha256(token)`. TTL ≤ 3600 с. Me2eM-сессии (Tier-2) в этой таблице **не хранятся** — они stateless и не выпускаются сервером (§4.6).

#### 4.1.4. `revocations` — отзывы

```sql
CREATE TABLE revocations (
  revocation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  jti TEXT NOT NULL UNIQUE,                       -- attestation jti или session_id
  entity_id UUID NOT NULL REFERENCES entities(entity_id),
  reason TEXT,
  revoked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ,                         -- jti expiry (для cleanup)
  CONSTRAINT valid_jti CHECK (length(jti) > 0 AND length(jti) <= 256)
);

CREATE INDEX idx_revocations_jti ON revocations(jti);
CREATE INDEX idx_revocations_entity ON revocations(entity_id);
```

#### 4.1.5. `cloud_backups` — Cloud Backup (encrypted seeds)

```sql
CREATE TABLE cloud_backups (
  backup_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  entity_id UUID NOT NULL REFERENCES entities(entity_id) ON DELETE CASCADE,
  encrypted_seed BYTEA NOT NULL,                  -- Argon2id(password) → AES-256-GCM(seed)
  kdf_profile TEXT NOT NULL,                      -- 'INTERACTIVE' | 'SENSITIVE'
  kdf_salt BYTEA NOT NULL,                        -- Argon2id salt
  kdf_params JSONB NOT NULL,                      -- { memory, iterations, parallelism }
  checksum BYTEA NOT NULL,                        -- sha256(encrypted_seed), целостность
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(entity_id)
);

CREATE INDEX idx_cloud_backups_entity ON cloud_backups(entity_id);
```

**Решение v2.0 (вместо дублирования PG + S3 из v1.0):** PostgreSQL — единственный источник истины (`encrypted_seed` ≈ 100–200 B). R2/S3 — опциональное зеркало и история версий в v2.0 (multi-device sync); при зеркалировании PG остаётся authoritative, S3 — восстановимый кэш. Сервер не может расшифровать без пароля (KDF выполняется на клиенте).

#### 4.1.6. `audit_log` — аудит

```sql
CREATE TABLE audit_log (
  audit_id BIGSERIAL PRIMARY KEY,
  entity_id UUID REFERENCES entities(entity_id),  -- NULL после анонимизации (§13.1)
  event_type TEXT NOT NULL,                       -- 'register' | 'login' | 'session.create' | ...
  ip_hash BYTEA,                                  -- sha256(ip), псевдонимизированные данные
  user_agent_hash BYTEA,                          -- sha256(user-agent)
  metadata JSONB DEFAULT '{}',                    -- без секретов (enforced приложением)
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_entity ON audit_log(entity_id);
CREATE INDEX idx_audit_event ON audit_log(event_type);
CREATE INDEX idx_audit_created ON audit_log(created_at);
```

**Изменения v2.0:** удалена фиктивная конструкция `CHECK (true)` из v1.0; запрет секретов в `metadata` enforced приложением (serialization guard, тест) и covered security-тестом §10.3. Retention — 90 дней, затем партиции удаляются (§13.1).

*(Таблица `rate_limits` из v1.0 удалена: пер-регионный persistent rate limit не нужен — Cloudflare Rate Limiting на edge + Redis INCR/EXPIRE покрывают требования; см. §4.2.)*

### 4.2. Redis-схема

```
# Nonce (challenge)
KEY: nonce:{challengeId}
VALUE: JSON { nonce, pubkey, purpose, expiresAt }
TTL: 60s
TYPE: string
ATOMIC: GETDEL при использовании

# Revocation cache (быстрая проверка для verifyStateless/verifyAttested и Tier-1)
KEY: revoked:{jti}
VALUE: "1"
TTL: до jti.exp + 30s skew
TYPE: string

# Rate limit (fast path)
KEY: ratelimit:{ip_hash}:{window}
VALUE: counter
TTL: 60s
TYPE: string (INCR + EXPIRE)

# Login throttling per pubkey (anti-bruteforce challenge)
KEY: ratelimit:pubkey:{pubkey_hash}:{window}
VALUE: counter
TTL: 60s
TYPE: string (INCR + EXPIRE)
```

**Примечание:** кэш сессий (session:{jti}) из v1.0 удалён — Tier-1 верифицируется по `server_sessions` (кэш на уровне connection pooling достаточно быстрый), Tier-2 stateless. Это убирает класс рассинхронизации кэша с БД.

### 4.3. S3/R2-схема (только v2.0)

```
# Cloud Backup mirror / version history
KEY: backups/{entityId}/{timestamp}-{backupId}.bin
VALUE: encrypted_seed (Argon2id + AES-GCM)
METADATA: { kdfProfile, kdfSalt, kdfParams, checksum }
ENCRYPTION: client-side (Argon2id + AES-GCM) — единственная значимая защита;
            server-side SSE — гигиена носителя
ACCESS: private, presigned URLs (TTL 60s)
AUTHORITATIVE SOURCE: PostgreSQL (S3 — восстановимый кэш)
```

### 4.4. Что **не** хранится (Zero-Knowledge)

| Данные | Почему |
|---|---|
| Приватные ключи | Только у клиента |
| Seed в plaintext | Только opt-in encrypted (Cloud Backup) |
| Пароль (даже хэш) | Пароль не покидает клиент; KDF на клиенте (OPAQUE не используется — резолюция открытого вопроса №1) |
| Секреты (PAT, API keys) | Это `t2em.com` |
| IP-адреса (plaintext) | Только `sha256(ip)` для rate limit и audit |
| Тела запросов с секретами | Zero-logging |

### 4.5. Гарантии

- **Pubkey уникален:** `UNIQUE(pubkey)` — один pubkey = одна сущность.
- **Attestation jti уникален:** `UNIQUE(jti)` — нет коллизий; revocation атомарна (UNIQUE + транзакция).
- **Opaque-токены не восстановимы:** в БД только sha256.
- **Audit без секретов:** `metadata` без PAT/seed/паролей (application guard + тест).
- **Cloud Backup encrypted:** сервер не может расшифровать без пароля.

### 4.6. Модель сессий (новое — ключевое изменение v2.0)

**Ограничение ядра:** `Session.create(handle, options)` из `@me2em/core` подписывает payload **приватным ключом Handle**. По инварианту Me2eM («Non-persistent private key», seed/ключи не покидают клиента) сервер we2em **не владеет** приватными ключами клиентов и, следовательно, **не может** создавать Me2eM-сессии. Формулировка v1.0 («сервер создаёт session token через `Session.create`») криптографически неосуществима и заменена:

| | **Tier-1: Server Session** | **Tier-2: Me2eM Session** |
|---|---|---|
| Кто создаёт | Сервер we2em (после challenge-response) | **Клиент** (`Session.create` на своём Handle) |
| Формат | Opaque `wem_<base64url 32B>` | `base64url(payload).base64url(sig)`, payload = `{ hId, hNm, aud, scp, exp, iat, jti }` |
| Хранение | sha256 в `server_sessions`, TTL ≤ 1 ч | Не хранится; stateless верификация |
| Верификация | lookup `token_hash` + expiry + revocation | `Session.verifyAttested(token, rootPublicKey, chain, aud, revocationChecker)` |
| Audience | `we2em.com` (API самого we2em, SSO-флоу) | Любой ресурс экосистемы (`t2em.com`, ...) |
| Revocation | `DELETE` сессии → `revocations` | `RevocationChecker` → `GET /api/v1/revocations/:jti` |
| Применение | Web UI, SSO, CLI, все entity-типы | Agent/бот/IoT → ресурсные серверы, federation |

**Кто что использует:** Tier-1 — универсальный минимум (все entity, включая root-pubkey регистрации без Handle). Tier-2 — для делегированных агентов (attested Handle) и IoT (attested Handle/SubHandle); ресурсные серверы (например, t2em v2.0) верифицируют Tier-2 сами, используя we2em как реестр root-ключей и revocation-источник.

### 4.7. Retention данных

| Данные | Срок |
|---|---|
| `audit_log` | 90 дней (партиции по дате, затем drop) |
| `revocations` | до `expires_at` + 30 дней (cleanup job) |
| `server_sessions` истёкшие | 7 дней (cleanup job) |
| `cloud_backups` | пока владелец не удалит |
| `entities` | пока не удалена владельцем (см. §13.1 erasure) |

---

## 5. API-спецификация

### 5.0. Общие требования

- **Base URL:** `https://we2em.com/api/v1`
- **Content-Type:** `application/json`
- **Auth:** Bearer token (Tier-1 `wem_...`) либо Me2eM session token (Tier-2) — для защищённых эндпоинтов; challenge-response — для login/register.
- **Rate limit:** 60 req/min на IP; challenge-эндпоинты — дополнительно 30 req/min на pubkey; аутентифицированные — 120 req/min на entity. Ответы 429 включают `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `Retry-After`.
- **Max payload:** 64 KB.
- **Cache:** `Cache-Control: no-store, no-cache, private`.
- **Logging:** тела запросов **не логируются** (zero-logging), только метаданные.
- **CORS:** allowlist (web UI, known agents).
- **TLS:** 1.3 only.
- **Ошибки:** RFC 7807-подобное тело `{ code, level, message, details? }`; коды совместимы с таксономией `AttestationError`/`CryptoError` из `@me2em/*` (`MALFORMED`, `BAD_SIGNATURE`, `EXPIRED`, `REVOKED`, `SUBJECT_MISMATCH`, `AUDIENCE_NOT_PERMITTED`, `UNSUPPORTED_VERSION`, ...).

#### 5.0.1. Канонический подписываемый payload challenge (новое)

Все challenge-response операции подписывают **строго определённую** байтовую последовательность (domain separation — защита от replay между register/login и другими Me2eM-протоколами):

```
message = ascii("we2em/challenge/v1")
       || 0x00
       || ascii(purpose)            // "register" | "login"
       || 0x00
       || uuidParse(challengeId)    // 16 байт, RFC 4122
       || nonce                     // 32 байта, base64url-декодированные
signature = Ed25519_sign(entity_privkey, message)   // verifyRaw из @me2em/crypto
```

Клиентские реализации (SDK, CLI, MCP) обязаны использовать ровно эту конкатенацию; тест-векторы публикуются в `specs/challenge-vectors.json` репозитория we2em. Сервер принимает только подпись этого payload — подпись «голого» nonce отвергается.

### 5.1. Регистрация (Self Custody)

#### 5.1.1. `POST /api/v1/auth/register/init`

**Request:**

```json
{
  "pubkey": "<base64url 32B Ed25519 public key>",
  "key_kind": "identity",
  "entity_type": "human" | "agent" | "bot" | "iot" | "robot",
  "display_name": "Alice"        // optional
}
```

**Response (200 OK) — одинаковый для существующего и нового pubkey (анти-перечисление):**

```json
{
  "challengeId": "uuid",
  "nonce": "<base64url 32B>",
  "purpose": "register",
  "expires_in": 60
}
```

**Поведение:**
- Nonce сохраняется в Redis `nonce:{challengeId}` с TTL 60s (внутри — факт «pubkey уже существует», если это так).
- Ответ по форме/времени идентичен для обоих случаев.

#### 5.1.2. `POST /api/v1/auth/register/complete`

**Request:**

```json
{
  "challengeId": "uuid",
  "signature": "<base64url 64B, см. §5.0.1>"
}
```

**Response (201 Created):**

```json
{
  "entityId": "uuid",
  "sessionToken": "wem_<base64url>",   // Tier-1
  "expires_in": 3600
}
```

**Поведение:**
- `GETDEL nonce:{challengeId}` — атомарно.
- `verifyRaw(pubkey, message, signature)` по каноническому payload §5.0.1 → если false, `401` (единый ответ «invalid signature or unknown challenge»).
- Если pubkey существует и подпись верна → `409 Conflict` (легитимный владелец узнаёт о конфликте; посторонний — не может, т.к. не владеет ключом).
- Создаёт `entities` запись.
- Выпускает Tier-1 session (§4.6): случайный токен, sha256 в `server_sessions`.

**Ошибки:**

| Код | Причина |
|---|---|
| `400 Bad Request` | Невалидный JSON, неизвестный `key_kind`/`entity_type` |
| `401 Unauthorized` | Неверная подпись / challenge expired / unknown challengeId |
| `409 Conflict` | Pubkey уже существует (только при валидной подписи владельца) |

### 5.2. Вход

#### 5.2.1. `POST /api/v1/auth/login/init`

**Request:**

```json
{ "pubkey": "<base64url 32B>" }
```

**Response (200 OK) — одинаковый для существующего и несуществующего pubkey (анти-перечисление; в v1.0 был 404, что раскрывало реестр):**

```json
{
  "challengeId": "uuid",
  "nonce": "<base64url 32B>",
  "purpose": "login",
  "expires_in": 60
}
```

#### 5.2.2. `POST /api/v1/auth/login/complete`

**Request:**

```json
{
  "challengeId": "uuid",
  "signature": "<base64url 64B>"
}
```

**Response (200 OK):**

```json
{
  "entityId": "uuid",
  "sessionToken": "wem_<base64url>",   // Tier-1
  "expires_in": 3600
}
```

**Поведение:**
- `GETDEL nonce:{challengeId}`; `verifyRaw` по §5.0.1.
- Несуществующий pubkey / неверная подпись → единый `401` (без различения).
- Успех → `UPDATE entities SET last_seen_at = now()` → выпуск Tier-1 session.

### 5.3. Session (Tier-1)

#### 5.3.1. `GET /api/v1/auth/session/verify`

**Request:**

```http
GET /api/v1/auth/session/verify HTTP/1.1
Authorization: Bearer wem_<base64url>
```

**Response (200 OK):**

```json
{
  "entityId": "uuid",
  "pubkey": "<base64url 32B>",
  "key_kind": "identity",
  "entity_type": "agent",
  "scopes": ["read", "write"],
  "expiresAt": 1735000000,
  "jti": "uuid"
}
```

**Ошибки:** `401 Unauthorized` (невалидный/просроченный), `403 Forbidden` (revoked). Lookup — constant-time по `token_hash`.

#### 5.3.2. `POST /api/v1/auth/logout`

**Request:** `Authorization: Bearer wem_...`

**Response:** `204 No Content`.

**Поведение:** `UPDATE server_sessions SET revoked_at` + `INSERT INTO revocations (jti=session_id)` + `SET revoked:{jti}` в Redis.

### 5.4. Session (Tier-2, Me2eM) — верификация как сервис (новое)

#### 5.4.1. `POST /api/v1/verify/session`

Верификация Me2eM session token для ресурсных серверов экосистемы (например, t2em v2.0). Сервис-агностик: any verifier может делать это сам по документации протокола; endpoint — удобство и единая точка обновления логики.

**Request:**

```json
{
  "sessionToken": "<base64url payload>.<base64url signature>",
  "attestationChain": ["<attestHandle token>", "<attestSubHandle token>?"],
  "expectedAudience": "t2em.com"
}
```

**Поведение:**
- `Session.verifyAttested(sessionToken, rootPublicKey, attestationChain, expectedAudience, revocationChecker)`:
  - `rootPublicKey` — pubkey issuer-entity, найденного по корневой аттестации цепочки (реестр `entities` + `attestations`);
  - `revocationChecker` — Redis `revoked:{jti}` + таблица `revocations` (контракт `RevocationChecker` из `@me2em/core`).
- Длина цепочки: 1 (Handle-сессия) или 2 (SubHandle-сессия).
- Проверяются: гранты (scopes ⊆ grant, ttl ≤ maxSessionTtl, aud ∈ audiences), сроки, подписи всех уровней, revocation всех `jti`.

**Response (200 OK):**

```json
{
  "valid": true,
  "hId": "<base64url pubkey>",
  "hNm": "agent-github-bot",
  "entityId": "uuid",
  "scopes": ["read:github-token"],
  "expiresAt": 1735003600
}
```

**Ошибки (тело отражает `AttestationError.code`):** `400` MALFORMED, `401` BAD_SIGNATURE / EXPIRED / NOT_YET_VALID, `403` REVOKED / AUDIENCE_NOT_PERMITTED / SUBJECT_MISMATCH.

### 5.5. Attestation

#### 5.5.1. `POST /api/v1/attestations`

**Request:**

```json
{ "attestationToken": "<base64url Attestation token>" }
```

**Response (201 Created):**

```json
{
  "attestationId": "uuid",
  "issuerEntityId": "uuid",
  "subjectEntityId": "uuid | null",
  "issuedAt": 1735000000,
  "expiresAt": 1737600000
}
```

**Поведение:**
- `Attestation.decode(token)` → проверка структуры, `typ == "me2em/attestation/v1"`, payload ≤ 2048 B (`ATTESTATION_MAX_PAYLOAD`).
- `Attestation.verifySignature(token, issuerPubkey)`.
- Проверка: `issuer_pubkey` существует в `entities` (иначе `404`).
- Subject автосоздание: если `subject_pubkey` не существует — создаваемая запись имеет `entity_type = 'agent'` (по умолчанию), `key_kind = 'handle'`, `discoverable = false`.
- `INSERT INTO attestations` (idempotent по `jti` — повторная отправка того же токена возвращает существующую запись).

**Два способа выпуска attestation (подтверждено кодом `@me2em/core`):**

| Способ | API ядра | Когда |
|---|---|---|
| **Derived handle** | `identity.attestHandle(name, grant)` — ядро само выводит Handle из seed | Стандартный путь: агент получает производный ключ от владельца |
| **External key** | `Attestation.issue(ownerIdentity, subjectPubkey, subjectName, grant)` — аттестация произвольного 32B pubkey | Агент сгенерировал собственный ключ (MCP `we2em_keygen`); владелец подписывает привязку |

**Ошибки:** `400` (невалидный token / payload > 2048 B), `401` (неверная подпись), `404` (issuer не существует), `409` (jti уже зарегистрирован с другим токеном).

#### 5.5.2. `GET /api/v1/attestations/:attestationId`

Возвращает attestation (токен, payload, статус revocation).

#### 5.5.3. `GET /api/v1/attestations?subject=<subjectIdBase64url>` (новое)

Разрешение цепочки аттестаций по subject pubkey — для верификаторов Tier-2 (замена «grab from chat»).

**Response (200 OK):**

```json
{
  "subjectId": "<base64url>",
  "chain": ["<attestHandle token>"],
  "rootPublicKey": "<base64url, pubkey issuer-entity>"
}
```

Для SubHandle — `chain` из 2 токенов. Это публикуемый источник цепочек: ресурсный сервер не должен доверять цепочке, переданной самим клиентом, без сверки с реестром.

#### 5.5.4. `DELETE /api/v1/attestations/:attestationId`

Отзыв attestation (только issuer; проверка `issuer_entity_id == session.entityId`); каскад: `revocations` + Redis `revoked:{jti}`.

### 5.6. Sessions для attested-агентов (новое)

Агент с attested Handle не проходит login/init (его ключ — не root). Он получает доступ двумя путями:

1. **Tier-2 (основной):** сам создаёт `Session.create(handle, { audience: 't2em.com', scopes, ttl })` — ресурсный сервер верифицирует через §5.4.1 или самостоятельно.
2. **Tier-1 (для API we2em, опционально):** агент подписывает challenge (§5.0.1, purpose=`login`) своим **handle-приватным ключом**; сервер находит entity по `pubkey` (key_kind=`handle`), проверяет наличие действующей аттестации от активного issuer и выпускает `wem_...`-токен с грантами, ограниченными attestation grant (scopes ⊆ grant.scopes, ttl ≤ maxSessionTtl).

### 5.7. Реестр публичных ключей

#### 5.7.1. `GET /api/v1/keys/:pubkeyBase64url`

**Response (200 OK):**

```json
{
  "entityId": "uuid",
  "pubkey": "<base64url 32B>",
  "key_kind": "handle",
  "entity_type": "agent",
  "display_name": "github-bot",
  "status": "active",
  "hasActiveAttestation": true,
  "createdAt": 1735000000,
  "lastSeenAt": 1735100000
}
```

Lookup по точному pubkey — всегда доступен (это основа Mode A key discovery в t2em v2.0). Ошибка: `404 Not Found`.

#### 5.7.2. `GET /api/v1/keys?type=agent&status=active`

**Поиск — только `discoverable = true`** (privacy-решение v2.0: каталог не публикует всех подряд).

| Параметр | Тип | Описание |
|---|---|---|
| `type` | string | `human` / `agent` / `bot` / `iot` / `robot` |
| `status` | string | `active` / `suspended` / `revoked` |
| `cursor` | string | Pagination cursor |
| `limit` | number | Max 100, default 20 |

**Response (200 OK):** `{ "entities": [ ... ], "nextCursor": "uuid" | null }`

Флаг `discoverable` переключается владельцем: `PATCH /api/v1/entities/me { "discoverable": true }`.

### 5.8. Cloud Backup

**Требование v2.0:** все backup-операции требуют аутентифицированной сессии владельца (Tier-1 `Authorization: Bearer wem_...` с `session.entityId == entityId`). В v1.0 `POST /backup/init` не требовал auth — это позволяло любому субъекту, знающему pubkey, затереть чужой backup (исправлено).

#### 5.8.1. `POST /api/v1/backup/init`

**Request:**

```json
{
  "encryptedSeed": "<base64url>",
  "kdfProfile": "INTERACTIVE" | "SENSITIVE",
  "kdfSalt": "<base64url 16B>",
  "kdfParams": { "memory": 65536, "iterations": 3, "parallelism": 1 },
  "checksum": "<base64url 32B sha256(encryptedSeed)>"
}
```

**Поведение:** auth обязателен; `entityId` берётся из сессии (не из тела). `INSERT INTO cloud_backups` (upsert по entity — повторная инициализация заменяет запись после подтверждения восстановления). Профиль и параметры KDF валидируются против `ARGON2_PROFILES` из `@me2em/crypto` (client-side: `deriveKeyArgon2id`, `generateArgon2Salt`, `encryptAead`).

#### 5.8.2. `GET /api/v1/backup/me`

Возврат `encrypted_seed` + KDF-метаданных владельцу (только своя запись; эндпоинт `:entityId` из v1.0 заменён на `/me` — исключает перечисление entityId).

#### 5.8.3. `DELETE /api/v1/backup/me`

`204 No Content`; удаляет запись (+ зеркала в R2 — v2.0); `UPDATE entities SET has_cloud_backup = false`.

### 5.9. Revocation

#### 5.9.1. `POST /api/v1/revocations`

**Request:** `{ "jti": "uuid", "reason": "compromised" }`

**Поведение:** проверка владения (`jti` — jti attestation, где caller = issuer, или `session_id`, где caller = владелец сессии). `INSERT INTO revocations` + Redis `revoked:{jti}`. Атомарно в транзакции.

#### 5.9.2. `GET /api/v1/revocations/:jti`

**Response (200 OK):** `{ "jti": "...", "revoked": true, "revokedAt": ..., "reason": "..." }`
**Response (404 Not Found):** jti не отозван.

**Контракт для `RevocationChecker`:** 200 → revoked, 404 → not revoked; верификаторы кэшируют 200-ответы на `max(ttl до exp, 60s)`.

### 5.10. SSO (OAuth 2.0 / OIDC)

#### 5.10.0. Транспортные требования (новое)

- Веб-флоу SSO использует cookie-сессию we2em: имя `__Host-we2em_session`, `HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=3600` (префикс `__Host-` запрещает subdomain-передачу).
- CSRF: параметр `state` обязателен; PKCE (`S256`) обязателен для всех клиентов; cookie-сессия SameSite=Lax.
- API (не SSO) — cookies не использует (Bearer only); двойной транспорт не смешивается: `authorize` принимает только cookie-сессию, `token` — только `application/x-www-form-urlencoded` по спецификации OAuth.
- `id_token` подписывается **ключами самого we2em** (issuer keys, EdDSA/Ed25519, JWKS §5.10.4) — это независимые ключи IdP, не ключи клиентов. Rotation: минимум 2 активных `kid`, смена — добавлением нового ключа в JWKS до вывода старого.

#### 5.10.1. `GET /api/v1/sso/authorize`

**Query params:** `client_id`, `redirect_uri`, `scope`, `state`, `code_challenge`, `code_challenge_method=S256`, (optional) `prompt=login`.

**Response:** Redirect на login (если нет cookie-сессии) или на `redirect_uri?code=...&state=...`.

#### 5.10.2. `POST /api/v1/sso/token`

**Request (`application/x-www-form-urlencoded`):** `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`, `code_verifier`.

**Response (200 OK):**

```json
{
  "access_token": "wem_<base64url>",   // Tier-1 сессия we2em от имени пользователя
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "<base64url>",      // v1.1, см. резолюцию открытого вопроса №2
  "id_token": "<JWT EdDSA>"
}
```

**`id_token` claims:** `iss=https://we2em.com`, `sub=<entityId>`, `aud=<client_id>`, `exp`, `iat`, `nonce`, `entity_type`, `display_name` (если задан). **Claims email/phone не выдаются** — we2em их не хранит.

#### 5.10.3. `GET /api/v1/sso/.well-known/openid-configuration`

```json
{
  "issuer": "https://we2em.com",
  "authorization_endpoint": "https://we2em.com/api/v1/sso/authorize",
  "token_endpoint": "https://we2em.com/api/v1/sso/token",
  "jwks_uri": "https://we2em.com/api/v1/sso/jwks",
  "userinfo_endpoint": "https://we2em.com/api/v1/sso/userinfo",
  "scopes_supported": ["openid", "profile", "entity"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code"],
  "code_challenge_methods_supported": ["S256"],
  "id_token_signing_alg_values_supported": ["EdDSA"],
  "claims_supported": ["sub", "entity_type", "display_name", "updated_at"]
}
```

*(Scope `email` из v1.0 удалён — противоречие no-PII модели; `entity` — кастомный scope, отдающий `entity_type`.)*

#### 5.10.4. `GET /api/v1/sso/jwks`

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "<base64url pubkey>",
      "kid": "<key_id>",
      "use": "sig",
      "alg": "EdDSA"
    }
  ]
}
```

### 5.11. `GET /llms.txt` — документация для AI-агентов

Содержание — как в v1.0 (обнаружение, quick start, endpoints, entity types, errors), плюс: канонический payload challenge (§5.0.1), различие Tier-1/Tier-2 сессий, указание, что Me2eM-сессии агент создаёт сам (`Session.create`), а we2em только верифицирует. Генерируется из OpenAPI при сборке.

### 5.12. `GET /health`

```json
{ "status": "ok", "postgres": "ok", "redis": "ok", "version": "1.0.0" }
```

503 при деградации любого компонента.

### 5.13. OpenAPI 3.1

`GET /openapi.json` — полная спецификация; `Cache-Control: public, max-age=300`.

---

## 6. Сценарии использования

### 6.1. User Journey: человек регистрируется (Self Custody)

**Персона:** Алиса — хочет создать Identity для входа в t2em.com.

**Шаги:**

1. **Алиса открывает** `https://we2em.com/register`, выбирает «Self Custody».
2. **Клиент генерирует** BIP39 seed (12 слов), показывает Алисе; Алиса записывает seed и подтверждает (выбор 3 слов).
3. **Клиент деривирует** Identity (`Identity.fromSeed` → root keypair).
4. **Клиент → Сервер:** `POST /auth/register/init { pubkey, key_kind: "identity", entity_type: "human" }` → `{ challengeId, nonce }`.
5. **Клиент подписывает** канонический payload (§5.0.1, purpose=`register`), отправляет `complete`.
6. **Сервер:** verify → создаёт entity → выпускает Tier-1 session (`wem_...`).
7. **Клиент** сохраняет session в cookie web UI (HttpOnly) / IndexedDB для SDK; seed — только на бумаге у Алисы; RAM затирается (`secureWipe`).
8. **Алиса** входит в t2em.com через SSO (§6.5).

**Гарантии:** seed/приватный ключ не на сервере; сервер знает только pubkey; сессия отзываема (logout → revocation).

### 6.2. User Journey: человек регистрируется (Cloud Backup)

**Персона:** Боб — хочет Cloud Backup (боится потерять seed).

**Шаги:**

1. **Боб** выбирает «Cloud Backup», вводит сильный пароль (локальная проверка сложности; опционально HIBP k-anonymity range check на клиенте).
2. **Клиент генерирует** seed и Identity, проходит register init/complete (как §6.1).
3. **Клиент шифрует seed локально:** `salt = generateArgon2Salt(profile)`; `key = deriveKeyArgon2id(password, salt, profile)`; `{ ciphertext, iv } = encryptAead(importAeadKey(key), seed)`.
4. **Клиент → Сервер (аутентифицированно):** `POST /backup/init { encryptedSeed, kdfProfile, kdfSalt, kdfParams, checksum }`.
5. **Сервер сохраняет** запись в PostgreSQL; `has_cloud_backup = true`.
6. **Клиент уничтожает** seed и ключи в RAM (`secureWipeMultiple`).
7. **Восстановление:** пароль → `GET /backup/me` → `deriveKeyArgon2id` → `decryptAead` → seed.

**Гарантии:** сервер хранит только ciphertext; пароль/ключ не покидают клиента; KDF-профиль SENSITIVE удорожает офлайн-перебор.

### 6.3. User Journey: AI-агент регистрируется сам (external key)

**Персона:** Claude Code (AI-агент) хочет зарегистрироваться в we2em.

**Шаги:**

1. **Агент** вызывает MCP-tool `we2em_keygen` → MCP генерирует Ed25519 keypair, privkey в `InMemorySecretVault`, возвращает `{ pubkey, key_id }`.
2. **Агент** вызывает `we2em_register { pubkey, entity_type: "agent" }`.
3. **MCP → Сервер:** register init/complete (§5.0.1, подпись privkey из vault).
4. **Сервер → MCP:** `{ entityId, sessionToken }` (Tier-1); MCP сохраняет токен в vault, возвращает агенту `secret_handle`.
5. **Агент** использует `we2em_http_request` с подстановкой токена.

**Гарантии:** приватный ключ и токен — не в LLM-контексте (только `secret_handle`); агент — равноправный participant (`entity_type: "agent"`, `key_kind: "identity"`); впоследствии владелец может привязать этот ключ аттестацией (§6.4, external key).

### 6.4. User Journey: Owner делегирует агенту

**Персона:** Алиса (Owner) хочет делегировать агенту `agent-github-bot` доступ к GitHub.

**Шаги (derived handle — стандартный путь):**

1. **Алиса** в Web UI: «Создать агента».
2. **Клиент** деривирует Handle: `identity.deriveHandle("agent-github-bot")`.
3. **Клиент** создаёт attestation: `identity.attestHandle("agent-github-bot", { audiences: ["t2em.com"], scopes: ["read:github-token"], maxSessionTtl: 300 })`.
4. **Клиент → Сервер:** `POST /attestations { attestationToken }`; subject ещё не зарегистрирован → `subject_entity_id = NULL`.
5. **Клиент передаёт** агенту производный приватный ключ Handle (через t2em Mode A дроп — сквозная интеграция продуктов) и `{ attestationToken }` (публичные данные).
6. **Агент** регистрирует pubkey (`register/init+complete`, `key_kind: "handle"`) → сервер связывает запись с attestation (subject match) → entity `agent` с `hasActiveAttestation=true`.
7. **Агент** создаёт Tier-2 сессию сам: `Session.create(handle, { audience: "t2em.com", scopes: ["read:github-token"], ttl: 300 })`.
8. **t2em.com** верифицирует через we2em: `GET /attestations?subject=<hId>` → chain + root key → `Session.verifyAttested`-логика (§5.4.1) → гранты соблюдены.

**Вариант external key:** если агент уже имеет собственный ключ (§6.3), владелец выпускает attestation через `Attestation.issue(ownerIdentity, agentPubkey, "agent-github-bot", grant)` — остальной флоу идентичен.

**Гарантии:** attestation подписана владельцем; гранты (audiences/scopes/maxSessionTtl) enforced при каждой верификации; отзыв аттестации мгновенно рвет Tier-2 доступ (revocation checker).

### 6.5. User Journey: SSO в t2em.com

**Персона:** Боб (зарегистрирован в we2em) хочет войти в t2em.com.

**Шаги:**

1. **Боб** открывает `https://t2em.com`, нажимает «Login with we2em».
2. **Redirect:** `we2em.com/api/v1/sso/authorize?client_id=t2em&redirect_uri=...&scope=openid+profile+entity&state=...&code_challenge=...&code_challenge_method=S256`.
3. **we2em:** cookie-сессия Боба валидна → redirect `t2em.com?code=...&state=...` (иначе — форма login challenge).
4. **t2em → we2em:** `POST /sso/token { code, code_verifier }`.
5. **we2em:** возвращает `{ access_token (Tier-1), id_token (EdDSA JWT), refresh_token (v1.1) }`.
6. **t2em** валидирует `id_token` по JWKS (EdDSA, kid rotation), использует `sub` (=entityId) как идентификатор пользователя; профильных данных больше нет — и не нужно.

**Гарантии:** OAuth2/OIDC стандарт; PKCE S256; `state` + SameSite (CSRF); нет email/PII в токенах.

---

## 7. Требования к реализации

### 7.1. API-First

- Все операции — JSON-эндпоинты; OpenAPI 3.1 на `GET /openapi.json`; OIDC discovery (§5.10.3); `llms.txt` генерируется из OpenAPI.

### 7.2. CLI (`we2em-cli`)

**Установка:** `npm install -g @we2em/cli`

**Команды:**

```bash
# Генерация Identity из новой seed-фразы
$ we2em-cli keygen --out ./identity.key
<base64url-pubkey>

# Регистрация (Self Custody)
$ we2em-cli register --key ./identity.key --type human
Registered: entity_id=uuid

# Вход
$ we2em-cli login --key ./identity.key
Session: wem_... (saved to session file 0600)

# Создание агента (derived handle)
$ we2em-cli agent create --name agent-github-bot --owner-key ./identity.key
Agent handle: agent-github-bot, pubkey=<base64url>

# Делегирование (attestation)
$ we2em-cli attest --issuer-key ./identity.key --subject-pubkey <pubkey> \
    --audiences t2em.com --scopes read:github-token --max-session-ttl 300
Attestation: <token>

# Проверка Tier-1 сессии
$ we2em-cli session verify
Valid: entity_id=uuid, expires_at=...

# Верификация Tier-2 сессии (для ресурсных серверов)
$ we2em-cli verify --token <session-token> --audience t2em.com
Valid: hNm=agent-github-bot, scopes=[read:github-token]

# Отзыв
$ we2em-cli revoke --jti <jti> --reason compromised
Revoked
```

**Требования:** UNIX-пайпы; секреты не в аргументах (только `--key-file`/stdin); права файлов `0600`; `secureWipe` после использования; диагностика в stderr.

### 7.3. Python SDK (`we2em`)

**Установка:** `pip install we2em` (backup-функции: `pip install "we2em[backup]"`)

**API:**

```python
from we2em import We2emClient, generate_identity, attest

client = We2emClient("https://we2em.com")

# Регистрация
identity = generate_identity()                  # Ed25519 keypair (PyCA cryptography)
session = client.register(identity, entity_type="agent")

# Вход
session = client.login(identity)                # challenge §5.0.1 под капотом

# Делегирование
attestation = attest(
    issuer_identity=owner_identity,
    subject_pubkey=agent_pubkey,
    audiences=["t2em.com"],
    scopes=["read:github-token"],
    max_session_ttl=300,
)
client.register_attestation(attestation)

# SSO
token = client.sso_token(code, code_verifier)
```

**Требования (уточнено в v2.0):**

- **Сеть:** только stdlib `urllib`.
- **Криптография:** **PyCA `cryptography`** (Ed25519: `generate_identity`, подпись challenge, verify) — обязательная зависимость; **`argon2-cffi`** — optional extra `[backup]` (Argon2id для Cloud Backup). Hand-rolled crypto запрещён.
- **Bit-compatible** с TypeScript; общие тест-векторы challenge и attestation.
- Type hints; Python ≥ 3.10.

### 7.4. MCP Server (`@we2em/mcp-server`)

**Tools:**

| Tool | Параметры | Возвращает |
|---|---|---|
| `we2em_keygen` | — | `{ pubkey, key_id }` (privkey в vault) |
| `we2em_register` | `{ pubkey, entity_type }` | `{ entityId, secret_handle }` |
| `we2em_login` | `{ pubkey }` | `{ entityId, secret_handle }` |
| `we2em_attest` | `{ issuer_key_id, subject_pubkey, audiences, scopes, max_session_ttl }` | `{ attestationToken }` |
| `we2em_register_attestation` | `{ attestationToken }` | `{ attestationId }` |
| `we2em_verify_session` | `{ session_handle, expected_audience }` | `{ valid, entityId, scopes, expiresAt }` |
| `we2em_http_request` | `{ url, method, headers?, body? }` | `{ status, headers, body }` |
| `we2em_wipe` | `{ handle }` | `{ ok }` |

**Требования:**

- **InMemorySecretVault:** privkey, session tokens в RAM MCP-процесса; `secret_handle` = `sec_<uuid>`.
- **`we2em_http_request`:** SSRF-защита идентична t2em (`TZ_t2em.md` §8.4): deny-list приватных сетей, https-only, DNS pinning, ручная обработка редиректов.
- **Challenge-подпись:** строго канонический payload §5.0.1.
- Zero-logging; `secureWipe` после `we2em_wipe`.

### 7.5. Токенизация для LLM

| Использовать | Не использовать |
|---|---|
| Entity | User, subject, party |
| Identity | Account, profile |
| Handle | Context, namespace |
| Attestation | Delegation, grant |
| Session (Tier-1/Tier-2) | Token, JWT (в общих текстах) |
| Pubkey | Public key, address |
| Challenge | Nonce (в доках), handshake |
| Revoke | Invalidate, cancel |

### 7.6. Инфраструктура (Cloudflare)

- DNSSEC; HSTS `max-age=63072000; includeSubDomains; preload`; TLS 1.3 only.
- WAF (Managed + OWASP); DDoS protection; Bot management.
- Rate limiting: edge (Cloudflare) — per IP; Redis — per IP + per pubkey (challenge) + per entity (authed).
- Zero-logging тел запросов; security-события — с `sha256(ip)`, `sha256(user-agent)`.
- Workers: Hono, cold start ≤ 50ms, bundle ≤ 1 MB.

### 7.7. Безопасность (сводно)

- Канонический домен-сепарированный challenge payload (§5.0.1) — единственная принимаемая подпись.
- Анти-перечисление на init-эндпоинтах (§5.1.1, §5.2.1); единый 401 на complete.
- Constant-time compare: token_hash lookup, подписи не требуют CT (Ed25519 verify — total function), jti-сравнения в БД.
- `GETDEL` nonce — атомарное одноразовое использование.
- Revocation проверяется при каждой session verify (Tier-1) и в verify-as-service (Tier-2).
- Argon2id — только на клиенте; сервер хранит ciphertext и KDF-параметры.
- KMS/SSE для R2-зеркала (v2.0) — гигиена носителя, не замена клиентскому шифрованию.
- SSRF-guard MCP (§7.4); CSP и nosniff для Web UI; audit без секретов (application guard + тест).

---

## 8. Тестирование

### 8.1. Unit-тесты (покрытие ≥ 85% строк, ≥ 75% веток — выше порога экосистемы 90% для core-пакетов недостижимо на старте, к v1.1 — подтянуть до 90/85)

- `@we2em/idp-core`: challenge payload builder (векторы), session issuance/verification (Tier-1), grant-nesting для Tier-1 на attested-хэндлах, attestation decode/verify (в т.ч. `Attestation.issue` external key), revocation state machine, backup upsert.
- `@we2em/relay-server`: handlers (mock PG/Redis), анти-перечисление (равенство ответов init), rate limits, error mapping (`AttestationError.code` → HTTP).

### 8.2. Integration-тесты

- Полный флоу register → session → verify → logout → verify (403).
- Login с несуществующим pubkey → init 200 → complete 401 (анти-перечисление).
- Attestation: register subject post-facto (§6.4 шаг 6) — связывание.
- verify-as-service: валидная цепочка (1 и 2 токена), отозванный issuer, отозванный session jti, нарушенный grant (scope/ttl/aud).
- Backup: init → fetch → restore-расшифровка клиентом (E2E с реальным Argon2id).
- Cleanup jobs: audit retention, expired sessions, revocations.

### 8.3. Security-тесты

- Fuzzing всех challenge/complete эндпоинтов (10k итераций).
- Replay challenge (повторный complete с тем же challengeId → 401).
- Cross-protocol replay: подпись «голого» nonce / nonce другого purpose → 401.
- Timing: init для существующего/несуществующего pubkey — распределения неотличимы (стат-тест).
- JSON `__proto__` → `safeJsonParse` отклоняет.
- SSRF-набор для MCP (как в `TZ_t2em.md` §9.3).
- Audit guard: попытка записать секрет в metadata → отклонение + алерт.

### 8.4. Load-тесты (k6)

- Baseline 100 RPS (login flow), p95 < 150ms; Peak 500 RPS (verify-session), p95 < 300ms; Spike 2000 RPS (keys lookup, cacheable), p95 < 500ms.

### 8.5. E2E (Playwright)

- Web UI: register Self Custody (подтверждение seed), register Cloud Backup + restore, SSO-флоу в тестовый RP, logout, revoke attestation.

---

## 9. Требования к безопасности (детально)

### 9.1. Zero-Knowledge

- Сервер не видит приватные ключи и seed (кроме opt-in ciphertext); пароли не покидают клиент; OPAQUE не используется (резолюция №1 — переоценка в v1.2, если появится требование password uniqueness).

### 9.2. Анти-перечисление и replay

- Init-эндпоинты не раскрывают существование pubkey (форма+время ответа).
- Complete-эндпоинты дают единый 401 для «неверная подпись» / «истёк challenge» / «неизвестный challengeId».
- Домен-сепарация `we2em/challenge/v1` + purpose + challengeId + nonce исключает переиспользование подписей в других протоколах экосистемы.

### 9.3. Криптография

- Только `@me2em/crypto` примитивы (`verifyRaw`, `generateX25519KeyPair`, `deriveKeyArgon2id`, `encryptAead`, `secureWipe`, ...); запрет hand-rolled; `Math.random()` запрещён; Ed25519 verify — total function.
- Изменение канонической строки challenge — только через `/v2` (freeze-правило PLAN-LTS §4).

### 9.4. Веб-безопасность

- Cookies: `__Host-we2em_session`, HttpOnly, Secure, SameSite=Lax; CSP строгий; `X-Content-Type-Options: nosniff`; `Referrer-Policy: no-referrer`.
- CSRF SSO: `state` + PKCE + SameSite; без cookies на API.
- Anti-clickjacking: `X-Frame-Options: DENY`.

### 9.5. Атаки и защита

| Атака | Защита |
|---|---|
| Replay challenge | GETDEL + TTL 60s + domain separation |
| Enumeration pubkey | Uniform init responses, единый 401 |
| Атака на backup (overwrite) | Auth required, entityId из сессии (§5.8) |
| Offline crack backup | Argon2id SENSITIVE (клиент), сильный пароль, HIBP k-anonymity (клиент) |
| Token theft (Tier-1) | sha256-only хранение, TTL 1h, revocation, TLS 1.3 |
| Session forgery (Tier-2) | Ed25519 подписи, verifyAttested гранты, revocation checker |
| SSRF (MCP) | Deny-list, DNS pinning, redirect policy |
| DoS | Rate limit per IP/pubkey/entity, WAF, max payload |
| Prompt injection | `secret_handle`, no plaintext в LLM-контексте |
| Audit tampering | append-only партиции, ограниченные права записи |

### 9.6. Supply chain

- Зависимости: `@me2em/core`, `@me2em/crypto`, PyCA `cryptography`, `argon2-cffi`.
- `pnpm audit` blocking; Dependabot; lockfile committed; SBOM (CycloneDX); npm Provenance; gitleaks; CodeQL.

### 9.7. Аудит

- Внешний аудит перед v1.0; bug bounty после; `SECURITY.md` с responsible disclosure; CVE через MITRE.

---

## 10. Документация

| Документ | Аудитория |
|---|---|
| `README.md`, `docs/` (VitePress) | Все |
| `llms.txt` (генерируется) | AI-агенты |
| `openapi.json` (OpenAPI 3.1) | Разработчики |
| `specs/challenge-vectors.json` | Разработчики клиентов |
| `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `LICENSE` (Apache-2.0) | Соответствующие |

Структура `docs/`: index, getting-started (quickstart, cli, python-sdk, mcp), concepts (entity-model, sessions-tiers, attestations, cloud-backup, threat-model), api (reference, errors, rate-limits), deployment (cloudflare, docker, configuration), security, guides (ai-agents, iot-provisioning, sso-integration, resource-server-verification).

---

## 11. Открытые вопросы v1.0 — резолюции

| № | Вопрос | Резолюция |
|---|---|---|
| 1 | Password uniqueness (OPAQUE) | **Убрать.** Не security-critical (пароль защищает только ciphertext backup, который и так не расшифровывается без него). Переоценка в v1.2 |
| 2 | Refresh tokens | **v1.0 — нет** (сессии 1 ч, повторный login). **v1.1 — да** для SSO web-клиентов: ротация при каждом использовании + reuse detection (инвалидация всей цепочки) |
| 3 | Multi-device sync | **v1.0/1.1 — через Cloud Backup restore** (второе устройство восстанавливает seed паролем). Живая синхронизация — v2.0 (R2 история версий) |
| 4 | Federation (we2em.com ↔ self-hosted) | **v1.2 — OIDC federation** (trust по JWKS + allowlist issuers). DID — вне scope |
| 5 | Extension entity_type | **v1.0 — фиксированный CHECK** (5 типов). Новый тип — миграция + CHANGELOG (никаких динамических строк — предсказуемость для LLM). Кандидаты `service`/`contract` — v1.1 по запросу |
| 6 | Audit retention | **90 дней** (партиции), затем безвозвратное удаление. Агрегаты (счётчики событий) — отдельно, без entity-привязки |
| 7 | Rate limit | **Per IP 60/min** (все эндпоинты) + **per pubkey 30/min** (challenge) + **per entity 120/min** (authed). Edge + Redis двухслойно |
| 8 | Attestation size | **2048 B — константа ядра** (`ATTESTATION_MAX_PAYLOAD`), не менять (breaking). Гранты должны укладываться; при нехватке — несколько attestation с разными scopes |
| 9 | SSO scopes | **`openid`, `profile`, `entity`**. `email` удалён (no-PII). `profile` = display_name; `entity` = entity_type |
| 10 | Recovery | **Self Custody:** потеря seed = потеря аккаунта (фича, warning в UI). **Cloud Backup:** восстановление паролем; warning: пароль не восстанавливается |

---

## 12. Риски и митигация

| Риск | Вероятность | Влияние | Митигация |
|---|---|---|---|
| Компромисс PG (все сущности) | Низкая | Высокое | Нет plaintext секретов; backup — ciphertext; opaque-токены — хэши; TLS/RBAC/шифрование дисков |
| Enumeration реестра | Средняя | Среднее | Анти-перечисление (§9.2), discoverable opt-in, rate limit |
| Seed loss (Self Custody) | Средняя | Высокое (для пользователя) | Обучение, Cloud Backup opt-in, восстановление по паролю |
| Weak backup password | Средняя | Высокое | zxcvbn + HIBP на клиенте, Argon2id SENSITIVE |
| Ошибка в verify-as-service | Низкая | Высокое | Реюз `Session.verifyAttested` ядра (протестирован 648 тестами экосистемы), versioned API |
| SSRF через MCP | Средняя | Высокое | Deny-list + DNS pinning + redirect policy |
| Утечка audit-метаданных | Низкая | Среднее | sha256-only, retention 90d, app guard |
| SSO token leak | Низкая | Высокое | PKCE, короткий TTL, refresh rotation (v1.1), JWKS rotation |
| Lock-in managed DB | Низкая | Среднее | Standard Postgres, self-hosted parity (docker compose) |
| Ветеран-сессии после revocation issuer | Средняя | Высокое | RevocationChecker проверяет и attestation jti, и session jti при каждой верификации |

---

## 13. Соответствие (Compliance)

### 13.1. GDPR

**Персональные данные, обрабатываемые we2em:** pubkey + entity_type + display_name (опционально) + `sha256(ip)`/`sha256(user-agent)` (audit/rate limit) + timestamps. Основание — legitimate interest / явное согласие при регистрации (регистрация = активное действие).

- **Data minimization:** email/телефон отсутствуют; display_name и discoverable — опциональны.
- **Right to erasure (ст. 17):** `DELETE /api/v1/entities/me` (v1.1) — каскад: backup удаляется, entity помечается `revoked`, строки audit **анонимизируются** (entity_id → NULL, ip_hash/ua_hash → NULL, event_type сохраняется), pubkey-запись удаляется. Публичные attestation, где субъект — удалённый ключ, сохраняются как криптографические факты, но де-associируются с профилем.
- **Data portability (ст. 20):** `GET /api/v1/entities/me/export` (v1.1) — JSON: entity, attestations (subject), sessions active, backup metadata.
- **Retention:** §4.7.
- **DPIA:** требуется перед запуском (обработка псевдонимизированных данных в масштабе).

### 13.2. SOC 2 (планируется)

Security (TLS 1.3, WAF, rate limit, audit, constant-time), Availability (99.9%, multi-region), Confidentiality (zero-knowledge, encrypted backups), Privacy (§13.1).

### 13.3. Open Source

Apache-2.0; `CONTRIBUTING.md` + DCO; Contributor Covenant; governance по образцу GOVERNANCE.md экосистемы (RFC → lazy consensus; MIP для изменений протокола).

---

## 14. Roadmap

### 14.1. v1.0 (MVP)

- Регистрация/вход (challenge-response, канонический payload), Tier-1 sessions, revocation.
- Attestation registry + chain resolution (`GET /attestations?subject=`).
- Verify-as-service (`POST /verify/session`).
- Реестр ключей (lookup + discoverable-поиск).
- CLI, Python SDK, MCP server, базовый Web UI, `llms.txt`, OpenAPI.
- **Срок:** 12 недель.

### 14.2. v1.1

- Cloud Backup (PG, Argon2id+AES-GCM client-side) + restore-флоу.
- OIDC SSO полный (authorize/token/jwks/discovery/userinfo), refresh tokens с ротацией.
- `DELETE /entities/me` + export (GDPR), Audit UI.
- Coverage 90/85.
- **Срок:** 8 недель.

### 14.3. v1.2

- Delegation chains Owner → Agent1 → Agent2 через SubHandle-аттестации (цепочка из 2 токенов — уже поддержана ядром).
- OIDC federation (cross-IdP, JWKS trust).
- Переоценка OPAQUE.
- **Срок:** 8 недель.

### 14.4. v2.0

- Multi-device sync (R2 история версий backup, presigned TTL 60s).
- w2em registry (человекочитаемые имена — внешний продукт; we2em предоставляет resolution hooks).
- X3DH integration (`wrapKeyForRecipient` из `@me2em/crypto` — offline recipients).
- `@me2em/pact` (криптоаудит), `@me2em/x402` (платежи) — интеграции.
- **Срок:** 12 недель.

---

## 15. Приложения

### A. Пример Entity JSON

```json
{
  "entityId": "550e8400-e29b-41d4-a716-446655440000",
  "pubkey": "5Kd3NBUAdUnhyzenEwVLy9pBKxSwXvE9FMPyR4UKZvpe",
  "key_kind": "handle",
  "entity_type": "agent",
  "display_name": "github-bot",
  "discoverable": false,
  "status": "active",
  "createdAt": 1735000000,
  "lastSeenAt": 1735100000,
  "hasCloudBackup": false
}
```

### B. Пример Attestation JSON

```json
{
  "attestationId": "660e8400-e29b-41d4-a716-446655440001",
  "issuerEntityId": "550e8400-e29b-41d4-a716-446655440000",
  "subjectEntityId": "770e8400-e29b-41d4-a716-446655440002",
  "attestationToken": "<base64url>",
  "payload": {
    "typ": "me2em/attestation/v1",
    "subjectName": "agent-github-bot",
    "subjectId": "<base64url>",
    "grant": {
      "audiences": ["t2em.com"],
      "scopes": ["read:github-token"],
      "maxSessionTtl": 300
    },
    "iat": 1735000000,
    "exp": 1737600000,
    "jti": "880e8400-e29b-41d4-a716-446655440003"
  },
  "issuedAt": 1735000000,
  "expiresAt": 1737600000,
  "revokedAt": null
}
```

### C. Примеры session payload

**Tier-2 Me2eM session (создаётся клиентом, формат ядра):**

```json
{
  "hId": "<base64url handle pubkey>",
  "hNm": "agent-github-bot",
  "aud": "t2em.com",
  "scp": ["read:github-token"],
  "exp": 1735003600,
  "iat": 1735000000,
  "jti": "990e8400-e29b-41d4-a716-446655440004"
}
```

Токен: `base64url(json_payload).base64url(ed25519_signature)` — без JWT header (формат `@me2em/core`).

**Tier-1 server session (выпускается we2em):**

```
Authorization: Bearer wem_9xK2mN8pQ4rT7vW1yZ3aB6cD0eF5gH8iJ2kL4mN6oP8qR1sT3uV
```

(Сервер хранит только sha256; verify возвращает §5.3.1.)

### D. Канонический challenge payload — тест-требования

Реализации обязаны проходить общий набор векторов `specs/challenge-vectors.json`:

- register и login purposes → разные подписи при том же nonce;
- фиксированные векторы (nonce, challengeId, privkey → signature) бит-в-бит совпадают в TS, Python, CLI, MCP;
- подпись «голого» nonce (без префикса) отвергается сервером.

### E. Глоссарий

| Термин | Определение |
|---|---|
| **Entity** | Любая сущность: человек, агент, бот, IoT, робот |
| **Identity** | Корневая идентичность (Ed25519) |
| **Handle** | Контекстная идентичность (derived) |
| **SubHandle** | Leaf-идентичность (derived, MAX_DEPTH=2) |
| **Attestation** | Подписанный грант (делегация), typ me2em/attestation/v1 |
| **Session (Tier-1)** | Opaque серверный токен `wem_...` |
| **Session (Tier-2)** | Me2eM stateless-токен, созданный клиентом |
| **Seed** | BIP39 seed (64 байта) |
| **Challenge-Response** | Подпись канонического payload §5.0.1 |
| **Revocation** | Отзыв attestation/session по jti |
| **SSO** | Single Sign-On (OAuth 2.0 / OIDC) |
| **OIDC** | OpenID Connect |
| **PKCE** | Proof Key for Code Exchange |
| **key_kind** | `identity` или `handle` (§4.1.1.1) |
| **discoverable** | Opt-in флаг публичного поиска |
| **Verify-as-service** | `POST /verify/session` — верификация Tier-2 силами we2em |

---

**Конец документа.**
