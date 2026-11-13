# Ручное приёмочное тестирование t2em — v1.0 (Этапы 1–5)

Чек-лист ручной проверки релиза `Этап 1–5` (Blind Relay + Web UI + protocol
Mode A + CLI + Python SDK + MCP). Каждый пункт: шаг → ожидаемый результат.
Формат отчёта о проблеме: **ID пункта + фактический результат** (пример:
«C8: exit=0, ожидался 2»).

Пометка ✅ = дополнительно подтверждено агентом автоматическим прогоном
того же сценария 2026-11-13 (не отменяет ручного повтора).

---

## 0. Подготовка окружения

| # | Шаг | Ожидание |
|---|-----|----------|
| 0.1 | `node -v` | ≥ 18 (рекомендован 22) |
| 0.2 | `corepack enable && pnpm -v` | pnpm 10.x |
| 0.3 | `git clone git@github.com:me2em-org/t2em.git && cd t2em && pnpm install && pnpm -r build` | сборка без ошибок; есть `packages/*/dist` |
| 0.4 | `alias t2em-cli='"$(pwd)"/packages/cli/dist/main.js'` (в текущую сессию) | `t2em-cli --version` → `t2em-cli 0.1.0 (protocol v1)` ✅ |
| 0.5 | `python3 -m venv .venv && source .venv/bin/activate && pip install -e ./python-sdk` | `python -c "import t2em"` без ошибок |
| 0.6 | MCP-сервер собран | `node packages/mcp-server/dist/main.js` стартует (молча ждёт JSON-RPC на stdin) ✅ |

Всё дальнейшее — против прод-релея `https://t2em.com` (если не указано иное).
Альтернативный хост для 16: `https://siteup24.workers.dev`.

---

## A. Веб-интерфейс t2em.com (браузер, окно инкогнито)

| ID | Шаг | Ожидание |
|----|-----|----------|
| A1 | Открыть `https://t2em.com`, DevTools → Network | 200; все запросы — только к t2em.com, ни одного внешнего домена ✅ |
| A2 | DevTools → Console | нет ошибок CSP, предупреждений о mixed content нет |
| A3 | Ввести секрет, TTL 120, создать | ссылка вида `https://t2em.com/s/<uuid>#<ключ>`; ключ в якоре, не в пути ✅ |
| A4 | Открыть ссылку в новом инкогнито-окне | секрет показан ровно один раз, кнопка копирования работает |
| A5 | F5 (или повторно открыть ту же ссылку) | страница «drop недоступен/уже прочитан», секрета нет ✅ |
| A6 | Открыть ссылку с отрезанным якорем (`/s/<uuid>` без `#…`) | секрет не раскрывается; в Network запросах нет материала ключа |
| A7 | Создать drop с TTL 60, НЕ открывать 70 сек, потом открыть | 404 — drop истёг без чтения ✅ (TTL-клип на сервере) |
| A8 | Создать drop, досрочно уничтожить (delete token из stderr/ответа) | после delete ссылка даёт 404 ✅ |
| A9 | Открыть `/s/00000000-0000-0000-0000-000000000000` | 404, неотличимая страница (анти-перебор) ✅ |
| A10 | DevTools → Application (localStorage/sessionStorage/cookies) | секрет отсутствует в любом storage |
| A11 | Открыть две вкладки с одной свежей ссылкой почти одновременно | секрет получает максимум одна вкладка |
| A12 | Мобильный вьюпорт (DevTools responsive) | UI читабелен, кнопки доступны |

## B. HTTP API (curl, без браузера)

| ID | Шаг | Ожидание |
|----|-----|----------|
| B1 | `curl -s https://t2em.com/health` | 200, статус-тело health-check ✅ |
| B2 | `curl -sI https://t2em.com/ \| grep -i security` | CSP `default-src 'none'`, `script-src 'self'` без `unsafe-inline`; X-Content-Type-Options и т.п. ✅ |
| B3 | Создать drop командой `t2em-cli push --ttl 300` (см. C4) | 201 внутри CLI; stderr содержит drop id и `delete token:` |
| B4 | `curl -s -o /dev/null -w "%{http_code}" -X DELETE https://t2em.com/api/v1/drop/<id>` | `401` (нет токена) ✅ |
| B5 | … с `-H "x-delete-token: $(printf 'f%.0s' {1..64})"` | `403` ✅ |
| B6 | … с верным токеном из stderr шага B3 | `200` ✅ |
| B7 | Повторный GET/DELETE того же id | `404` ✅ |
| B8 | `curl -s -o /dev/null -w "%{http_code}" https://t2em.com/api/v1/drop/<random-uuid>` | `404` (анти-перебор) ✅ |
| B9 | `curl -s -o /dev/null -w "%{http_code}" -X PUT https://t2em.com/api/v1/drop/<id>` | `404/405` — метод не обслуживается |
| B10 | Полный крипто-контур API покрывают скрипты D1/D2 (ручной curl не должен конструировать AES-GCM) | D1/D2 зелёные |

## C. CLI `t2em-cli` (ТЗ §8.2)

Контракт: секреты — только через stdin (`--secret` запрещён); диагностика —
только в stderr; секрет pull — на stdout без хвостового `\n`;
коды выхода: `0` успех, `1` ошибка, `2` неверные аргументы.

| ID | Шаг | Ожидание |
|----|-----|----------|
| C1 | `t2em-cli --help` | help-текст, exit 0 ✅ |
| C2 | `t2em-cli --version` | `t2em-cli 0.1.0 (protocol v1)`, exit 0 ✅ |
| C3 | `t2em-cli keygen --out /tmp/agent.key` | pubkey (43 симв. base64url) на stdout **без** `\n`; `fingerprint: XXXXXXXX` и имя файла в stderr; `ls -l` → `-rw-------` (0600) ✅ |
| C4 | `echo "секрет-123" \| t2em-cli push --ttl 120` | exit 0; URL `https://t2em.com/s/<uuid>#<ключ>` на stdout; drop id + `delete token:` в stderr ✅ |
| C5 | `t2em-cli pull "<url из C4>"` | exit 0; секрет на stdout без хвостового перевода строки (`xxd \| tail -1` не кончается `0a`) ✅ |
| C6 | Повторить C5 с той же ссылкой | exit 1, `t2em-cli: drop not found, expired or already consumed` ✅ |
| C7 | `echo secret \| t2em-cli push --to <pubkey из C3> --ttl 120` | exit 0; `fingerprint:` получателя в stderr (сверить с C3!); URL **без** `#` ✅ |
| C8 | `t2em-cli pull "<url из C7>" --key /tmp/agent.key` | exit 0, секрет на stdout ✅ |
| C9 | `t2em-cli pull "<url из C7>"` (Mode A без --key) | exit 2, `pull needs a Mode B url with #fragment or --key` ✅ |
| C10 | `t2em-cli pull "<url B>#fragment" --key /tmp/agent.key` | exit 2, `#fragment and --key are mutually exclusive` ✅ |
| C11 | `t2em-cli delete "<url>" --token <токен из C4>` | exit 0; затем pull → exit 1 ✅ |
| C12 | `t2em-cli delete "<url>" --token AAAA` | exit 1, `HTTP 403 [FORBIDDEN] Invalid delete token` ✅ |
| C13 | `echo x \| t2em-cli push --secret boom` | exit 2, `--secret is forbidden` ✅ |
| C14 | `echo x \| t2em-cli push --ttl 59` и `--ttl 901` и `--ttl abc` | exit 2, `--ttl must be an integer 60..900` ✅ |
| C15 | `t2em-cli bogus` | exit 2, `unknown command` ✅ |
| C16 | `export T2EM_BASE_URL=https://siteup24.workers.dev`, повторить C4→C6 | полный цикл на workers.dev работает ✅ |
| C17 | `printf '' \| t2em-cli push --ttl 120` (пустой stdin) | exit 1, понятная ошибка без URL ✅ |
| C18 | `t2em-cli keygen` (без --out) | exit 2, `keygen requires --out` ✅ |

## D. NodeJS-скрипты (папка `docs/manual-tests/js/`)

Все три — без npm-зависимостей (только `node:crypto`/глобальный fetch).
D1/D2 — против живого прод-релея; D3 — из корня репо после `pnpm -r build`.

| ID | Команда | Ожидание |
|----|---------|----------|
| D1 | `node docs/manual-tests/js/mode_b_live.mjs` | 15 PASS: create 201 → конверт в HTML → расшифровка → повтор 404 → DELETE-лестница 401/403/200/404 ✅ |
| D2 | `node docs/manual-tests/js/mode_a_live.mjs` | 8 PASS: fingerprint 8 симв., HKDF-ключ 32B, URL без `#`, расшифровка получателем, **чужой ключ не расшифровывает**, повтор 404 ✅ |
| D3 | `node docs/manual-tests/js/vectors_check.mjs` | 6/6 PASS — побитовая совместимость с `vectors/t2em-drop.v1.json` (ascii/utf8/пустой; sym + x25519) ✅ |
| D4 | Повторить D1/D2 с аргументом: `node docs/manual-tests/js/mode_b_live.mjs https://siteup24.workers.dev` | те же PASS на workers.dev |

## E. Python SDK `t2em` (ТЗ §8.3)

| ID | Шаг | Ожидание |
|----|-----|----------|
| E1 | `python3 docs/manual-tests/py/sdk_live.py` | 12 PASS: Mode B push/pull, повтор 404, Mode A, чужой ключ, delete 403/200/404, keyfile 0600 ✅ |
| E2 | `python3 docs/manual-tests/py/sdk_live.py https://siteup24.workers.dev` | те же PASS на workers.dev |
| E3 | `pytest python-sdk/tests -q` | все тесты зелёные (включая бит-совместимость с векторами) |
| E4 | Кросс keyfile: pubkey из E1 → `t2em-cli pull "<mode A url>" --key <файл из E1>` (создав drop через `t2em-cli push --to <pub из E1>`) | CLI и Python читают один формат keyfile ✅ (формат общий) |
| E5 | Ошибочная ветка: `client.pull_text("https://t2em.com/s/00000000-0000-0000-0000-000000000000")` | `HttpError`, `status == 404` — ветвление по таксономии §4.5 работает |

## F. MCP-сервер (ТЗ §8.4)

Подключение: `claude mcp add t2em -- node /abs/path/t2em/packages/mcp-server/dist/main.js`
или в `mcpServers`: `{ "t2em": { "command": "node", "args": ["/abs/path/dist/main.js"] } }`.

| ID | Шаг | Ожидание |
|----|-----|----------|
| F1 | Список инструментов у агента | ровно 6: `t2em_keygen`, `t2em_push`, `t2em_pull`, `t2em_http_request`, `t2em_wipe_secret`, `t2em_list_secrets` ✅ |
| F2 | `t2em_keygen` | приватный ключ остаётся в in-process vault, наружу — fingerprint ✅ |
| F3 | `t2em_push {secret, ttl:300}` | `{url, delete_token, expires_in, mode}`; url t2em.com ✅ |
| F4 | `t2em_pull {url}` | ответ содержит **только** `secret_handle` (`sec_<uuid>`) — самого секрета в ответе нет ✅ |
| F5 | `t2em_list_secrets` | только handles, без значений ✅ |
| F6 | `t2em_http_request {url: https://postman-echo.com/post, method: POST, body: "Bearer {{sec_…}}"}` | 200; эхо-тело содержит подставленный секрет; литеральный текст без `{{}}` не тронут ✅ |
| F7 | Негатив: `t2em_http_request {url: "http://example.com/"}` | `SSRF blocked: only https is allowed, got http:` ✅ |
| F8 | Негатив: `t2em_http_request {url: "https://169.254.169.254/latest/meta-data/"}` | `SSRF blocked: hostname resolves to denied range 169.254.0.0/16` ✅ |
| F9 | Негатив: `t2em_http_request {url: "https://user:pw@example.com/"}` | `SSRF blocked: credentials in url are not allowed` |
| F10 | `t2em_wipe_secret {handle}` → повтор F6 с тем же handle | ошибка unknown handle — секрет стёрт (two-pass) |
| F11 | Логи MCP (stderr/stdout агента) после F3–F6 | нигде нет значения секрета (zero-logging) ✅ |

## G. Кросс-экосистемные проверки (TS ↔ Python)

| ID | Шаг | Ожидание |
|----|-----|----------|
| G1 | `echo cross \| t2em-cli push --ttl 300` → `client.pull_text(<url>)` в Python | один и тот же секрет ✅ |
| G2 | `client.push(secret="cross2", ttl=300)` → `t2em-cli pull <url>` | один и тот же секрет ✅ |
| G3 | Python `client.push(secret=..., recipient_pubkey=<pub CLI>)` → `t2em-cli pull <url> --key <keyfile CLI>` | Mode A между Python-отправителем и CLI-получателем ✅ |
| G4 | D3 (векторы TS) + E3 (векторы Python) на одном `vectors/t2em-drop.v1.json` | обе экосистемы бит-совместимы между собой |

## H. Гигиена и безопасность

| ID | Шаг | Ожидание |
|----|-----|----------|
| H1 | `ls -l` всех keyfile | 0600 на всех (CLI и Python) ✅ |
| H2 | Внимательно перечитать stderr/stdout CLI при push | секрета нет нигде, кроме stdout `pull` (по дизайну) ✅ |
| H3 | `curl -sI https://t2em.com/s/<id> \| grep -i cache` | `Cache-Control: no-store` ✅ |
| H4 | Консоль Upstash → DBSIZE после всех тестов | 0 (все drop потреблены/удалены/истекли) |
| H5 | `git grep -i "<тестовый секрет>"` в репо | пусто — тестовые секреты не попали в код/коммиты |
| H6 | `pnpm audit --prod --audit-level high` в корне | уязвимостей уровня high+ нет |

---

## Приложение. Контракт, на который опирается чек-лист

- TTL-клип: **60..900 c** (меньше/больше → отказ на входе).
- Envelope v1: `{v:1, mode:'sym'|'x25519', ciphertext, iv[, ephemeralPubKey]}`, base64url **без паддинга**.
- POST `/api/v1/drop` → **201** `{id, url, expires_in, delete_token}`; `url` канонический: `https://t2em.com/s/<id>`.
- Браузерный GET `/s/:id` **потребляет** drop: 200 text/html со встроенным
  конвертом (`<script type="application/json" id="t2em-envelope">`), повтор — 404.
- DELETE `/api/v1/drop/:id` c `x-delete-token`: 401 нет токена / 403 неверный / 200 удалён / далее 404.
- HKDF info (freeze §4.5): `me2em/crypto/v1/t2em-drop`; salt Mode A = `eph_pub || recipient_pub`.
- Fingerprint: `base64url(sha256(pubkey))[0..8]` (§4.2.1).
- Источник истины по API: `docs/TZ_t2em.md` §5, §8.2–§8.4; векторы: `vectors/t2em-drop.v1.json`.
