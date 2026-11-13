/**
 * Ручной тест D1 — Mode B (симметричный) живьём, без зависимостей.
 * Node >= 18. Запуск:  node mode_b_live.mjs [https://t2em.com]
 *
 * Полное путешествие секрета, как его видит браузер:
 *   1) клиент шифрует AES-256-GCM и создаёт drop (POST /api/v1/drop, 201);
 *   2) GET /s/:id возвращает text/html с ВСТРОЕННЫМ конвертом
 *      (<script id="t2em-envelope">) — этот запрос ПОТРЕБЛЯЕТ drop;
 *   3) расшифровка встроенного конверта даёт исходный секрет;
 *   4) повторное чтение -> 404 (read-exactly-once);
 *   5) лестница DELETE: без токена 401 / неверный 403 / верный 200 / потом 404.
 * Секреты и токены на экран не печатаются (только PASS/FAIL + статусы).
 */
const BASE = (process.argv[2] || 'https://t2em.com').replace(/\/+$/, '');
const enc = new TextEncoder();
const dec = new TextDecoder();
const b64u = (buf) => Buffer.from(buf).toString('base64url');

let failed = 0;
const check = (cond, label) => {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${label}`);
  if (!cond) { failed++; process.exitCode = 1; }
};

const PLAINTEXT = `manual mode B ${Date.now()}`;

// 1. Создание drop: ключ генерируется ЗДЕСЬ, на сервер уходит только конверт.
const key = crypto.getRandomValues(new Uint8Array(32));
const iv = crypto.getRandomValues(new Uint8Array(12));
const aes = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt', 'decrypt']);
const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aes, enc.encode(PLAINTEXT)));
const envelope = { v: 1, mode: 'sym', ciphertext: b64u(ct), iv: b64u(iv) };

const create = await fetch(`${BASE}/api/v1/drop`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ envelope, ttl: 120 }),
});
check(create.status === 201, `POST /api/v1/drop -> 201 (got ${create.status})`);
const created = create.status === 201 ? await create.json() : null;
if (!created) { console.log('FATAL: create failed, дальше тест невозможен'); process.exit(1); }
check(typeof created.id === 'string' && typeof created.delete_token === 'string', 'в ответе есть id и delete_token');
check(created.url === `${BASE}/s/${created.id}` || created.url === `https://t2em.com/s/${created.id}`,
  `share url канонический: ${created.url} (T2EM_PUBLIC_ORIGIN всегда t2em.com, даже если дроп создан через workers.dev)`);
check(created.expires_in === 120, `expires_in === 120 (got ${created?.expires_in})`);

// 2. Открытие страницы — одноразовое потребление.
const page = await fetch(created.url, { headers: { accept: 'text/html,application/xhtml+xml' } });
const html = await page.text();
check(page.status === 200 && (page.headers.get('content-type') || '').includes('text/html'),
  `GET /s/:id (браузер) -> 200 text/html (got ${page.status})`);
check((page.headers.get('cache-control') || '').includes('no-store'), 'Cache-Control: no-store на странице секрета');
const m = html.match(/<script type="application\/json" id="t2em-envelope">(.*?)<\/script>/s);
check(!!m, 'конверт встроен в HTML (<script id="t2em-envelope">)');
check(!html.includes(PLAINTEXT), 'секрет НЕ присутствует в HTML в открытом виде');

// 3. Расшифровка встроенного конверта.
let plain = null;
if (m) {
  const env = JSON.parse(m[1]);
  check(env.mode === 'sym' && env.v === 1, 'конверт v1/sym');
  try {
    plain = dec.decode(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: Buffer.from(env.iv, 'base64url') },
      await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']),
      Buffer.from(env.ciphertext, 'base64url'),
    ));
  } catch { plain = null; }
}
check(plain === PLAINTEXT, 'расшифровка встроенного конверта === исходному секрету');

// 4. Read-exactly-once.
const second = await fetch(created.url, { headers: { accept: 'application/json' } });
check(second.status === 404, `повторное чтение -> 404 (got ${second.status})`);

// 5. Лестница DELETE.
const noTok = await fetch(`${BASE}/api/v1/drop/${created.id}`, { method: 'DELETE' });
const bad = await fetch(`${BASE}/api/v1/drop/${created.id}`, { method: 'DELETE', headers: { 'x-delete-token': 'f'.repeat(64) } });
const good = await fetch(`${BASE}/api/v1/drop/${created.id}`, { method: 'DELETE', headers: { 'x-delete-token': created.delete_token } });
const after = await fetch(`${BASE}/api/v1/drop/${created.id}`, { headers: { accept: 'application/json' } });
check(noTok.status === 401, `DELETE без токена -> 401 (got ${noTok.status})`);
check(bad.status === 403, `DELETE с неверным токеном -> 403 (got ${bad.status})`);
check(good.status === 200, `DELETE с верным токеном -> 200 (got ${good.status})`);
check(after.status === 404, `GET после DELETE -> 404 (got ${after.status})`);

console.log(failed === 0 ? 'ИТОГ: ВСЕ PASS' : `ИТОГ: ПРОВАЛЕНО ${failed}`);
