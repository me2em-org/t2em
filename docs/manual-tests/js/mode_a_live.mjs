/**
 * Ручной тест D2 — Mode A (X25519 E2EE) живьём, без зависимостей.
 * Node >= 18. Запуск:  node mode_a_live.mjs [https://t2em.com]
 *
 * Ключевое расписание (ТЗ §4.2, freeze §4.5):
 *   shared   = X25519(eph_priv, recipient_pub)            — 32B
 *   salt     = eph_pub || recipient_pub                   — 64B (UKS-safe)
 *   aes_key  = HKDF-SHA256(shared, salt, "me2em/crypto/v1/t2em-drop", 32)
 *   ct       = AES-256-GCM(aes_key, iv 12B, plaintext)    — ct включает 16B tag
 * Ссылка Mode A НЕ содержит #fragment — сервер вообще не видит материала ключа.
 */
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  webcrypto,
} from 'node:crypto';

const BASE = (process.argv[2] || 'https://t2em.com').replace(/\/+$/, '');
const enc = new TextEncoder();
const dec = new TextDecoder();
const b64u = (buf) => Buffer.from(buf).toString('base64url');
const HKDF_INFO = 'me2em/crypto/v1/t2em-drop';

let failed = 0;
const check = (cond, label) => {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${label}`);
  if (!cond) { failed++; process.exitCode = 1; }
};

// X25519 KeyObject <-> raw 32B (DER-префиксы SPKI/PKCS8 для кривой X25519).
const SPKI = Buffer.from('302a300506032b656e032100', 'hex');
const PKCS8 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const rawPub = (k) => k.publicKey.export({ type: 'spki', format: 'der' }).subarray(12);
const rawPriv = (k) => k.privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(16);
const pubFromRaw = (raw) => createPublicKey({ key: Buffer.concat([SPKI, raw]), format: 'der', type: 'spki' });
const privFromRaw = (raw) => createPrivateKey({ key: Buffer.concat([PKCS8, raw]), format: 'der', type: 'pkcs8' });
const deriveKey = (shared, salt) =>
  Buffer.from(hkdfSync('sha256', shared, salt, HKDF_INFO, 32));
const gcmEncrypt = async (keyBuf, plaintext) => {
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const k = await webcrypto.subtle.importKey('raw', keyBuf, 'AES-GCM', false, ['encrypt']);
  const ct = await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, enc.encode(plaintext));
  return { iv, ct: new Uint8Array(ct) };
};
const gcmDecrypt = async (keyBuf, iv, ct) => {
  const k = await webcrypto.subtle.importKey('raw', keyBuf, 'AES-GCM', false, ['decrypt']);
  return dec.decode(await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv }, k, ct));
};

const PLAINTEXT = `manual mode A ${Date.now()}`;

// 0. «Получатель» и его отпечаток (то, что сверяют вслепую: base64url(sha256(pub))[0..8]).
const recipient = generateKeyPairSync('x25519');
const recipientPubRaw = rawPub(recipient);
const fingerprint = createHash('sha256').update(recipientPubRaw).digest('base64url').slice(0, 8);
check(/^[A-Za-z0-9_-]{8}$/.test(fingerprint), `fingerprint получателя 8 символов base64url: ${fingerprint}`);

// 1. Отправитель: эфемерная пара + запечатывание (сервер получает только конверт).
const eph = generateKeyPairSync('x25519');
const shared = diffieHellman({ privateKey: eph.privateKey, publicKey: recipient.publicKey });
const salt = Buffer.concat([rawPub(eph), recipientPubRaw]);
const aesKey = deriveKey(shared, salt);
check(aesKey.length === 32, 'HKDF дал 32-байтный ключ AES-256');
const { iv, ct } = await gcmEncrypt(aesKey, PLAINTEXT);

const envelope = {
  v: 1,
  mode: 'x25519',
  ephemeralPubKey: b64u(rawPub(eph)),
  ciphertext: b64u(ct),
  iv: b64u(iv),
};

// 2. Создание drop: URL БЕЗ #fragment.
const create = await fetch(`${BASE}/api/v1/drop`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ envelope, ttl: 120 }),
});
check(create.status === 201, `POST /api/v1/drop -> 201 (got ${create.status})`);
const created = create.status === 201 ? await create.json() : null;
if (!created) { console.log('FATAL: create failed'); process.exit(1); }
check(!created.url.includes('#'), `share url без #fragment (${created.url})`);

// 3. Получатель открывает страницу и распаковывает конверт.
const page = await fetch(created.url, { headers: { accept: 'text/html' } });
const html = await page.text();
const m = html.match(/<script type="application\/json" id="t2em-envelope">(.*?)<\/script>/s);
check(page.status === 200 && !!m, 'страница отдаёт встроенный конверт v1/x25519');
let plain = null;
if (m) {
  const env = JSON.parse(m[1]);
  const ephPubRaw = Buffer.from(env.ephemeralPubKey, 'base64url');
  const shared2 = diffieHellman({ privateKey: recipient.privateKey, publicKey: pubFromRaw(ephPubRaw) });
  const aesKey2 = deriveKey(shared2, Buffer.concat([ephPubRaw, rawPub(recipient)]));
  plain = await gcmDecrypt(aesKey2, Buffer.from(env.iv, 'base64url'), Buffer.from(env.ciphertext, 'base64url')).catch(() => null);
}
check(plain === PLAINTEXT, 'расшифровка получателем === исходному секрету');

// 4. Негатив: чужой приватный ключ НЕ расшифровывает.
{
  const stranger = generateKeyPairSync('x25519');
  const env = m ? JSON.parse(m[1]) : null;
  let wrong = null;
  if (env) {
    const ephPubRaw = Buffer.from(env.ephemeralPubKey, 'base64url');
    const sharedBad = diffieHellman({ privateKey: stranger.privateKey, publicKey: pubFromRaw(ephPubRaw) });
    const aesKeyBad = deriveKey(sharedBad, Buffer.concat([ephPubRaw, rawPub(stranger)]));
    wrong = await gcmDecrypt(aesKeyBad, Buffer.from(env.iv, 'base64url'), Buffer.from(env.ciphertext, 'base64url')).catch((e) => `ERR:${e.name}`);
  }
  check(wrong === null || String(wrong).startsWith('ERR:'), 'чужой ключ не может расшифровать (GCM auth fail)');
}

// 5. Повторное чтение -> 404.
const second = await fetch(created.url, { headers: { accept: 'application/json' } });
check(second.status === 404, `повторное чтение -> 404 (got ${second.status})`);

console.log(failed === 0 ? 'ИТОГ: ВСЕ PASS' : `ИТОГ: ПРОВАЛЕНО ${failed}`);
