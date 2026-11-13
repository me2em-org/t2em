/**
 * Ручной тест D3 — побитовая совместимость с общими векторами (ТЗ §4.5).
 * Запуск из корня репо (нужен `pnpm -r build`):
 *   node docs/manual-tests/js/vectors_check.mjs
 *
 * Распаковывает все 6 векторов из vectors/t2em-drop.v1.json через
 * продакшн-код @t2em/protocol: 3 Mode A (X25519, фиксированные ключи)
 * и 3 Mode B (sym, фиксированный sym_key). Ожидаемый открытый текст —
 * поле plaintext_utf8 каждого вектора.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const { unpackDropAsym, unpackDropSym, b64uDecodeStrict, decodeUtf8 } = await import(
  new URL('packages/protocol/dist/index.js', `file://${ROOT}`)
);

const file = JSON.parse(readFileSync(new URL('vectors/t2em-drop.v1.json', `file://${ROOT}`), 'utf8'));
console.log(`векторов: ${file.vectors.length}, hkdf_info: ${file.hkdf_info}`);

let failed = 0;
for (const v of file.vectors) {
  const label = `${v.name} (${v.envelope.mode})`;
  try {
    const bytes =
      v.envelope.mode === 'sym'
        ? await unpackDropSym(v.envelope, v.sym_key)
        : await unpackDropAsym(v.envelope, b64uDecodeStrict(v.recipient_privkey));
    const text = decodeUtf8(bytes);
    const ok = text === v.plaintext_utf8;
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${label} -> "${text}"`);
    if (!ok) { failed++; process.exitCode = 1; }
  } catch (e) {
    console.log(`FAIL  ${label} -> исключение: ${e.message}`);
    failed++; process.exitCode = 1;
  }
}
console.log(failed === 0 ? 'ИТОГ: ВСЕ ВЕКТОРЫ PASS (бит-совместимость)' : `ИТОГ: ПРОВАЛЕНО ${failed}`);
