#!/usr/bin/env python3
"""Ручной тест E1 — Python SDK `t2em` живьём против релея.

Запуск из корня репо (нужен `pip install -e ./python-sdk`):

    python3 docs/manual-tests/py/sdk_live.py [https://t2em.com]

Проверяет: Mode B (push/pull), одноразовость (повторное чтение -> 404),
Mode A (X25519), чужой ключ не расшифровывает, досрочное удаление
(неверный токен -> 403, верный -> drop исчезает), keyfile 0600 и его
совместимость с форматом TS-CLI `t2em-cli keygen`.
Секреты и токены не печатаются.
"""
from __future__ import annotations

import os
import stat
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "python-sdk", "src"))

from t2em import (  # noqa: E402
    HttpError,
    T2emClient,
    generate_x25519_keypair,
    load_keyfile,
    write_keyfile,
)
from t2em.base64url import b64u_encode  # noqa: E402

BASE = (sys.argv[1] if len(sys.argv) > 1 else "https://t2em.com").rstrip("/")
client = T2emClient(BASE)
failed = 0


def check(cond: bool, label: str) -> None:
    global failed
    print(f"{'PASS' if cond else 'FAIL'}  {label}")
    if not cond:
        failed += 1


SECRET_B = f"py manual mode B {id(object())}"

# 1. Mode B: push -> pull_text.
drop = client.push(secret=SECRET_B, ttl=120)
check(drop.url.startswith(f"{BASE}/s/") and "#" in drop.url, f"Mode B url с #fragment: {drop.url[:40]}...")
check(drop.expires_in == 120 and bool(drop.delete_token), "expires_in=120, delete_token выдан")
check(client.pull_text(drop.url) == SECRET_B, "pull_text вернул исходный секрет")

# 2. Одноразовость: повторное чтение -> HttpError 404.
try:
    client.pull_text(drop.url)
    check(False, "повторное чтение должен был упасть")
except HttpError as e:
    check(e.status == 404, f"повторное чтение -> HttpError 404 (got {e.status})")

# 3. Mode A: запечатывание на pubkey получателя.
keys = generate_x25519_keypair()
SECRET_A = f"py manual mode A {id(object())}"
drop_a = client.push(secret=SECRET_A, recipient_pubkey=keys.public_key, ttl=120)
check("#" not in drop_a.url, f"Mode A url без #fragment: {drop_a.url[:40]}...")
check(client.pull_text(drop_a.url, recipient_privkey=keys.private_key) == SECRET_A,
      "Mode A: получатель расшифровал")

# 4. Негатив: чужой приватный ключ.
other = generate_x25519_keypair()
try:
    client.pull_text(drop_a.url, recipient_privkey=other.private_key)
    check(False, "чужой ключ должен был дать DECRYPT_FAILED")
except HttpError as e:
    check(e.status == 404 or "DECRYPT" in str(getattr(e, "code", "")),
          f"чужой ключ -> ошибка расшифровки (HTTP {e.status})")
except Exception as e:  # ProtocolError DECRYPT_FAILED и т.п.
    check(True, f"чужой ключ -> ошибка расшифровки ({type(e).__name__})")

# 5. Досрочное удаление: неверный токен 403, верный -> drop исчезает.
d3 = client.push(secret="to be deleted", ttl=300)
try:
    client.delete(d3.id, "A" * 43)
    check(False, "неверный токен должен был дать 403")
except HttpError as e:
    check(e.status == 403, f"delete с неверным токеном -> 403 (got {e.status})")
client.delete(d3.id, d3.delete_token)
print("PASS  delete с верным токеном прошёл (HTTP 200)")
try:
    client.pull_text(d3.url)
    check(False, "после delete чтение должен был дать 404")
except HttpError as e:
    check(e.status == 404, f"после delete -> 404 (got {e.status})")

# 6. Keyfile: 0600, совместим с TS CLI (t2em-cli keygen / pull --key).
tmp = os.path.join(tempfile.mkdtemp(), "agent.key")
pub_b64 = write_keyfile(tmp)
mode = stat.S_IMODE(os.stat(tmp).st_mode)
check(mode == 0o600, f"keyfile создан с правами 0600 (got {oct(mode)})")
loaded = load_keyfile(tmp)
check(b64u_encode(loaded.public_key) == pub_b64, "load_keyfile вернул тот же pubkey")
print(f"PASS  pubkey для кросс-теста с CLI: {pub_b64}")

print("ИТОГ: ВСЕ PASS" if failed == 0 else f"ИТОГ: ПРОВАЛЕНО {failed}")
sys.exit(1 if failed else 0)
