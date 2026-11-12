# @t2em/web-ui

Embedded browser UI of [t2em.com](https://t2em.com) (ТЗ §3.2).

Vanilla JS/TS, **no framework** — the whole bundle is served by the
relay and does exactly three things in the browser:

1. Mode B: take `sym_key` from the URL `#fragment` (never sent to the
   server, RFC 3986), fetch the envelope via `GET /s/:id`, decrypt
   locally with WebCrypto, display, wipe.
2. Show a recipient public key + QR for the Mode A key channel (§4.2.1).
3. Nothing else: no analytics, no external requests, no logging.

## Status

Skeleton (Этап 0). UI lands together with the relay API in Этап 1–2.
