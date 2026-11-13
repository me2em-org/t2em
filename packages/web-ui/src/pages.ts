/**
 * Server-rendered HTML pages of the embedded Web UI (ТЗ §3.2, §5.3).
 *
 * All pages are pure strings: the relay mounts them as-is. Inline
 * `<script>` is forbidden by WEB_UI_CSP (`script-src 'self'`) — the
 * only inline script tag carries the envelope as non-executable
 * `type="application/json"` data, HTML-escaped against `</script>`
 * breakout (§11.4 injection hygiene).
 */
import type { Envelope } from '@t2em/protocol';

/**
 * Embed JSON inside a `<script type="application/json">` block:
 * escape `<`/`>`/`&`/line-separators as JSON unicode escapes so the
 * payload can neither close the tag nor smuggle markup. `JSON.parse`
 * on the client restores the original values exactly.
 */
function embedJson(json: string): string {
  return json
    .split('<')
    .join('\\u003c')
    .split('>')
    .join('\\u003e')
    .split('&')
    .join('\\u0026')
    .split('\u2028')
    .join('\u2028')
    .split('\u2029')
    .join('\u2029');
}

function head(title: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta name="referrer" content="no-referrer">
<title>${title}</title>
<link rel="stylesheet" href="/ui.css">
</head>`;
}

/** `GET /` — landing + create form (ТЗ §7.1 journey step 1-4). */
export function renderHomePage(): string {
  return `${head('t2em — one-time encrypted secrets')}
<body>
<header>
  <h1><a href="/">t2em</a></h1>
  <p class="tagline">Zero-knowledge one-time secrets. The blind relay stores ciphertext only.</p>
</header>
<main>
<form id="create-form" class="card">
  <label for="secret">Secret</label>
  <textarea id="secret" placeholder="Paste a token, password or key..." autocomplete="off" spellcheck="false"></textarea>
  <div class="row">
    <label for="ttl">Expires in</label>
    <select id="ttl">
      <option value="60">60 seconds</option>
      <option value="300" selected>5 minutes</option>
      <option value="600">10 minutes</option>
      <option value="900">15 minutes</option>
    </select>
    <label><input type="checkbox" id="burn" checked> burn after first read</label>
  </div>
  <button type="submit" id="create-btn" disabled>Create secure link</button>
  <noscript><p class="error">JavaScript is required: encryption happens locally in your browser and the key never leaves it.</p></noscript>
  <p class="note">Encryption happens in your browser. The key travels only inside the link after #, which browsers never send to the server.</p>
  <p id="create-error" class="error" hidden></p>
</form>
<section id="result" class="card" hidden>
  <h2>Drop created</h2>
  <div class="field">
    <label for="drop-link">Share link — send the whole link, including the # part</label>
    <input type="text" id="drop-link" readonly>
    <button type="button" class="ghost" id="copy-link">Copy link</button>
  </div>
  <p class="note" id="link-expiry"></p>
  <div class="field">
    <label for="delete-token">Delete token — early destroy: DELETE /api/v1/drop/:id</label>
    <input type="text" id="delete-token" readonly>
    <button type="button" class="ghost" id="copy-token">Copy token</button>
  </div>
</section>
</main>
<footer>
  <p class="note">t2em is a blind relay: request bodies, IPs and user agents are never logged; drops die on first read or on expiry.</p>
</footer>
<script src="/ui.js"></script>
</body>
</html>
`;
}

/**
 * `GET /s/:id` with `Accept: text/html` (ТЗ §5.3) — the envelope is
 * embedded as data and the drop is consumed by THIS request, so the
 * browser needs no second fetch (read-exactly-once, §6.4).
 */
export function renderOpenPage(envelope: Envelope): string {
  const embedded = embedJson(JSON.stringify(envelope));
  return `${head('t2em — one-time secret')}
<body>
<header>
  <h1><a href="/">t2em</a></h1>
  <p class="tagline">A one-time secret was left for you.</p>
</header>
<main>
<p id="open-error" class="error" hidden></p>
<section id="open-result" class="card" hidden>
  <h2>Your secret</h2>
  <p class="note" id="open-note"></p>
  <label for="secret-value">Secret</label>
  <textarea id="secret-value" readonly></textarea>
  <button type="button" class="ghost" id="copy-secret">Copy</button>
</section>
<noscript><p class="error">JavaScript is required: decryption happens locally in your browser.</p></noscript>
</main>
<footer>
  <p class="note">The decryption key is the part of the link after #. It never reaches the server.</p>
</footer>
<script type="application/json" id="t2em-envelope">${embedded}</script>
<script src="/ui.js"></script>
</body>
</html>
`;
}

/**
 * Static 404 page for browser reads (ТЗ §5.3 anti-enumeration): the
 * body is byte-identical for "does not exist", "expired" and "already
 * read" — it must never distinguish the three cases.
 */
export function renderNotFoundPage(): string {
  return `${head('t2em — link not found')}
<body>
<header>
  <h1><a href="/">t2em</a></h1>
  <p class="tagline">Zero-knowledge one-time secrets.</p>
</header>
<main>
<section class="card">
  <h2>Link not found</h2>
  <p>This drop does not exist, has expired, or has already been read. t2em deletes a drop on first read and retains nothing about it afterwards.</p>
  <p><a href="/">Create a new drop</a></p>
</section>
</main>
<script src="/ui.js"></script>
</body>
</html>
`;
}
