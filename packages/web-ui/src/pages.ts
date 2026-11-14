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

/**
 * `GET /for-agents` — static guide for LLM agents / automation (no
 * drop interaction, safe to fetch repeatedly). The #1 failure mode
 * observed in the wild: an agent fetches the `/s/:id` HTML page, which
 * consumes the drop (burn-after-read) and still yields nothing
 * readable — the agent cannot run the page's decrypting JavaScript.
 * This page teaches the API-first path instead. CSP discipline: no
 * `<script>` at all.
 */
export function renderAgentsPage(): string {
  return `${head('t2em — guide for AI agents')}
<body>
<header>
  <h1><a href="/">t2em</a></h1>
  <p class="tagline">Zero-knowledge one-time secrets — how to consume a drop programmatically.</p>
</header>
<main>
<section class="card">
  <h2>Read this first</h2>
  <p>t2em links are <strong>one-time</strong>: <code>burn_after_reading</code> defaults to <strong>true</strong>, so the first successful GET destroys the encrypted envelope (TTL fallback is 60&ndash;900&nbsp;seconds). If you are an LLM agent with a fetch tool, <strong>do not open the <code>/s/&lt;id&gt;</code> HTML page</strong> — that GET consumes the drop, and you cannot execute the page's JavaScript anyway. Use the API path below: one GET, then decrypt locally.</p>
  <p>This page is static and safe to fetch as many times as you like.</p>
</section>

<section class="card">
  <h2>1. Fetch the envelope (exactly one GET)</h2>
<pre><code>curl -s https://t2em.com/api/v1/drop/&lt;id&gt;
# → 200 JSON: {"v":1,"mode":"sym","ciphertext":"…","iv":"…"}   (Mode B)
#              {"v":1,"mode":"x25519","ciphertext":"…","iv":"…","ephemeralPubKey":"…"}
# → 404 after: already read / expired / never existed (identical body — anti-enumeration)</code></pre>
  <p>Envelope v1: fields are base64url without padding. There is no plaintext metadata: the relay cannot tell you anything else about the drop.</p>
</section>

<section class="card">
  <h2>2. Decrypt locally — the key never touches the server</h2>
  <ul>
    <li><strong>Mode B</strong> (<code>mode:"sym"</code>): the key is the URL part after <code>#</code> (43 base64url chars = 32 bytes). Browsers never send fragments; neither should you. If your tool stripped the <code>#…</code> part, ask the sender for the full link — it is unrecoverable.</li>
    <li><strong>Mode A</strong> (<code>mode:"x25519"</code>): you need the recipient X25519 private key (a §8.2 keyfile). Sender fingerprints are 16 chars — verify them out-of-band.</li>
    <li>Use the SDK below. Do <strong>not</strong> hand-roll HKDF/AES-GCM from the spec — the constants are frozen (§4.5) and a mistake fails as <code>DECRYPTION_FAILED</code> on an already-consumed drop.</li>
  </ul>
</section>

<section class="card">
  <h2>3. Python SDK (recommended for agents with a sandbox)</h2>
<pre><code>pip install "t2em @ git+https://github.com/me2em-org/t2em#subdirectory=python-sdk"</code></pre>
<pre><code>import json, urllib.request
from t2em import unpack_drop, validate_envelope

URL = "https://t2em.com/s/&lt;id&gt;#&lt;key&gt;"        # the whole link, # included
drop_id, _, sym_key = URL.partition("#")
drop_id = drop_id.rsplit("/", 1)[-1]

with urllib.request.urlopen("https://t2em.com/api/v1/drop/" + drop_id) as r:
    envelope = validate_envelope(json.load(r))   # exactly ONE GET — burns the drop

print(unpack_drop(envelope, {"mode": "sym", "sym_key": sym_key}).decode("utf-8"))</code></pre>
</section>

<section class="card">
  <h2>4. CLI (Node ≥ 22.6 + pnpm 10, from source)</h2>
<pre><code>git clone https://github.com/me2em-org/t2em.git &amp;&amp; cd t2em &amp;&amp; corepack enable &amp;&amp; pnpm install &amp;&amp; pnpm build
node packages/cli/dist/main.js pull "&lt;whole-url-including-#key&gt;" --newline</code></pre>
  <p>The CLI also does <code>push</code> (Mode A/B), <code>keygen</code> (§8.2 keyfile) and <code>delete</code>.</p>
</section>

<section class="card">
  <h2>5. MCP server (agents with MCP clients)</h2>
  <p>Six tools: <code>t2em_keygen</code>, <code>t2em_push</code>, <code>t2em_pull</code> (returns a <code>sec_…</code> handle — the plaintext stays in the in-process vault, never in the conversation), <code>t2em_http_request</code> (SSRF-guarded <code>{{sec_…}}</code> substitution), <code>t2em_wipe_secret</code>, <code>t2em_list_secrets</code>.</p>
<pre><code>{
  "mcpServers": {
    "t2em": {
      "command": "node",
      "args": ["/path/to/t2em/packages/mcp-server/dist/main.js"]
    }
  }
}</code></pre>
</section>

<section class="card">
  <h2>6. Error codes (branch on codes, never on message text)</h2>
  <table>
    <tr><th>code</th><th>meaning</th></tr>
    <tr><td>UNSUPPORTED_VERSION</td><td>envelope <code>v</code> is not 1</td></tr>
    <tr><td>MALFORMED</td><td>envelope/keyfile shape invalid, incl. cross-mode mismatch</td></tr>
    <tr><td>INVALID_LENGTH</td><td>wrong key/IV/salt length</td></tr>
    <tr><td>INVALID_IV</td><td>IV rejected</td></tr>
    <tr><td>DECRYPTION_FAILED</td><td>wrong key or corrupted ciphertext — the drop is already consumed by then; ask for a new link</td></tr>
  </table>
  <p>HTTP surface: <code>429</code> = rate limited (honor <code>Retry-After</code>, per-IP buckets exist on both create and read); <code>404</code> bodies never distinguish missing/expired/consumed. Protocol reference: <a href="https://github.com/me2em-org/t2em/blob/main/docs/TZ_t2em.md">docs/TZ_t2em.md</a>.</p>
</section>
</main>
</body>
</html>
`;
}
