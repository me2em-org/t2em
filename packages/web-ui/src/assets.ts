/**
 * Static UI assets served by the relay (vanilla, no framework — ТЗ §3.2).
 *
 * CSP discipline (ТЗ §3.1, WEB_UI_CSP): `script-src 'self'` and
 * `style-src 'self'` forbid anything inline, so the browser logic and
 * styles live in separate same-origin files (`/ui.js`, `/ui.css`).
 *
 * The client JS is embedded as a plain string — it must therefore
 * contain no backslashes, no backticks and no `${` sequences. The
 * Mode B crypto below replicates `@t2em/protocol` `packDropSym` /
 * `unpackDropSym` bit-for-bit on raw WebCrypto (AES-256-GCM, 32B key,
 * 12B IV, no AAD — verified by test/client-crypto.test.ts).
 */

export interface UiAsset {
  /** Same-origin path served by the relay. */
  path: string;
  contentType: string;
  body: string;
}

export const UI_CSS = `:root { color-scheme: dark; }
* { box-sizing: border-box; }
body {
  font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
  background: #0d1117;
  color: #e6edf3;
  max-width: 40rem;
  margin: 0 auto;
  padding: 1.5rem 1rem 3rem;
  line-height: 1.55;
}
a { color: #7ee787; }
h1 { font-size: 1.5rem; margin: 0; }
h1 a { color: #e6edf3; text-decoration: none; }
h2 { font-size: 1.15rem; margin: 0 0 .4rem; }
.tagline { margin: .2rem 0 0; color: #8b949e; font-size: .95rem; }
.card { border: 1px solid #30363d; border-radius: 10px; padding: 1.1rem; margin: 1.1rem 0; }
label { display: block; font-weight: 600; margin: .7rem 0 .25rem; }
textarea, input[type="text"] {
  width: 100%;
  background: #161b22;
  color: #e6edf3;
  border: 1px solid #30363d;
  border-radius: 6px;
  padding: .6rem .7rem;
  font: inherit;
  resize: vertical;
}
textarea#secret { min-height: 7rem; }
textarea[readonly], input[readonly] {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: .95rem;
}
select { font: inherit; background: #161b22; color: #e6edf3; border: 1px solid #30363d; border-radius: 6px; padding: .45rem; }
.row { display: flex; gap: .8rem; align-items: center; flex-wrap: wrap; margin: .8rem 0; }
.row label { margin: 0; font-weight: 400; }
.row input[type="checkbox"] { width: 1rem; height: 1rem; }
button {
  font: inherit;
  font-weight: 600;
  cursor: pointer;
  background: #238636;
  color: #ffffff;
  border: 1px solid #2ea043;
  border-radius: 6px;
  padding: .55rem 1.1rem;
}
button:disabled { opacity: .5; cursor: not-allowed; }
button.ghost { background: transparent; color: #7ee787; border-color: #30363d; font-weight: 400; }
button:hover { filter: brightness(1.12); }
.error { color: #ff7b72; border: 1px solid #ff7b72; border-radius: 8px; padding: .7rem .9rem; margin: 1rem 0; }
.note { color: #8b949e; font-size: .9rem; }
.field { margin: .9rem 0; }
footer { margin-top: 2.5rem; border-top: 1px solid #21262d; padding-top: 1rem; }
[hidden] { display: none !important; }
`;

export const UI_JS = `(function () {
  'use strict';
  var ENC = new TextEncoder();
  var DEC = new TextDecoder();

  function byId(id) { return document.getElementById(id); }
  function show(id) { var el = byId(id); if (el) el.hidden = false; }
  function hide(id) { var el = byId(id); if (el) el.hidden = true; }
  function setText(id, text) { var el = byId(id); if (el) el.textContent = text; }
  function showError(id, msg) { setText(id, msg); show(id); }

  function b64uFromBytes(bytes) {
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).split('+').join('-').split('/').join('_').split('=').join('');
  }

  function bytesFromB64u(s) {
    var t = s.split('-').join('+').split('_').join('/');
    while (t.length % 4 !== 0) t += '=';
    var bin = atob(t);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function wipe(bytes) { crypto.getRandomValues(bytes); bytes.fill(0); }

  function flash(btn) {
    var old = btn.textContent;
    btn.textContent = 'Copied';
    setTimeout(function () { btn.textContent = old; }, 1200);
  }

  function fallbackCopy(el, btn) {
    el.focus();
    el.select();
    try { document.execCommand('copy'); flash(btn); } catch (e) { /* clipboard unavailable */ }
  }

  function copyButton(buttonId, sourceId) {
    var btn = byId(buttonId);
    if (!btn) return;
    btn.addEventListener('click', function () {
      var el = byId(sourceId);
      if (!el) return;
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(el.value).then(function () { flash(btn); }, function () { fallbackCopy(el, btn); });
      } else {
        fallbackCopy(el, btn);
      }
    });
  }

  // ---------- create page (/) ----------

  var form = byId('create-form');
  if (form) {
    var submit = byId('create-btn');
    if (submit) submit.disabled = false; // JS required: crypto is local-only
    form.addEventListener('submit', function (ev) { ev.preventDefault(); create(); });
    copyButton('copy-link', 'drop-link');
    copyButton('copy-token', 'delete-token');
  }

  async function create() {
    hide('create-error');
    hide('result');
    var secretField = byId('secret');
    var secret = secretField.value;
    if (!secret) { showError('create-error', 'Enter a secret first.'); return; }
    var ttl = Number(byId('ttl').value);
    var burn = byId('burn').checked;
    var key = crypto.getRandomValues(new Uint8Array(32));
    var iv = crypto.getRandomValues(new Uint8Array(12));
    try {
      var aesKey = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
      var ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, aesKey, ENC.encode(secret)));
      var res = await fetch('/api/v1/drop', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          envelope: { v: 1, mode: 'sym', ciphertext: b64uFromBytes(ciphertext), iv: b64uFromBytes(iv) },
          ttl: ttl,
          burn_after_reading: burn
        })
      });
      if (!res.ok) {
        var code = 'HTTP ' + res.status;
        try {
          var err = await res.json();
          if (err && err.error && err.error.code) code = err.error.code;
        } catch (e) { /* body was not JSON */ }
        throw new Error(code);
      }
      var body = await res.json();
      var link = body.url + '#' + b64uFromBytes(key);
      byId('drop-link').value = link;
      byId('delete-token').value = body.delete_token;
      setText('link-expiry', 'The drop self-destructs ' + (body.expires_in === 1 ? 'in 1 second' : 'in ' + body.expires_in + ' seconds') + ' or on first read.');
      show('result');
      secretField.value = '';
    } catch (e) {
      showError('create-error', 'Could not create the drop (' + e.message + '). Nothing was stored.');
    } finally {
      wipe(key); // the raw key must not linger; it survives only inside the share link
    }
  }

  // ---------- open page (/s/:id) ----------

  var dataEl = byId('t2em-envelope');
  if (dataEl) {
    try {
      runOpen(JSON.parse(dataEl.textContent));
    } catch (e) {
      showError('open-error', 'Malformed drop data.');
    }
  }
  copyButton('copy-secret', 'secret-value');

  async function runOpen(env) {
    if (!env || typeof env !== 'object') { showError('open-error', 'Malformed drop data.'); return; }
    if (env.mode === 'x25519') {
      showError('open-error', 'This drop is encrypted for a specific recipient key (Mode A). Use the t2em CLI or SDK with the recipient private key.');
      return;
    }
    if (env.mode !== 'sym') { showError('open-error', 'Unsupported envelope mode.'); return; }
    var frag = location.hash.slice(1);
    if (!frag) {
      showError('open-error', 'Missing decryption key: the part after # in the share link is required and is never sent to the server. Ask the sender for the complete link.');
      return;
    }
    var keyBytes = new Uint8Array(0);
    try {
      keyBytes = bytesFromB64u(frag);
      if (keyBytes.length !== 32) throw new Error('bad key length');
      var aesKey = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
      var plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytesFromB64u(env.iv) }, aesKey, bytesFromB64u(env.ciphertext));
      byId('secret-value').value = DEC.decode(plaintext);
      setText('open-note', 'Decrypted locally. The server copy was destroyed the moment this page loaded.');
      show('open-result');
    } catch (e) {
      showError('open-error', 'Decryption failed: the key after # does not match this drop.');
    } finally {
      wipe(keyBytes);
    }
  }
})();
`;

/** Assets mounted by the relay: same-origin only, immutable bodies. */
export const UI_ASSETS: readonly UiAsset[] = [
  { path: '/ui.js', contentType: 'text/javascript; charset=utf-8', body: UI_JS },
  { path: '/ui.css', contentType: 'text/css; charset=utf-8', body: UI_CSS },
];
