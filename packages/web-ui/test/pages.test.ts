/**
 * Этап 1D — rendered page + asset contract tests.
 *
 * The pages are the security surface served to browsers: these tests
 * pin the CSP-compliant structure (no inline executable script), the
 * `</script>` breakout escaping and the static asset wiring.
 */
import { describe, expect, it } from 'vitest';
import { UI_ASSETS, UI_JS } from '../src/assets.js';
import { WEB_UI_CSP } from '../src/index.js';
import { renderHomePage, renderNotFoundPage, renderOpenPage } from '../src/pages.js';
import type { Envelope } from '@t2em/protocol';

function symEnvelope(ciphertext = 'A'.repeat(64)): Envelope {
  return { v: 1, mode: 'sym', ciphertext, iv: 'B'.repeat(16) };
}

describe('renderHomePage (ТЗ §7.1)', () => {
  const html = renderHomePage();

  it('renders the create form with ttl and burn controls', () => {
    expect(html).toContain('<form id="create-form"');
    expect(html).toContain('<textarea id="secret"');
    expect(html).toContain('<option value="60"');
    expect(html).toContain('<option value="300" selected');
    expect(html).toContain('<option value="900">15 minutes</option>');
    expect(html).toContain('<input type="checkbox" id="burn" checked');
    expect(html).toContain('<button type="submit" id="create-btn" disabled>');
  });

  it('references only self assets, never inline executable script', () => {
    expect(html).toContain('<link rel="stylesheet" href="/ui.css">');
    expect(html).toContain('<script src="/ui.js"></script>');
    expect(html).not.toMatch(/<script(?![^>]*src=)[^>]*>[^<]*</); // no inline script bodies
    expect(html).not.toContain('<style');
  });

  it('tells no-JS visitors why nothing works without JavaScript', () => {
    expect(html).toContain('<noscript>');
    expect(html).toContain('JavaScript is required');
  });
});

describe('renderOpenPage (ТЗ §5.3)', () => {
  it('embeds the envelope as non-executable JSON data', () => {
    const envelope = symEnvelope();
    const html = renderOpenPage(envelope);
    expect(html).toContain('<script type="application/json" id="t2em-envelope">');
    // Round-trip: the embedded payload must parse back to the envelope.
    const m = /<script type="application\/json" id="t2em-envelope">(.*?)<\/script>/s.exec(html);
    expect(m).not.toBeNull();
    expect(JSON.parse((m as RegExpExecArray)[1])).toEqual(envelope);
  });

  it('escapes </script> breakout attempts in envelope fields (§11.4)', () => {
    const evil = '</script><script>alert(1)</script>';
    const html = renderOpenPage(symEnvelope(evil));
    // The payload is escaped, so the document contains exactly the two
    // legitimate script tags: the JSON data block and /ui.js — the
    // escaped data can never close the JSON tag or open a new one.
    const closes = html.match(/<\/script>/g) ?? [];
    expect(closes).toHaveLength(2);
    expect(html).not.toContain('</script><script>');
    expect(html).toContain('\\u003c/script\\u003e');
  });

  it('escapes & and < in envelope fields as JSON unicode escapes', () => {
    const html = renderOpenPage(symEnvelope('&<x'));
    expect(html).toContain('\\u0026\\u003cx');
  });
});

describe('renderNotFoundPage (§5.3 anti-enumeration)', () => {
  it('is static and identical regardless of the failure reason', () => {
    expect(renderNotFoundPage()).toBe(renderNotFoundPage());
    expect(renderNotFoundPage()).toContain('does not exist, has expired, or has already been read');
    expect(renderNotFoundPage()).not.toContain('t2em-envelope');
  });
});

describe('UI assets (CSP discipline)', () => {
  it('serves the two same-origin files with exact content types', () => {
    expect(UI_ASSETS).toHaveLength(2);
    const [js, css] = UI_ASSETS;
    expect(js.path).toBe('/ui.js');
    expect(js.contentType).toBe('text/javascript; charset=utf-8');
    expect(css.path).toBe('/ui.css');
    expect(css.contentType).toBe('text/css; charset=utf-8');
  });

  it('client JS parses as valid script source', () => {
    expect(() => new Function(UI_JS)).not.toThrow();
  });

  it('client JS keeps the CSP-safe structure (single IIFE, strict mode)', () => {
    expect(UI_JS.trimStart().startsWith('(function () {')).toBe(true);
    expect(UI_JS).toContain("'use strict';");
  });

  it('CSP is unchanged (single source of truth)', () => {
    expect(WEB_UI_CSP).toBe(
      "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
    );
  });
});
