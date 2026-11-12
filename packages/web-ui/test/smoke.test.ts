import { describe, expect, it } from 'vitest';
import { WEB_UI_CSP, WEB_UI_ROUTES, WEB_UI_VERSION } from '../src/index.js';

describe('web-ui asset contract', () => {
  it('serves only the root and drop pages', () => {
    expect(WEB_UI_ROUTES).toEqual(['/', '/s/:id']);
  });

  it('ships a deny-by-default CSP', () => {
    expect(WEB_UI_CSP).toContain("default-src 'none'");
    expect(WEB_UI_CSP).toContain("frame-ancestors 'none'");
  });

  it('versions the bundle', () => {
    expect(WEB_UI_VERSION).toBe('0.1.0');
  });
});
