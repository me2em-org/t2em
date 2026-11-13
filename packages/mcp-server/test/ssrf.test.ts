import { describe, expect, it } from 'vitest';
import { SsrfError, classifyIp, validateTarget } from '../src/ssrf.js';

describe('classifyIp — deny ranges (ТЗ §8.4 SSRF guard)', () => {
  const denied: Array<[string, string]> = [
    // IPv4
    ['0.0.0.1', '0.0.0.0/8'],
    ['10.1.2.3', '10.0.0.0/8'], // RFC1918
    ['100.64.1.1', '100.64.0.0/10'], // CGNAT
    ['127.0.0.1', '127.0.0.0/8'], // loopback
    ['169.254.169.254', '169.254.0.0/16'], // cloud metadata!
    ['172.16.0.1', '172.16.0.0/12'], // RFC1918
    ['172.31.255.255', '172.16.0.0/12'],
    ['192.168.1.1', '192.168.0.0/16'], // RFC1918
    ['192.0.2.1', '192.0.2.0/24'], // documentation
    ['198.51.100.7', '198.51.100.0/24'],
    ['203.0.113.9', '203.0.113.0/24'],
    ['198.18.0.1', '198.18.0.0/15'], // benchmarking
    ['224.0.0.1', '224.0.0.0/4'], // multicast
    ['240.0.0.1', '240.0.0.0/4'], // reserved
    ['255.255.255.255', '240.0.0.0/4'],
    // IPv6
    ['::', '::/128'], // unspecified
    ['::1', '::1/128'], // loopback
    ['::ffff:10.0.0.1', 'mapped IPv4'], // v4-mapped RFC1918
    ['::ffff:169.254.169.254', 'mapped IPv4'], // metadata via mapping
    ['64:ff9b::a00:1', '64:ff9b::/96'], // NAT64 into RFC1918
    ['2001:db8::1', '2001:db8::/32'], // documentation
    ['fc00::1', 'fc00::/7'], // ULA
    ['fd12:3456::1', 'fc00::/7'],
    ['fe80::1', 'fe80::/10'], // link-local
    ['ff02::1', 'ff00::/8'], // multicast
  ];

  for (const [ip, label] of denied) {
    it(`denies ${ip} (${label})`, () => {
      expect(classifyIp(ip)).not.toBe('public');
    });
  }

  const allowed = [
    '8.8.8.8',
    '1.1.1.1',
    '93.184.216.34',
    '172.32.0.1', // just outside RFC1918 /12
    '2606:4700:4700::1111', // public IPv6
    '2a00:1450:4001:81b::200e',
  ];
  for (const ip of allowed) {
    it(`allows public ${ip}`, () => {
      expect(classifyIp(ip)).toBe('public');
    });
  }
});

describe('validateTarget', () => {
  const resolveOk = async () => ['93.184.216.34'];

  it('requires https', async () => {
    await expect(validateTarget('http://example.com/', resolveOk)).rejects.toThrow(SsrfError);
    await expect(validateTarget('ftp://example.com/', resolveOk)).rejects.toThrow(SsrfError);
  });

  it('rejects credentials in the URL', async () => {
    await expect(validateTarget('https://user:pass@example.com/', resolveOk)).rejects.toThrow(
      SsrfError,
    );
  });

  it('rejects when DNS resolves to a private range', async () => {
    const evil = async () => ['10.0.0.5', '93.184.216.34'];
    await expect(validateTarget('https://rebind.example/', evil)).rejects.toThrow(SsrfError);
  });

  it('rejects when DNS resolves to the metadata address', async () => {
    const evil = async () => ['169.254.169.254'];
    await expect(validateTarget('https://metadata.example/', evil)).rejects.toThrow(SsrfError);
  });

  it('rejects IPv6 ULA resolution', async () => {
    const evil = async () => ['fd00::1'];
    await expect(validateTarget('https://internal.example/', evil)).rejects.toThrow(SsrfError);
  });

  it('pins the validated IP and accepts public literals', async () => {
    const pinned = await validateTarget('https://example.com/x?y=1', resolveOk);
    expect(pinned.pinnedIp).toBe('93.184.216.34');
    expect(pinned.url.pathname).toBe('/x');

    const literal = await validateTarget('https://[2606:4700:4700::1111]/', resolveOk);
    expect(literal.pinnedIp).toBe('2606:4700:4700::1111');

    const v4 = await validateTarget('https://8.8.8.8/', resolveOk);
    expect(v4.pinnedIp).toBe('8.8.8.8');
  });

  it('rejects a private IP literal without DNS', async () => {
    await expect(validateTarget('https://127.0.0.1/')).rejects.toThrow(SsrfError);
    await expect(validateTarget('https://10.9.8.7/')).rejects.toThrow(SsrfError);
    await expect(validateTarget('https://[::1]/')).rejects.toThrow(SsrfError);
    await expect(validateTarget('https://[fd00::1]/')).rejects.toThrow(SsrfError);
  });

  it('rejects malformed urls', async () => {
    await expect(validateTarget('not a url')).rejects.toThrow(SsrfError);
    await expect(validateTarget('https://')).rejects.toThrow(SsrfError);
  });

  it('rejects empty DNS answers', async () => {
    const empty = async () => [];
    await expect(validateTarget('https://void.example/', empty)).rejects.toThrow(SsrfError);
  });
});
