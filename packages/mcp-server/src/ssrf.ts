/**
 * SSRF guard for `t2em_http_request` (ТЗ §8.4, blocking in CodeQL).
 *
 * The tool makes outbound HTTPS requests with agent-supplied URLs and
 * substituted secrets — a blind SSRF would exfiltrate them. Rules:
 *
 *  - HTTPS only; credentials in the URL are rejected outright.
 *  - The hostname is resolved and EVERY address must be public unicast
 *    (RFC1918, loopback, link-local incl. cloud metadata 169.254.169.254,
 *    CGNAT, ULA, multicast, documentation ranges, IPv4-mapped/NAT64 —
 *    all denied).
 *  - DNS pinning: the connection uses one of the validated addresses,
 *    so a rebinding between validation and connect cannot redirect the
 *    request into a private network.
 *  - Redirects are re-validated hop by hop (same rules), max 3 hops.
 */
import { isIP } from 'node:net';
import type { LookupAddress } from 'node:dns';

/** Range checks operate on 128-bit BigInt view; IPv4 = mapped form. */
function v4ToBigInt(ip: string): bigint | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let value = 0n;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = (value << 8n) | BigInt(octet);
  }
  return value;
}

function v6ToBigInt(ip: string): bigint | null {
  // Expand ::, then hex groups; supports embedded IPv4 (::ffff:a.b.c.d).
  let head = ip;
  const v4match = ip.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (v4match) {
    const v4 = v4ToBigInt(v4match[2]);
    if (v4 === null) return null;
    const hi = (v4 >> 16n) & 0xffffn;
    const lo = v4 & 0xffffn;
    head = `${v4match[1]}${hi.toString(16)}:${lo.toString(16)}`;
  }
  const doubleColon = head.split('::');
  if (doubleColon.length > 2) return null;
  const groupsOf = (s: string): bigint[] =>
    s === '' ? [] : s.split(':').map((g) => (/^[0-9a-fA-F]{1,4}$/.test(g) ? BigInt(`0x${g}`) : -1n));
  let groups: bigint[];
  if (doubleColon.length === 2) {
    const left = groupsOf(doubleColon[0]);
    const right = groupsOf(doubleColon[1]);
    const fill = 8 - left.length - right.length;
    if (fill < 0) return null;
    groups = [...left, ...Array<bigint>(fill).fill(0n), ...right];
  } else {
    groups = groupsOf(head);
  }
  if (groups.length !== 8 || groups.some((g) => g < 0n || g > 0xffffn)) return null;
  return groups.reduce((acc: bigint, g: bigint) => (acc << 16n) | g, 0n);
}

function ipToBigInt(ip: string): bigint | null {
  const family = isIP(ip);
  if (family === 4) return v4ToBigInt(ip);
  if (family === 6) return v6ToBigInt(ip);
  return null;
}

/*  IPv4 deny list — RFC1918, loopback, link-local (cloud metadata),
 *  CGNAT, this-network, reserved, multicast, broadcast, documentation.
 *  Kept in 32-bit space; v4-mapped IPv6 is unpacked before the check. */
const DENY_V4 = [
  '0.0.0.0/8',
  '10.0.0.0/8',
  '100.64.0.0/10',
  '127.0.0.0/8',
  '169.254.0.0/16',
  '172.16.0.0/12',
  '192.0.0.0/24',
  '192.0.2.0/24',
  '192.168.0.0/16',
  '198.18.0.0/15',
  '198.51.100.0/24',
  '203.0.113.0/24',
  '224.0.0.0/4',
  '240.0.0.0/4',
];

/*  IPv6 deny list — unspecified, loopback, NAT64, 6to4, Teredo,
 *  documentation, ULA, link-local, multicast. IPv4-mapped forms are
 *  handled by unpacking to the IPv4 list above. */
const DENY_V6 = ['::/128', '::1/128', '64:ff9b::/96', '2001:db8::/32', 'fc00::/7', 'fe80::/10', 'ff00::/8'];

interface DenyRange {
  lo: bigint;
  hi: bigint;
  label: string;
}

function cidrRange(cidrs: string[], bitsTotal: number): DenyRange[] {
  return cidrs.map((cidr) => {
    const [base, bitsRaw] = cidr.split('/');
    const bits = Number(bitsRaw);
    const baseValue = ipToBigInt(base);
    if (baseValue === null || !Number.isInteger(bits) || bits < 0 || bits > bitsTotal) {
      throw new Error(`bad deny-range: ${cidr}`);
    }
    const hostBits = BigInt(bitsTotal - bits);
    const lo = (baseValue >> hostBits) << hostBits;
    return { lo, hi: lo | ((1n << hostBits) - 1n), label: cidr };
  });
}

const DENY_V4_RANGES = cidrRange(DENY_V4, 32);
const DENY_V6_RANGES = cidrRange(DENY_V6, 128);

function matchRange(value: bigint, ranges: DenyRange[]): 'public' | string {
  for (const { lo, hi, label } of ranges) {
    if (value >= lo && value <= hi) return label;
  }
  return 'public';
}

/** `'public'` or the matched deny-range label. */
export function classifyIp(ip: string): 'public' | string {
  const family = isIP(ip);
  if (family === 4) {
    const value = v4ToBigInt(ip);
    return value === null ? 'unparseable' : matchRange(value, DENY_V4_RANGES);
  }
  if (family === 6) {
    const value = v6ToBigInt(ip);
    if (value === null) return 'unparseable';
    // ::ffff:0:0/96 — unpack embedded IPv4 and judge it as IPv4.
    if ((value >> 32n) === 0xffffn && (value >> 96n) === 0n) {
      const v4 = value & 0xffffffffn;
      return matchRange(v4, DENY_V4_RANGES);
    }
    return matchRange(value, DENY_V6_RANGES);
  }
  return 'unparseable';
}

export type Resolver = (hostname: string) => Promise<string[]>;

/** Default resolver: node:dns lookup, ALL addresses (verbatim order). */
export const defaultResolve: Resolver = async (hostname) => {
  const { lookup } = await import('node:dns/promises');
  const records = await lookup(hostname, { all: true, verbatim: true });
  return records.map((r: LookupAddress) => r.address);
};

export interface ValidatedTarget {
  url: URL;
  /** A validated address to pin the connection to (anti-rebinding). */
  pinnedIp: string;
}

/**
 * Validate an outbound URL: HTTPS, no credentials, every resolved
 * address public. Returns the pinned target for the actual request.
 */
export async function validateTarget(
  rawUrl: string,
  resolve: Resolver = defaultResolve,
): Promise<ValidatedTarget> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new SsrfError('invalid url');
  }
  if (url.protocol !== 'https:') {
    throw new SsrfError(`only https is allowed, got ${url.protocol}`);
  }
  if (url.username || url.password) {
    throw new SsrfError('credentials in url are not allowed');
  }
  if (!url.hostname) {
    throw new SsrfError('missing hostname');
  }

  const addresses = url.hostname.startsWith('[')
    ? [url.hostname.slice(1, -1)] // bracketed IPv6 literal — no DNS
    : isIP(url.hostname)
      ? [url.hostname] // bare IP literal — no DNS
      : await resolve(url.hostname);

  if (addresses.length === 0) {
    throw new SsrfError(`dns resolved no addresses for ${url.hostname}`);
  }
  for (const address of addresses) {
    const verdict = classifyIp(address);
    if (verdict !== 'public') {
      throw new SsrfError(`hostname resolves to denied range ${verdict} (${address})`);
    }
  }
  return { url, pinnedIp: addresses[0]! };
}

/** Rejected by the SSRF guard. */
export class SsrfError extends Error {
  constructor(message: string) {
    super(`SSRF blocked: ${message}`);
    this.name = 'SsrfError';
  }
}
