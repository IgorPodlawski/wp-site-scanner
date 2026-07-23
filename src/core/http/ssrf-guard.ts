import net from 'node:net';

export interface SsrfCheckResult {
  safe: boolean;
  reason?: string;
}

const ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);

interface Ipv4Range {
  base: string;
  prefix: number;
  label: string;
}

// Not exhaustive of every reserved IANA block — covers the ranges relevant to
// SSRF (loopback, private, link-local incl. the cloud metadata address,
// unspecified, and CGNAT) rather than the full reserved-address registry.
const BLOCKED_IPV4_RANGES: Ipv4Range[] = [
  { base: '0.0.0.0', prefix: 8, label: 'unspecified/this-network' },
  { base: '10.0.0.0', prefix: 8, label: 'private' },
  { base: '100.64.0.0', prefix: 10, label: 'carrier-grade NAT' },
  { base: '127.0.0.0', prefix: 8, label: 'loopback' },
  { base: '169.254.0.0', prefix: 16, label: 'link-local (includes cloud metadata)' },
  { base: '172.16.0.0', prefix: 12, label: 'private' },
  { base: '192.168.0.0', prefix: 16, label: 'private' },
  { base: '224.0.0.0', prefix: 4, label: 'multicast' },
  { base: '240.0.0.0', prefix: 4, label: 'reserved' },
];

function ipv4ToInt(ip: string): number {
  const parts = ip.split('.').map((p) => Number.parseInt(p, 10));
  return parts.reduce((acc, part) => (acc << 8) | (part & 0xff), 0) >>> 0;
}

function isIpv4InRange(ip: string, range: Ipv4Range): boolean {
  const ipInt = ipv4ToInt(ip);
  const baseInt = ipv4ToInt(range.base);
  const mask = range.prefix === 0 ? 0 : (~0 << (32 - range.prefix)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}

function checkIpv4(ip: string): SsrfCheckResult {
  for (const range of BLOCKED_IPV4_RANGES) {
    if (isIpv4InRange(ip, range)) {
      return { safe: false, reason: `IPv4 address ${ip} falls in blocked range (${range.label}).` };
    }
  }
  return { safe: true };
}

function checkIpv6(ip: string): SsrfCheckResult {
  const normalized = ip.toLowerCase();

  if (normalized === '::1' || normalized === '::') {
    return { safe: false, reason: `IPv6 address ${ip} is loopback/unspecified.` };
  }
  if (
    normalized.startsWith('fe80:') ||
    normalized.startsWith('fe8') ||
    normalized.startsWith('fe9') ||
    normalized.startsWith('fea') ||
    normalized.startsWith('feb')
  ) {
    return { safe: false, reason: `IPv6 address ${ip} is link-local (fe80::/10).` };
  }
  if (/^f[cd][0-9a-f]{2}:/.test(normalized)) {
    return { safe: false, reason: `IPv6 address ${ip} is unique local (fc00::/7).` };
  }
  // IPv4-mapped IPv6 (::ffff:a.b.c.d) — unwrap and re-check as IPv4.
  const mapped = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped?.[1]) {
    return checkIpv4(mapped[1]);
  }
  return { safe: true };
}

function isLocalhostHostname(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  return lower === 'localhost' || lower.endsWith('.localhost');
}

/**
 * Rejects requests to localhost, private IPv4/IPv6, link-local addresses
 * (including the 169.254.169.254 cloud metadata endpoint), and disallowed
 * schemes. Only handles literal IP addresses and the `localhost` hostname —
 * a hostname that *resolves* to a private address (DNS rebinding) requires
 * actual DNS resolution and is a TODO for the real http-client, which must
 * re-run this check against the resolved address before connecting and on
 * every redirect hop.
 */
export function isSafeToFetch(url: URL): SsrfCheckResult {
  if (!ALLOWED_PROTOCOLS.has(url.protocol)) {
    return { safe: false, reason: `Protocol "${url.protocol}" is not allowed.` };
  }

  const hostname = url.hostname.replace(/^\[|\]$/g, '');

  if (isLocalhostHostname(hostname)) {
    return { safe: false, reason: `Hostname "${hostname}" refers to localhost.` };
  }

  if (net.isIPv4(hostname)) {
    return checkIpv4(hostname);
  }

  if (net.isIPv6(hostname)) {
    return checkIpv6(hostname);
  }

  return { safe: true };
}
