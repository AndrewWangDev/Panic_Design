/**
 * Security utilities for SSRF protection and input validation in Edge runtime.
 */

/**
 * Fully parses and expands any valid IPv6 address into exactly 8 16-bit words (0..0xffff).
 * Handles zero compression (::), leading zeros, brackets, and embedded IPv4 notation.
 * Returns null if the address is not a syntactically valid IPv6 address.
 */
export function parseIpv6Words(ip: string): number[] | null {
  if (!ip || typeof ip !== 'string') return null;

  let clean = ip.trim().toLowerCase();
  if (clean.startsWith('[') && clean.endsWith(']')) {
    clean = clean.slice(1, -1);
  }

  // Handle embedded IPv4 at the end (e.g. ::ffff:192.168.1.1 or 0:0:0:0:0:ffff:127.0.0.1)
  const lastColon = clean.lastIndexOf(':');
  if (lastColon !== -1 && clean.slice(lastColon + 1).includes('.')) {
    const v4Part = clean.slice(lastColon + 1);
    const v4Octets = v4Part.split('.');
    if (v4Octets.length !== 4) return null;
    const b = v4Octets.map(Number);
    if (b.some(n => isNaN(n) || n < 0 || n > 255)) return null;
    const word1 = (b[0] << 8) | b[1];
    const word2 = (b[2] << 8) | b[3];
    clean = `${clean.slice(0, lastColon)}:${word1.toString(16)}:${word2.toString(16)}`;
  }

  const doubleColonIdx = clean.indexOf('::');
  if (doubleColonIdx !== -1) {
    if (clean.indexOf('::', doubleColonIdx + 2) !== -1) return null; // Only one "::" allowed
    const leftStr = clean.slice(0, doubleColonIdx);
    const rightStr = clean.slice(doubleColonIdx + 2);
    const leftWords = leftStr ? leftStr.split(':') : [];
    const rightWords = rightStr ? rightStr.split(':') : [];
    const missing = 8 - (leftWords.length + rightWords.length);
    if (missing < 1) return null;
    clean = [...leftWords, ...new Array(missing).fill('0'), ...rightWords].join(':');
  }

  const parts = clean.split(':');
  if (parts.length !== 8) return null;
  const words: number[] = [];
  for (const p of parts) {
    if (!/^[0-9a-f]{1,4}$/i.test(p)) return null;
    words.push(parseInt(p, 16));
  }
  return words;
}

/**
 * Checks whether an IP address belongs to a private, loopback, link-local,
 * cloud metadata, or reserved network (RFC 1918, RFC 3927, RFC 5735, RFC 4291, etc.).
 *
 * Supports IPv4, IPv6, IPv4-mapped IPv6, and integer representations.
 */
export function isPrivateIp(ip: string): boolean {
  if (!ip || typeof ip !== 'string') return true;

  let trimmed = ip.trim().toLowerCase();

  // Handle brackets in IPv6 like [::1]
  if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
    trimmed = trimmed.slice(1, -1);
  }

  // IPv6 checks (handles full normalization)
  if (trimmed.includes(':')) {
    const words = parseIpv6Words(trimmed);
    if (!words) {
      // Malformed IPv6 representation, reject as unsafe (fail-closed)
      return true;
    }

    // 1. Unspecified address (::/128)
    if (words.every(w => w === 0)) return true;

    // 2. Loopback address (::1/128)
    if (words.slice(0, 7).every(w => w === 0) && words[7] === 1) return true;

    // 3. IPv4-mapped IPv6 (::ffff:0:0/96 or ::ffff:a.b.c.d)
    if (words.slice(0, 5).every(w => w === 0) && words[5] === 0xffff) {
      const b0 = (words[6] >> 8) & 0xff;
      const b1 = words[6] & 0xff;
      const b2 = (words[7] >> 8) & 0xff;
      const b3 = words[7] & 0xff;
      return isPrivateIpv4Octets(b0, b1, b2, b3);
    }

    // 4. IPv4-compatible IPv6 (::/96 - deprecated RFC 4291)
    if (words.slice(0, 6).every(w => w === 0) && (words[6] !== 0 || words[7] > 1)) {
      const b0 = (words[6] >> 8) & 0xff;
      const b1 = words[6] & 0xff;
      const b2 = (words[7] >> 8) & 0xff;
      const b3 = words[7] & 0xff;
      return isPrivateIpv4Octets(b0, b1, b2, b3);
    }

    // 5. Unique Local Addresses (ULA, fc00::/7 -> fc00..fdff)
    if ((words[0] & 0xfe00) === 0xfc00) return true;

    // 6. Link-Local Unicast (fe80::/10 -> fe80..febf)
    if ((words[0] & 0xffc0) === 0xfe80) return true;

    // 7. Site-Local (deprecated RFC 3879, fec0::/10 -> fec0..feff)
    if ((words[0] & 0xffc0) === 0xfec0) return true;

    // 8. Multicast (ff00::/8)
    if ((words[0] & 0xff00) === 0xff00) return true;

    // 9. Discard prefix (100::/64, RFC 6666)
    if (words[0] === 0x100 && words[1] === 0 && words[2] === 0 && words[3] === 0) return true;

    // 10. Documentation prefix (2001:db8::/32, RFC 3849)
    if (words[0] === 0x2001 && words[1] === 0x0db8) return true;

    // 11. Benchmarking (2001:2::/48, RFC 5180)
    if (words[0] === 0x2001 && words[1] === 0x0002) return true;

    // 12. 6to4 (2002::/16, RFC 3056) - check embedded IPv4
    if (words[0] === 0x2002) {
      const b0 = (words[1] >> 8) & 0xff;
      const b1 = words[1] & 0xff;
      const b2 = (words[2] >> 8) & 0xff;
      const b3 = words[2] & 0xff;
      return isPrivateIpv4Octets(b0, b1, b2, b3);
    }

    return false;
  }

  // Integer representation (e.g. 2130706433 -> 127.0.0.1)
  if (/^\d+$/.test(trimmed)) {
    const num = Number(trimmed);
    if (!isNaN(num) && num >= 0 && num <= 0xffffffff) {
      const b0 = (num >>> 24) & 255;
      const b1 = (num >>> 16) & 255;
      const b2 = (num >>> 8) & 255;
      const b3 = num & 255;
      return isPrivateIpv4Octets(b0, b1, b2, b3);
    }
    return true; // Out of range integer IP, treat as unsafe
  }

  // Standard or varied IPv4 octets
  const rawParts = trimmed.split('.');
  if (rawParts.length !== 4) {
    return true; // Malformed IP or non-standard format
  }

  const parts: number[] = [];
  for (const part of rawParts) {
    let val: number;
    if (part.startsWith('0x') || part.startsWith('0X')) {
      val = parseInt(part, 16);
    } else if (part.length > 1 && part.startsWith('0')) {
      val = parseInt(part, 8); // Octal notation e.g. 0177
    } else {
      val = Number(part);
    }

    if (isNaN(val) || val < 0 || val > 255) {
      return true; // Malformed octet
    }
    parts.push(val);
  }

  return isPrivateIpv4Octets(parts[0], parts[1], parts[2], parts[3]);
}

function isPrivateIpv4Octets(b0: number, b1: number, b2: number, b3: number): boolean {
  // 0.0.0.0/8 (Current network)
  if (b0 === 0) return true;

  // 10.0.0.0/8 (Private network - RFC 1918)
  if (b0 === 10) return true;

  // 100.64.0.0/10 (Shared address space / Carrier-grade NAT - RFC 6598)
  if (b0 === 100 && b1 >= 64 && b1 <= 127) return true;

  // 127.0.0.0/8 (Loopback - RFC 1122)
  if (b0 === 127) return true;

  // 169.254.0.0/16 (Link-local & Cloud Metadata endpoint 169.254.169.254 - RFC 3927)
  if (b0 === 169 && b1 === 254) return true;

  // 172.16.0.0/12 (Private network: 172.16.0.0 - 172.31.255.255 - RFC 1918)
  if (b0 === 172 && b1 >= 16 && b1 <= 31) return true;

  // 192.0.0.0/24 (IETF Protocol Assignments - RFC 6890)
  if (b0 === 192 && b1 === 0 && b2 === 0) return true;

  // 192.0.2.0/24 (TEST-NET-1 - RFC 5737)
  if (b0 === 192 && b1 === 0 && b2 === 2) return true;

  // 192.168.0.0/16 (Private network - RFC 1918)
  if (b0 === 192 && b1 === 168) return true;

  // 198.18.0.0/15 (Network benchmark tests - RFC 2544)
  if (b0 === 198 && (b1 === 18 || b1 === 19)) return true;

  // 198.51.100.0/24 (TEST-NET-2 - RFC 5737)
  if (b0 === 198 && b1 === 51 && b2 === 100) return true;

  // 203.0.113.0/24 (TEST-NET-3 - RFC 5737)
  if (b0 === 203 && b1 === 0 && b2 === 113) return true;

  // 224.0.0.0/4 (Multicast - RFC 5771)
  if (b0 >= 224 && b0 <= 239) return true;

  // 240.0.0.0/4 (Reserved for future use - RFC 1112)
  if (b0 >= 240) return true;

  // 255.255.255.255 (Broadcast)
  if (b0 === 255 && b1 === 255 && b2 === 255 && b3 === 255) return true;

  return false;
}

export function isValidIpv6(ip: string): boolean {
  return parseIpv6Words(ip) !== null;
}

export interface ParsedHost {
  hostname: string;
  port: string;
  isIpv6: boolean;
  isIp: boolean;
}

/**
 * Parses raw host string into normalized hostname, port, and network type.
 * Handles bracketed IPv6 ([2606::1]:8080), bare IPv6 (2606::1), and host:port (example.com:80).
 */
export function parseTargetHost(rawHost: string): ParsedHost | null {
  if (!rawHost || typeof rawHost !== 'string') return null;
  const host = rawHost.trim().toLowerCase();
  if (/[/?#@\\]/.test(host)) return null;

  // 1. Bracketed IPv6: [2606::1]:8080 or [2606::1]
  if (host.startsWith('[')) {
    const match = host.match(/^\[([0-9a-f:]+)\](?::(\d{1,5}))?$/);
    if (!match) return null;
    return { hostname: match[1], port: match[2] || '', isIpv6: true, isIp: true };
  }

  // 2. Host with port (standard domain or IPv4)
  if (host.includes(':')) {
    const parts = host.split(':');
    if (parts.length === 2 && !host.includes('::')) {
      return { hostname: parts[0], port: parts[1], isIpv6: false, isIp: /^[0-9.]+$/.test(parts[0]) };
    }
    // 3. Bare IPv6
    return { hostname: host, port: '', isIpv6: true, isIp: true };
  }

  // 4. Standard domain or IPv4
  return { hostname: host, port: '', isIpv6: false, isIp: /^[0-9.]+$/.test(host) };
}

/**
 * Validates a target host string to prevent SSRF, internal network scanning,
 * and command/protocol injection. Supports FQDNs, public IPv4, and public IPv6.
 */
export function isValidTargetHost(rawHost: string): boolean {
  if (!rawHost || typeof rawHost !== 'string') return false;

  let host = rawHost.trim().toLowerCase();

  // 1. Strict rejection of protocols / schemes, paths, queries, fragments, credentials
  if (/[/?#@\\]/.test(host)) {
    return false;
  }

  // 2. Bracketed IPv6 validation with optional port (e.g. [2606:4700:4700::1111] or [2606:4700:4700::1111]:8080)
  if (host.startsWith('[')) {
    const match = host.match(/^\[([0-9a-f:]+)\](?::(\d{1,5}))?$/);
    if (!match) return false;
    if (match[2]) {
      const port = Number(match[2]);
      if (isNaN(port) || port < 1 || port > 65535) return false;
    }
    const ip = match[1];
    if (isPrivateIp(ip)) return false;
    return isValidIpv6(ip);
  }

  // 3. Strip port for standard hostname / IPv4 if present (e.g., example.com:8080 or 1.1.1.1:443)
  if (host.includes(':')) {
    if (!host.includes('::') && host.split(':').length === 2) {
      const parts = host.split(':');
      if (!/^\d+$/.test(parts[1])) return false;
      const port = Number(parts[1]);
      if (isNaN(port) || port < 1 || port > 65535) return false;
      host = parts[0];
    }
  }

  // 4. Length checks (RFC 1035: 1 to 253 characters)
  if (host.length === 0 || host.length > 253) return false;

  // 5. Disallowed private/special hostnames & TLDs
  const forbiddenExact = new Set([
    'localhost',
    'metadata',
    'metadata.google.internal',
    'instance-data',
    'router',
    'gateway',
    'broadcasthost'
  ]);
  if (forbiddenExact.has(host)) return false;

  // Block self-referencing service domains and worker-to-worker routing loop candidates.
  const blockedSelfDomains = new Set([
    'gateway.andrewwangdev.com',
    'panic.andrewwangdev.com',
    'panic.design',
    'gateway.panic.design',
    'panicdesign.androwsmith7923.workers.dev'
  ]);
  if (blockedSelfDomains.has(host) || host.endsWith('.workers.dev')) return false;

  const forbiddenSuffixes = [
    '.localhost',
    '.local',
    '.internal',
    '.arpa',
    '.invalid',
    '.test',
    '.example',
    '.onion',
    '.corp',
    '.home',
    '.lan'
  ];
  for (const suffix of forbiddenSuffixes) {
    if (host.endsWith(suffix)) return false;
  }

  // 6. Check bare IPv6 address (e.g. 2606:4700:4700::1111)
  if (host.includes(':')) {
    if (isPrivateIp(host)) return false;
    return isValidIpv6(host);
  }

  // 7. Check IPv4 / obfuscated numeric IP addresses (standard, octal, hex)
  if (/^[0-9.]+$/.test(host) || /^0x[0-9a-f.]+$/i.test(host)) {
    const octets = host.split('.');
    if (octets.length !== 4) return false;
    if (octets.some(o => o.length === 0 || isNaN(Number(o)) || Number(o) < 0 || Number(o) > 255)) {
      return false;
    }
    return !isPrivateIp(host);
  }

  // 8. Hostname syntax validation (RFC 1123)
  // Must have at least one dot (e.g. domain.tld) to prevent querying single-word internal hosts
  if (!host.includes('.')) return false;

  // Labels must be separated by dots
  const labels = host.split('.');
  if (labels.some(label => label.length === 0 || label.length > 63)) return false;
  // TLD cannot be pure numeric or hex octet (prevents numeric IPv4 disguise fallback)
  if (/^(\d+|0x[0-9a-f]+)$/i.test(labels[labels.length - 1])) return false;

  // Validate each label
  for (const label of labels) {
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(label)) {
      return false;
    }
  }

  return true;
}

/**
 * Resolves all IPv4 (A) and IPv6 (AAAA) addresses for a target host via Cloudflare DoH.
 * If the host is already a raw IP literal, returns it directly without network DNS lookup.
 */
export async function resolveHostIps(rawHost: string): Promise<{ ips: string[]; primaryIp: string | null }> {
  const parsed = parseTargetHost(rawHost);
  if (!parsed) return { ips: [], primaryIp: null };

  if (parsed.isIp) {
    return { ips: [parsed.hostname], primaryIp: parsed.hostname };
  }

  const queryDns = async (qtype: 'A' | 'AAAA'): Promise<string[]> => {
    try {
      const dnsRes = await fetch(
        `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(parsed.hostname)}&type=${qtype}`,
        {
          headers: { accept: 'application/dns-json' },
          signal: AbortSignal.timeout(3000)
        }
      );
      const dnsData = (await dnsRes.json()) as {
        Status?: number;
        Answer?: Array<{ type: number; data: string }>;
      };
      if (dnsData.Status === 0 && Array.isArray(dnsData.Answer)) {
        const expectedType = qtype === 'A' ? 1 : 28;
        return dnsData.Answer.filter(a => a.type === expectedType && typeof a.data === 'string').map(a => a.data);
      }
    } catch (err) {
      console.warn(`DoH ${qtype} resolution error:`, err);
    }
    return [];
  };

  const [v4List, v6List] = await Promise.all([queryDns('A'), queryDns('AAAA')]);
  const ips = [...v4List, ...v6List];
  const primaryIp = v4List[0] || v6List[0] || null;
  return { ips, primaryIp };
}

/**
 * Validates that a mutation request originates from the same site/origin.
 * Defense against cross-site/same-site CSRF on high-consequence user management routes.
 *
 * Dynamic Host comparison (parsed.host === host) is strictly compliant
 * with modern browser security specifications (WHATWG Fetch / RFC 7230). In browser environments,
 * Host and Origin are Forbidden Header Names that JavaScript cannot forge or spoof.
 * Using dynamic Host matching preserves essential multi-domain routing (e.g. panic.design,
 * panic.andrewwangdev.com, and Cloudflare preview environments) without compromising security.
 */
export function validateSameOrigin(req: Request): boolean {
  const origin = req.headers.get('origin');
  const referer = req.headers.get('referer');
  const target = origin || referer;

  // In standard browser fetch/forms, Origin or Referer is always attached.
  if (!target) {
    // Non-browser / Node test environments without origin headers allowed outside production
    return process.env.NODE_ENV !== 'production';
  }

  try {
    const parsed = new URL(target);
    const host = req.headers.get('host') || 'panic.andrewwangdev.com';
    // Localhost in development/test allowed outside production
    if (process.env.NODE_ENV !== 'production' && (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1')) {
      return true;
    }
    return parsed.host === host;
  } catch {
    return false;
  }
}

/**
 * In-memory LRU cache for GeoIP coordinates.
 * Caps outbound requests to third-party geo services.
 */
const geoCache = new Map<string, { coords: [number, number]; timestamp: number }>();
const GEO_CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

export function _clearGeoCache(): void {
  geoCache.clear();
}

/**
 * Resolves W3 target host coordinates with 300ms fail-fast timeout and 24h LRU caching.
 */
export async function resolveGeoCoordinates(ip: string): Promise<[number, number] | null> {
  if (!ip || isPrivateIp(ip)) return null;

  const cached = geoCache.get(ip);
  const now = Date.now();
  if (cached && (now - cached.timestamp) < GEO_CACHE_TTL_MS) {
    return cached.coords;
  }

  try {
    const geoRes = await fetch(`https://ipapi.co/${ip}/json/`, {
      signal: AbortSignal.timeout(300)
    });
    const geoData = (await geoRes.json()) as { longitude?: unknown; latitude?: unknown } | null;
    if (geoData && typeof geoData.longitude === 'number' && typeof geoData.latitude === 'number') {
      const coords: [number, number] = [geoData.longitude, geoData.latitude];
      geoCache.set(ip, { coords, timestamp: now });
      if (geoCache.size > 1000) {
        const firstKey = geoCache.keys().next().value;
        if (firstKey) geoCache.delete(firstKey);
      }
      return coords;
    }
  } catch (geoErr) {
    console.warn(`[Geo] W3 resolution failed for ${ip}:`, geoErr);
  }
  return null;
}
