import { describe, it, expect, vi, afterEach } from 'vitest';
import { isPrivateIp, isValidTargetHost, parseTargetHost, resolveHostIps, isValidIpv6, parseIpv6Words, validateSameOrigin } from '../src/lib/security';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('Security: isPrivateIp (SSRF defense)', () => {
  it('should identify IPv4 loopback & RFC1918 private ranges as private', () => {
    expect(isPrivateIp('127.0.0.1')).toBe(true);
    expect(isPrivateIp('127.255.255.254')).toBe(true);
    expect(isPrivateIp('10.0.0.1')).toBe(true);
    expect(isPrivateIp('10.254.1.1')).toBe(true);
    expect(isPrivateIp('172.16.0.1')).toBe(true);
    expect(isPrivateIp('172.31.255.255')).toBe(true);
    expect(isPrivateIp('192.168.1.1')).toBe(true);
    expect(isPrivateIp('192.168.0.254')).toBe(true);
  });

  it('should block Cloud Metadata & link-local IP (169.254.169.254)', () => {
    expect(isPrivateIp('169.254.169.254')).toBe(true);
    expect(isPrivateIp('169.254.1.1')).toBe(true);
  });

  it('should block Carrier-grade NAT (100.64.0.0/10)', () => {
    expect(isPrivateIp('100.64.0.1')).toBe(true);
    expect(isPrivateIp('100.127.255.255')).toBe(true);
  });

  it('should block IPv6 loopback, link-local, and ULA', () => {
    expect(isPrivateIp('::1')).toBe(true);
    expect(isPrivateIp('::')).toBe(true);
    expect(isPrivateIp('0000:0000:0000:0000:0000:0000:0000:0001')).toBe(true);
    expect(isPrivateIp('[0000:0000:0000:0000:0000:0000:0000:0001]')).toBe(true);
    expect(isPrivateIp('0:0:0:0:0:0:0:0001')).toBe(true);
    expect(isPrivateIp('0000::0001')).toBe(true);
    expect(isPrivateIp('fe80::1')).toBe(true);
    expect(isPrivateIp('fc00::1')).toBe(true);
    expect(isPrivateIp('fd00::dead:beef')).toBe(true);
    expect(isPrivateIp('[::1]')).toBe(true);
  });

  it('should block IPv4-mapped and IPv4-compatible IPv6 in compressed and uncompressed formats', () => {
    expect(isPrivateIp('::ffff:127.0.0.1')).toBe(true);
    expect(isPrivateIp('::127.0.0.1')).toBe(true);
    expect(isPrivateIp('::192.168.1.1')).toBe(true);
    expect(isPrivateIp('::10.0.0.1')).toBe(true);
    expect(isPrivateIp('0:0:0:0:0:ffff:127.0.0.1')).toBe(true);
    expect(isPrivateIp('0000:0000:0000:0000:0000:ffff:7f00:0001')).toBe(true);
    expect(isPrivateIp('::ffff:169.254.169.254')).toBe(true);
    expect(isPrivateIp('::ffff:10.0.0.1')).toBe(true);
    expect(isPrivateIp('::ffff:7f00:0001')).toBe(true);
  });

  it('should block integer / decimal & octal / hex encoded IPs', () => {
    // 2130706433 is 127.0.0.1
    expect(isPrivateIp('2130706433')).toBe(true);
    // 0x7f000001
    expect(isPrivateIp('0x7f.0.0.1')).toBe(true);
    // octal 0177.0.0.1
    expect(isPrivateIp('0177.0.0.1')).toBe(true);
  });

  it('should allow legitimate public IPv4 and IPv6 addresses', () => {
    expect(isPrivateIp('1.1.1.1')).toBe(false);
    expect(isPrivateIp('8.8.8.8')).toBe(false);
    expect(isPrivateIp('104.21.5.19')).toBe(false);
    expect(isPrivateIp('2606:4700:4700::1111')).toBe(false);
    expect(isPrivateIp('::1.1.1.1')).toBe(false);
    expect(isValidIpv6('::1.1.1.1')).toBe(true);
    expect(parseIpv6Words('::1.1.1.1')).toEqual([0, 0, 0, 0, 0, 0, 257, 257]);
  });
});

describe('Security: isValidTargetHost', () => {
  it('should reject empty, protocol-prefixed, or path-containing hosts', () => {
    expect(isValidTargetHost('')).toBe(false);
    expect(isValidTargetHost('http://example.com')).toBe(false);
    expect(isValidTargetHost('https://example.com/api')).toBe(false);
    expect(isValidTargetHost('example.com/test')).toBe(false);
    expect(isValidTargetHost('example.com?query=1')).toBe(false);
    expect(isValidTargetHost('user:pass@example.com')).toBe(false);
  });

  it('should reject localhost and reserved internal suffixes', () => {
    expect(isValidTargetHost('localhost')).toBe(false);
    expect(isValidTargetHost('api.localhost')).toBe(false);
    expect(isValidTargetHost('service.internal')).toBe(false);
    expect(isValidTargetHost('app.local')).toBe(false);
    expect(isValidTargetHost('corp.lan')).toBe(false);
    expect(isValidTargetHost('metadata.google.internal')).toBe(false);
    // Self-referencing service domains & worker loop prevention (PD-AUDIT-01)
    expect(isValidTargetHost('gateway.andrewwangdev.com')).toBe(false);
    expect(isValidTargetHost('panic.andrewwangdev.com')).toBe(false);
    expect(isValidTargetHost('panic.design')).toBe(false);
    expect(isValidTargetHost('gateway.panic.design')).toBe(false);
    expect(isValidTargetHost('panicdesign.androwsmith7923.workers.dev')).toBe(false);
    expect(isValidTargetHost('custom-app.workers.dev')).toBe(false);
    expect(isValidTargetHost('api.andrewwangdev.com')).toBe(true);
  });

  it('should reject private IP host targets', () => {
    expect(isValidTargetHost('127.0.0.1')).toBe(false);
    expect(isValidTargetHost('169.254.169.254')).toBe(false);
    expect(isValidTargetHost('10.10.10.10')).toBe(false);
    expect(isValidTargetHost('192.168.1.1')).toBe(false);
  });

  it('should accept valid public domain names', () => {
    expect(isValidTargetHost('example.com')).toBe(true);
    expect(isValidTargetHost('example.com:8080')).toBe(true);
    expect(isValidTargetHost('sub.domain.org:3000')).toBe(true);
    expect(isValidTargetHost('api.panic.design')).toBe(true);
    expect(isValidTargetHost('httpbin.org')).toBe(true);
    expect(isValidTargetHost('cloudflare.com')).toBe(true);
  });

  it('should accept valid public IPv4 and IPv6 target hosts', () => {
    expect(isValidTargetHost('1.1.1.1')).toBe(true);
    expect(isValidTargetHost('8.8.8.8:443')).toBe(true);
    expect(isValidTargetHost('2606:4700:4700::1111')).toBe(true);
    expect(isValidTargetHost('[2606:4700:4700::1111]')).toBe(true);
    expect(isValidTargetHost('[2606:4700:4700::1111]:443')).toBe(true);
    expect(isValidTargetHost('[2001:4860:4860::8888]')).toBe(true);
  });

  it('should reject private IPv6 hosts in brackets or bare', () => {
    expect(isValidTargetHost('::1')).toBe(false);
    expect(isValidTargetHost('[::1]')).toBe(false);
    expect(isValidTargetHost('[::1]:8080')).toBe(false);
    expect(isValidTargetHost('fe80::1')).toBe(false);
    expect(isValidTargetHost('fc00::1')).toBe(false);
  });

  it('should reject path, query, credential, or invalid port truncation bypass attempts', () => {
    expect(isValidTargetHost('example.com:/admin')).toBe(false);
    expect(isValidTargetHost('example.com/admin')).toBe(false);
    expect(isValidTargetHost('example.com?query=1')).toBe(false);
    expect(isValidTargetHost('example.com#hash')).toBe(false);
    expect(isValidTargetHost('admin@example.com')).toBe(false);
    expect(isValidTargetHost('example.com:invalidPort')).toBe(false);
    expect(isValidTargetHost('example.com:999999')).toBe(false);
    expect(isValidTargetHost('example.com:0')).toBe(false);
    expect(isValidTargetHost('[2606:4700:4700::1111]/admin')).toBe(false);
    expect(isValidTargetHost('[2606:4700:4700::1111]@evil.com')).toBe(false);
    expect(isValidTargetHost('[2606:4700:4700::1111]:999999')).toBe(false);
    expect(isValidTargetHost('[2606:4700:4700::1111]:0')).toBe(false);
  });
});

describe('Security: parseTargetHost', () => {
  it('should parse standard domain with and without port', () => {
    expect(parseTargetHost('example.com')).toEqual({
      hostname: 'example.com',
      port: '',
      isIpv6: false,
      isIp: false
    });
    expect(parseTargetHost('api.example.com:8080')).toEqual({
      hostname: 'api.example.com',
      port: '8080',
      isIpv6: false,
      isIp: false
    });
  });

  it('should parse IPv4 with and without port', () => {
    expect(parseTargetHost('8.8.8.8')).toEqual({
      hostname: '8.8.8.8',
      port: '',
      isIpv6: false,
      isIp: true
    });
    expect(parseTargetHost('1.1.1.1:443')).toEqual({
      hostname: '1.1.1.1',
      port: '443',
      isIpv6: false,
      isIp: true
    });
  });

  it('should parse bracketed and bare IPv6 addresses', () => {
    expect(parseTargetHost('[2606:4700:4700::1111]')).toEqual({
      hostname: '2606:4700:4700::1111',
      port: '',
      isIpv6: true,
      isIp: true
    });
    expect(parseTargetHost('[2606:4700:4700::1111]:8443')).toEqual({
      hostname: '2606:4700:4700::1111',
      port: '8443',
      isIpv6: true,
      isIp: true
    });
    expect(parseTargetHost('2606:4700:4700::1111')).toEqual({
      hostname: '2606:4700:4700::1111',
      port: '',
      isIpv6: true,
      isIp: true
    });
  });

  it('should reject invalid or malicious host structures', () => {
    expect(parseTargetHost('')).toBeNull();
    expect(parseTargetHost('http://example.com')).toBeNull();
    expect(parseTargetHost('example.com/path')).toBeNull();
    expect(parseTargetHost('user@example.com')).toBeNull();
  });

  it('should reject hex/octal/integer SSRF host forms and numeric/hex TLD labels', () => {
    expect(isValidTargetHost('0x7f.0.0.1')).toBe(false);
    expect(isValidTargetHost('0177.0.0.1')).toBe(false);
    expect(isValidTargetHost('2130706433')).toBe(false);
    expect(isValidTargetHost('example.123')).toBe(false);
    expect(isValidTargetHost('example.0x1')).toBe(false);
  });
});

describe('Security: resolveHostIps (A + AAAA)', () => {
  it('should return bare IP directly without DoH lookup', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const res = await resolveHostIps('1.1.1.1:443');
    expect(res).toEqual({ ips: ['1.1.1.1'], primaryIp: '1.1.1.1' });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('should query both A and AAAA DoH records concurrently', async () => {
    const fetchMock = vi.fn(async (url: string) => {
      if (url.includes('type=A&') || url.endsWith('type=A')) {
        return {
          ok: true,
          json: async () => ({ Status: 0, Answer: [{ type: 1, data: '104.21.5.19' }] }),
        } as Response;
      }
      return {
        ok: true,
        json: async () => ({ Status: 0, Answer: [{ type: 28, data: 'fc00::1' }] }),
      } as Response;
    });
    vi.stubGlobal('fetch', fetchMock);

    const res = await resolveHostIps('dualstack.example.com');
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(res.ips).toContain('104.21.5.19');
    expect(res.ips).toContain('fc00::1');
    expect(res.ips.some((ip) => isPrivateIp(ip))).toBe(true);
    expect(res.primaryIp).toBe('104.21.5.19');
  });
});

describe('Security: validateSameOrigin (PD-AUDIT-SEC-01)', () => {
  const originalEnv = process.env.NODE_ENV;

  afterEach(() => {
    (process.env as any).NODE_ENV = originalEnv;
  });

  it('should accept matching host and origin in production', () => {
    (process.env as any).NODE_ENV = 'production';
    const req = new Request('https://panic.andrewwangdev.com/api/user/delete', {
      headers: {
        host: 'panic.andrewwangdev.com',
        origin: 'https://panic.andrewwangdev.com'
      }
    });
    expect(validateSameOrigin(req)).toBe(true);
  });

  it('should reject cross-origin request in production', () => {
    (process.env as any).NODE_ENV = 'production';
    const req = new Request('https://panic.andrewwangdev.com/api/user/delete', {
      headers: {
        host: 'panic.andrewwangdev.com',
        origin: 'https://attacker.andrewwangdev.com'
      }
    });
    expect(validateSameOrigin(req)).toBe(false);
  });

  it('should reject localhost origin when NODE_ENV is production (PD-AUDIT-SEC-01)', () => {
    (process.env as any).NODE_ENV = 'production';
    const req = new Request('https://panic.andrewwangdev.com/api/user/delete', {
      headers: {
        host: 'panic.andrewwangdev.com',
        origin: 'http://localhost:3000'
      }
    });
    expect(validateSameOrigin(req)).toBe(false);

    const reqIp = new Request('https://panic.andrewwangdev.com/api/user/delete', {
      headers: {
        host: 'panic.andrewwangdev.com',
        origin: 'http://127.0.0.1:8080'
      }
    });
    expect(validateSameOrigin(reqIp)).toBe(false);
  });

  it('should allow localhost origin outside production (dev/test)', () => {
    (process.env as any).NODE_ENV = 'test';
    const req = new Request('https://panic.andrewwangdev.com/api/user/delete', {
      headers: {
        host: 'panic.andrewwangdev.com',
        origin: 'http://localhost:3000'
      }
    });
    expect(validateSameOrigin(req)).toBe(true);
  });

  it('should reject missing origin/referer in production', () => {
    (process.env as any).NODE_ENV = 'production';
    const req = new Request('https://panic.andrewwangdev.com/api/user/delete', {
      headers: {
        host: 'panic.andrewwangdev.com'
      }
    });
    expect(validateSameOrigin(req)).toBe(false);
  });
});
