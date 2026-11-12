import { describe, it, expect, vi, beforeEach } from 'vitest';
import { parseTargetHost, isPrivateIp } from '../src/lib/security';

const mockAuth = vi.fn();
const mockCheckQuota = vi.fn();
const mockRefundQuota = vi.fn();
const mockTokenCreate = vi.fn();

vi.mock('@/auth', () => ({
  auth: () => mockAuth(),
}));

vi.mock('@/lib/quota', () => ({
  checkAndUpdateQuota: (...args: unknown[]) => mockCheckQuota(...args),
  refundQuota: (...args: unknown[]) => mockRefundQuota(...args),
}));

vi.mock('@/lib/prisma', () => ({
  getPrisma: () => ({
    token: {
      findMany: vi.fn().mockResolvedValue([]),
      create: mockTokenCreate,
    },
    user: {
      findUnique: vi.fn().mockResolvedValue({ jwtSalt: 'salt' }),
    },
  }),
}));

vi.mock('@opennextjs/cloudflare', () => ({
  getCloudflareContext: () => ({
    env: { AUTH_SECRET: 'test-secret-for-vitest-at-least-32-chars' },
  }),
}));

vi.mock('@/lib/turnstile', () => ({
  verifyTurnstileToken: vi.fn().mockResolvedValue(true),
}));

describe('Token Config & TTL Compatibility', () => {
  it('should accurately resolve TTL hours from modern ttlHours config', () => {
    const config = JSON.stringify({ fault: 'latency', latency: 50, ttlHours: 2 });
    const parsed = JSON.parse(config);
    const ttlHours = parseFloat(parsed.ttlHours || parsed.ttl) || 0.25;
    expect(ttlHours).toBe(2);
  });

  it('should accurately resolve TTL hours from legacy ttl config key', () => {
    const config = JSON.stringify({ fault: 'latency', latency: 50, ttl: 4 });
    const parsed = JSON.parse(config);
    const ttlHours = parseFloat(parsed.ttlHours || parsed.ttl) || 0.25;
    expect(ttlHours).toBe(4);
  });

  it('should default to 0.25 hours when TTL is unspecified or corrupt', () => {
    const config = JSON.stringify({ fault: '502' });
    const parsed = JSON.parse(config);
    const ttlHours = parseFloat(parsed.ttlHours || parsed.ttl) || 0.25;
    expect(ttlHours).toBe(0.25);
  });
});

describe('SSRF Protection with Port Stripping', () => {
  it('should isolate hostname from custom port before DNS lookup', () => {
    const hostWithPort = '127.0.0.1.nip.io:8080';
    const parsed = parseTargetHost(hostWithPort);
    expect(parsed).not.toBeNull();
    expect(parsed!.hostname).toBe('127.0.0.1.nip.io');
    expect(parsed!.port).toBe('8080');
    expect(parsed!.isIp).toBe(false);

    // Simulated DNS resolution result for 127.0.0.1.nip.io
    const resolvedIp = '127.0.0.1';
    expect(isPrivateIp(resolvedIp)).toBe(true);
  });

  it('should recognize public IP with port directly without DNS query', () => {
    const ipWithPort = '1.1.1.1:443';
    const parsed = parseTargetHost(ipWithPort);
    expect(parsed).not.toBeNull();
    expect(parsed!.hostname).toBe('1.1.1.1');
    expect(parsed!.port).toBe('443');
    expect(parsed!.isIp).toBe(true);
    expect(isPrivateIp(parsed!.hostname)).toBe(false);
  });

  it('should recognize bracketed IPv6 with port directly without DNS query', () => {
    const ipv6WithPort = '[2606:4700:4700::1111]:8080';
    const parsed = parseTargetHost(ipv6WithPort);
    expect(parsed).not.toBeNull();
    expect(parsed!.hostname).toBe('2606:4700:4700::1111');
    expect(parsed!.port).toBe('8080');
    expect(parsed!.isIp).toBe(true);
    expect(isPrivateIp(parsed!.hostname)).toBe(false);
  });
});

describe('POST /api/tokens/create validation & pre-flight SSRF guards', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockAuth.mockResolvedValue({ user: { id: 'user_123' } });
    mockCheckQuota.mockResolvedValue({ allowed: true, remaining: 5 });
  });

  it('rejects non-JSON Content-Type with 415', async () => {
    const { POST } = await import('../src/app/api/tokens/create/route');
    const req = new Request('https://panic.andrewwangdev.com/api/tokens/create', {
      method: 'POST',
      headers: { 'content-type': 'text/plain' },
      body: JSON.stringify({ targetHost: 'example.com', fault: '502' }),
    });
    const res = await POST(req);
    expect(res.status).toBe(415);
    expect(mockCheckQuota).not.toHaveBeenCalled();
  });

  it('rejects out-of-bounds parameters before quota or DB write', async () => {
    const { POST } = await import('../src/app/api/tokens/create/route');
    const badLatencyReq = new Request('https://panic.andrewwangdev.com/api/tokens/create', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        targetHost: 'example.com',
        fault: 'latency',
        latency: 99999,
        turnstileToken: 'tok',
      }),
    });
    const res1 = await POST(badLatencyReq);
    expect(res1.status).toBe(400);

    const badTtlReq = new Request('https://panic.andrewwangdev.com/api/tokens/create', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        targetHost: 'example.com',
        fault: '502',
        customTtl: 999,
        turnstileToken: 'tok',
      }),
    });
    const res2 = await POST(badTtlReq);
    expect(res2.status).toBe(400);
    expect(mockCheckQuota).not.toHaveBeenCalled();
    expect(mockTokenCreate).not.toHaveBeenCalled();
  });

  it('accepts max valid dashboard bounds (customTtl=168, jitter>latency when fault!=latency) and blocks AAAA private SSRF before quota/DB', async () => {
    const fetchMock = vi.fn(async (url: string) => {
      if (url.includes('type=A&') || url.endsWith('type=A')) {
        return {
          ok: true,
          json: async () => ({ Status: 0, Answer: [{ type: 1, data: '93.184.216.34' }] }),
        } as Response;
      }
      return {
        ok: true,
        json: async () => ({ Status: 0, Answer: [{ type: 28, data: '::1' }] }),
      } as Response;
    });
    vi.stubGlobal('fetch', fetchMock);

    const { POST } = await import('../src/app/api/tokens/create/route');
    const req = new Request('https://panic.andrewwangdev.com/api/tokens/create', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        targetHost: 'rebind6.example.com',
        fault: '502',
        scope: 'Global',
        distribution: 'Uniform',
        latency: 250,
        jitter: 500,
        packetLoss: 0,
        mutilationStrategy: 'None',
        customTtl: 168,
        turnstileToken: 'tok',
      }),
    });
    const res = await POST(req);
    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.error).toBe('SSRF_DETECTED');
    expect(mockCheckQuota).not.toHaveBeenCalled();
    expect(mockTokenCreate).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });
});
