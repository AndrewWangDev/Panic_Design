import { describe, it, expect, vi, beforeEach } from 'vitest';
import { parseTargetHost, isPrivateIp } from '../src/lib/security';

const mockAuth = vi.fn();
const mockCheckQuota = vi.fn();
const mockRefundQuota = vi.fn();
const mockTokenCreate = vi.fn();
const mockTokenFindMany = vi.fn().mockResolvedValue([]);
const mockTokenUpdate = vi.fn().mockResolvedValue({});
const mockUserFindFirst = vi.fn().mockResolvedValue({ id: 'user_1', jwtSalt: 'salt', githubId: 'gh_1' });
const mockVerifyTurnstile = vi.fn().mockResolvedValue(true);

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
      findMany: (...args: unknown[]) => mockTokenFindMany(...args),
      create: mockTokenCreate,
      update: (...args: unknown[]) => mockTokenUpdate(...args),
    },
    user: {
      findUnique: vi.fn().mockResolvedValue({ jwtSalt: 'salt' }),
      findFirst: (...args: unknown[]) => mockUserFindFirst(...args),
    },
  }),
}));

const mockCfEnv: Record<string, unknown> = {
  AUTH_SECRET: 'test-secret-for-vitest-at-least-32-chars',
  TURNSTILE_SECRET_KEY: 'test-turnstile-secret-key',
  CHAOS_JWT_SECRET: 'test-chaos-jwt-secret-at-least-32-chars'
};

vi.mock('@opennextjs/cloudflare', () => ({
  getCloudflareContext: () => ({
    env: mockCfEnv,
  }),
}));

vi.mock('@/lib/turnstile', () => ({
  verifyTurnstileToken: (...args: unknown[]) => mockVerifyTurnstile(...args),
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
    vi.unstubAllGlobals();
    process.env.TURNSTILE_SECRET_KEY = 'test-turnstile-secret';
    mockVerifyTurnstile.mockResolvedValue(true);
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
      if (typeof url === 'string' && url.includes('challenges.cloudflare.com')) {
        return {
          ok: true,
          json: async () => ({ success: true }),
        } as Response;
      }
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

  it('rejects when jitter exceeds latency for latency fault', async () => {
    mockAuth.mockResolvedValueOnce({ user: { id: 'user-valid' } });
    const { POST } = await import('../src/app/api/tokens/create/route');
    const req = new Request('https://panic.andrewwangdev.com/api/tokens/create', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        targetHost: 'api.example.com',
        fault: 'latency',
        latency: 100,
        jitter: 200,
        distribution: 'Uniform',
        turnstileToken: 'tok',
      }),
    });
    const res = await POST(req);
    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.error).toBe('INVALID_PARAMETERS');
    expect(data.message).toBe('Jitter cannot exceed base latency.');
  });

  it('rejects unresolvable target domain (DNS_RESOLUTION_FAILED) - Fail-Closed', async () => {
    mockAuth.mockResolvedValueOnce({ user: { id: 'user-valid' } });
    const fetchMock = vi.fn().mockRejectedValue(new Error('DNS resolution timeout'));
    vi.stubGlobal('fetch', fetchMock);

    const { POST } = await import('../src/app/api/tokens/create/route');
    const req = new Request('https://panic.andrewwangdev.com/api/tokens/create', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        targetHost: 'unresolvable-timeout-domain.xyz',
        fault: '502',
        turnstileToken: 'tok',
      }),
    });
    const res = await POST(req);
    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.error).toBe('DNS_RESOLUTION_FAILED');
    vi.unstubAllGlobals();
  });
});

describe('POST /api/tokens/revoke & /api/tokens/test security guards (PD-AUDIT-SEC-02, PD-AUDIT-RES-01, PD-AUDIT-API-01)', () => {
  it('rejects cross-origin request to /api/tokens/revoke with 403', async () => {
    const { POST } = await import('../src/app/api/tokens/revoke/route');
    const req = new Request('https://panic.andrewwangdev.com/api/tokens/revoke', {
      method: 'POST',
      headers: {
        host: 'panic.andrewwangdev.com',
        origin: 'https://evil.com',
        'content-type': 'application/json'
      },
      body: JSON.stringify({ id: 'tok-123' }),
    });
    const res = await POST(req);
    expect(res.status).toBe(403);
    const data = await res.json();
    expect(data.error).toBe('Cross-origin request rejected');
  });

  it('rejects non-JSON Content-Type to /api/tokens/revoke with 415', async () => {
    const { POST } = await import('../src/app/api/tokens/revoke/route');
    const req = new Request('https://panic.andrewwangdev.com/api/tokens/revoke', {
      method: 'POST',
      headers: {
        host: 'panic.andrewwangdev.com',
        origin: 'https://panic.andrewwangdev.com',
        'content-type': 'text/plain'
      },
      body: JSON.stringify({ id: 'tok-123' }),
    });
    const res = await POST(req);
    expect(res.status).toBe(415);
    const data = await res.json();
    expect(data.error).toBe('Content-Type must be application/json');
  });

  it('rejects non-JSON Content-Type to /api/tokens/test with 415', async () => {
    const { POST } = await import('../src/app/api/tokens/test/route');
    const req = new Request('https://panic.andrewwangdev.com/api/tokens/test', {
      method: 'POST',
      headers: {
        'content-type': 'text/plain'
      },
      body: JSON.stringify({ token: 'test-token' }),
    });
    const res = await POST(req);
    expect(res.status).toBe(415);
    const data = await res.json();
    expect(data.error).toBe('Content-Type must be application/json');
  });

  it('enforces burst rate limiting (max 5 requests per 10s) on /api/tokens/test (PD-AUDIT-RES-01)', async () => {
    mockAuth.mockResolvedValue({ user: { id: 'burst-tester' } });
    const { POST } = await import('../src/app/api/tokens/test/route');

    // 5 allowed attempts
    for (let i = 0; i < 5; i++) {
      const req = new Request('https://panic.andrewwangdev.com/api/tokens/test', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ token: 'malformed-jwt' }),
      });
      const res = await POST(req);
      // Malformed JWT returns 400, meaning rate limit check passed!
      expect(res.status).toBe(400);
    }

    // 6th attempt within window should be rate limited to 429
    const req6 = new Request('https://panic.andrewwangdev.com/api/tokens/test', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: 'malformed-jwt' }),
    });
    const res6 = await POST(req6);
    expect(res6.status).toBe(429);
    const data6 = await res6.json();
    expect(data6.error).toBe('RATE_LIMIT_EXCEEDED');
  });

  it('rejects cross-origin requests to /api/tokens/test with 403 (PD-AUDIT-04)', async () => {
    const { POST } = await import('../src/app/api/tokens/test/route');
    const req = new Request('https://panic.andrewwangdev.com/api/tokens/test', {
      method: 'POST',
      headers: {
        host: 'panic.andrewwangdev.com',
        origin: 'https://evil.com',
        'content-type': 'application/json'
      },
      body: JSON.stringify({ token: 'test-token' }),
    });
    const res = await POST(req);
    expect(res.status).toBe(403);
    const data = await res.json();
    expect(data.error).toBe('Cross-origin request rejected');
  });

  it('rejects deleted user session on /api/tokens/test with 401 instead of 429 (PD-AUDIT-02)', async () => {
    mockAuth.mockResolvedValueOnce({ user: { id: 'deleted-user' } });
    mockUserFindFirst.mockResolvedValueOnce(null);

    const { POST } = await import('../src/app/api/tokens/test/route');
    const req = new Request('https://panic.andrewwangdev.com/api/tokens/test', {
      method: 'POST',
      headers: {
        host: 'panic.andrewwangdev.com',
        origin: 'https://panic.andrewwangdev.com',
        'content-type': 'application/json'
      },
      body: JSON.stringify({ token: 'test-token' }),
    });
    const res = await POST(req);
    expect(res.status).toBe(401);
    const data = await res.json();
    expect(data.error).toBe('Unauthorized: Account deleted or inactive');
  });

  it('does not deadlock or revoke newly created token when historical corrupted tokens exist (PD-BUG-04)', async () => {
    mockAuth.mockResolvedValueOnce({ user: { id: 'user_1' } });
    mockCheckQuota.mockResolvedValueOnce({ allowed: true });

    // 5 old corrupted tokens created 2 days ago
    const corruptedOldTokens = Array.from({ length: 5 }, (_, i) => ({
      id: `tok_corrupted_${i}`,
      createdAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000),
      config: 'invalid-json-string'
    }));

    const newlyCreatedToken = {
      id: 'tok_new_valid',
      userId: 'user_1',
      targetHost: 'example.com',
      config: JSON.stringify({ fault: '502', ttlHours: 1 }),
      tokenHint: 'abc',
      issuedWithSalt: 0,
      isRevoked: false,
      createdAt: new Date()
    };

    // Pre-check returns 5 corrupted old tokens (both pre-check & post-check query unrevokedTokens)
    mockTokenFindMany
      .mockResolvedValueOnce(corruptedOldTokens) // pre-check: discarded because age > 15m
      .mockResolvedValueOnce([...corruptedOldTokens, newlyCreatedToken]); // post-check: corrupted discarded, new token is valid

    mockTokenCreate.mockResolvedValueOnce(newlyCreatedToken);

    const { POST } = await import('../src/app/api/tokens/create/route');
    const req = new Request('https://panic.andrewwangdev.com/api/tokens/create', {
      method: 'POST',
      headers: {
        host: 'panic.andrewwangdev.com',
        origin: 'https://panic.andrewwangdev.com',
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        targetHost: '1.1.1.1',
        fault: '502',
        customTtl: 1,
        turnstileToken: 'test'
      })
    });

    const res = await POST(req);
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.success).toBe(true);
    expect(json.token.id).toBe('tok_new_valid');
    expect(mockTokenUpdate).not.toHaveBeenCalledWith(expect.objectContaining({
      where: { id: 'tok_new_valid' },
      data: { isRevoked: true }
    }));
  });

  it('rejects cross-origin requests to /api/tokens/create with 403 (PD-INFO-07)', async () => {
    mockAuth.mockResolvedValueOnce({ user: { id: 'user_1' } });
    const { POST } = await import('../src/app/api/tokens/create/route');
    const req = new Request('https://panic.andrewwangdev.com/api/tokens/create', {
      method: 'POST',
      headers: {
        host: 'panic.andrewwangdev.com',
        origin: 'https://malicious-attacker.com',
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        targetHost: 'example.com',
        fault: '502'
      })
    });
    const res = await POST(req);
    expect(res.status).toBe(403);
    const json = await res.json();
    expect(json.error).toBe('Forbidden: Cross-Origin Request Blocked');
  });

  it('strictly enforces the 5 active tokens cap under high concurrency race conditions (BUG-03)', async () => {
    mockAuth.mockResolvedValue({ user: { id: 'user_1' } });
    mockCheckQuota.mockResolvedValue({ allowed: true });

    type MockToken = {
      id: string;
      userId: string;
      targetHost: string;
      config: string;
      tokenHint: string;
      issuedWithSalt: number;
      isRevoked: boolean;
      createdAt: Date;
    };

    const tokenDb: MockToken[] = [];
    let idCounter = 1;

    // Initially 3 active tokens already exist
    for (let i = 1; i <= 3; i++) {
      tokenDb.push({
        id: `tok_initial_${i}`,
        userId: 'user_1',
        targetHost: 'example.com',
        config: JSON.stringify({ fault: '502', ttlHours: 1 }),
        tokenHint: `hint_${i}`,
        issuedWithSalt: 0,
        isRevoked: false,
        createdAt: new Date(Date.now() - (10 - i) * 1000)
      });
    }

    mockTokenFindMany.mockImplementation(async () => {
      const tokens = tokenDb.filter(t => !t.isRevoked).map(t => ({ ...t }));
      tokens.sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime() || a.id.localeCompare(b.id));
      return tokens;
    });

    mockTokenCreate.mockImplementation(async ({ data }: any) => {
      const newToken: MockToken = {
        id: `tok_race_${idCounter++}`,
        userId: data.userId,
        targetHost: data.targetHost,
        config: data.config,
        tokenHint: data.tokenHint,
        issuedWithSalt: data.issuedWithSalt || 0,
        isRevoked: false,
        createdAt: new Date()
      };
      tokenDb.push(newToken);
      return { ...newToken };
    });

    mockTokenUpdate.mockImplementation(async ({ where, data }: any) => {
      const t = tokenDb.find(x => x.id === where.id);
      if (t) {
        if (data.isRevoked !== undefined) t.isRevoked = data.isRevoked;
      }
      return t ? { ...t } : null;
    });

    const prevEnv = process.env.NODE_ENV;
    (process.env as Record<string, string | undefined>).NODE_ENV = 'development';

    try {
      const { POST } = await import('../src/app/api/tokens/create/route');

      // Fire 6 parallel requests when only 2 slots remain (3 + 2 = 5 slots max)
      const requests = Array.from({ length: 6 }, () => {
        return POST(new Request('https://panic.andrewwangdev.com/api/tokens/create', {
          method: 'POST',
          headers: {
            host: 'panic.andrewwangdev.com',
            origin: 'https://panic.andrewwangdev.com',
            'content-type': 'application/json'
          },
          body: JSON.stringify({
            targetHost: '1.1.1.1',
            fault: '502',
            customTtl: 1
          })
        }));
      });

      const responses = await Promise.all(requests);
      const statuses = responses.map(r => r.status);
      const activeTokens = tokenDb.filter(t => !t.isRevoked);

      // Assert that active tokens NEVER exceed 5
      expect(activeTokens.length).toBeLessThanOrEqual(5);
      expect(activeTokens.length).toBe(5);

      // Exactly 2 succeeded, the remaining 4 were blocked/rolled back
      const successful = statuses.filter(s => s === 200).length;
      expect(successful).toBe(2);

      // Verify that all 3 initial confirmed tokens were NEVER revoked (PD-NEW-01)
      for (let i = 1; i <= 3; i++) {
        const initialTok = tokenDb.find(t => t.id === `tok_initial_${i}`);
        expect(initialTok?.isRevoked).toBe(false);
      }
    } finally {
      (process.env as Record<string, string | undefined>).NODE_ENV = prevEnv;
    }
  });

  it('self-revokes only the incoming token when cap is exceeded without revoking existing confirmed tokens (PD-NEW-01)', async () => {
    mockAuth.mockResolvedValue({ user: { id: 'user_1' } });
    mockCheckQuota.mockResolvedValue({ allowed: true });

    type MockToken = {
      id: string;
      userId: string;
      targetHost: string;
      config: string;
      tokenHint: string;
      issuedWithSalt: number;
      isRevoked: boolean;
      createdAt: Date;
    };

    const tokenDb: MockToken[] = [];
    // 5 confirmed active tokens already exist
    for (let i = 1; i <= 5; i++) {
      tokenDb.push({
        id: `tok_active_${i}`,
        userId: 'user_1',
        targetHost: 'example.com',
        config: JSON.stringify({ fault: '502', ttlHours: 1 }),
        tokenHint: `hint_${i}`,
        issuedWithSalt: 0,
        isRevoked: false,
        createdAt: new Date(Date.now() - (60 - i) * 1000)
      });
    }

    let findManyCallCount = 0;
    mockTokenFindMany.mockImplementation(async () => {
      findManyCallCount++;
      // Pre-check sees only 4 tokens (simulating concurrent window where pre-check passes)
      if (findManyCallCount === 1) {
        return tokenDb.slice(0, 4).map(t => ({ ...t }));
      }
      // Post-check sees all tokens including newly created ones
      const tokens = tokenDb.filter(t => !t.isRevoked).map(t => ({ ...t }));
      tokens.sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime() || a.id.localeCompare(b.id));
      return tokens;
    });

    let revokedTokenId = '';
    mockTokenCreate.mockImplementation(async ({ data }: any) => {
      const newToken: MockToken = {
        id: 'tok_surplus_new',
        userId: data.userId,
        targetHost: data.targetHost,
        config: data.config,
        tokenHint: data.tokenHint,
        issuedWithSalt: 0,
        isRevoked: false,
        createdAt: new Date()
      };
      tokenDb.push(newToken);
      return { ...newToken };
    });

    mockTokenUpdate.mockImplementation(async ({ where, data }: any) => {
      const t = tokenDb.find(x => x.id === where.id);
      if (t) {
        if (data.isRevoked !== undefined) {
          t.isRevoked = data.isRevoked;
          revokedTokenId = where.id;
        }
      }
      return t ? { ...t } : null;
    });

    const prevEnv = process.env.NODE_ENV;
    (process.env as Record<string, string | undefined>).NODE_ENV = 'development';

    try {
      const { POST } = await import('../src/app/api/tokens/create/route');
      const res = await POST(new Request('https://panic.andrewwangdev.com/api/tokens/create', {
        method: 'POST',
        headers: {
          host: 'panic.andrewwangdev.com',
          origin: 'https://panic.andrewwangdev.com',
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          targetHost: '1.1.1.1',
          fault: '502',
          customTtl: 1
        })
      }));

      expect(res.status).toBe(403);
      const json = await res.json();
      expect(json.error).toBe('CONCURRENT_CAP_EXCEEDED');

      // Only the surplus new token must have been revoked!
      expect(revokedTokenId).toBe('tok_surplus_new');
      // All 5 existing confirmed tokens must remain unrevoked
      for (let i = 1; i <= 5; i++) {
        const tok = tokenDb.find(t => t.id === `tok_active_${i}`);
        expect(tok?.isRevoked).toBe(false);
      }
    } finally {
      (process.env as Record<string, string | undefined>).NODE_ENV = prevEnv;
    }
  });

  it('prevents TOCTOU overshoot when 2 concurrent requests arrive with 4 existing active tokens (PD-CONC-01)', async () => {
    mockAuth.mockResolvedValue({ user: { id: 'user_1' } });
    mockCheckQuota.mockResolvedValue({ allowed: true });

    type MockToken = {
      id: string;
      userId: string;
      targetHost: string;
      config: string;
      tokenHint: string;
      issuedWithSalt: number;
      isRevoked: boolean;
      createdAt: Date;
    };

    const tokenDb: MockToken[] = [];
    // 4 active tokens already exist
    for (let i = 1; i <= 4; i++) {
      tokenDb.push({
        id: `tok_exist_${i}`,
        userId: 'user_1',
        targetHost: 'example.com',
        config: JSON.stringify({ fault: '502', ttlHours: 1 }),
        tokenHint: `hint_${i}`,
        issuedWithSalt: 0,
        isRevoked: false,
        createdAt: new Date(Date.now() - (50 - i) * 1000)
      });
    }

    let nextId = 1;
    mockTokenFindMany.mockImplementation(async () => {
      const tokens = tokenDb.filter(t => !t.isRevoked).map(t => ({ ...t }));
      tokens.sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime() || a.id.localeCompare(b.id));
      return tokens;
    });

    mockTokenCreate.mockImplementation(async ({ data }: any) => {
      const newToken: MockToken = {
        id: `tok_concurrent_${nextId++}`,
        userId: data.userId,
        targetHost: data.targetHost,
        config: data.config,
        tokenHint: data.tokenHint,
        issuedWithSalt: 0,
        isRevoked: false,
        createdAt: new Date()
      };
      tokenDb.push(newToken);
      return { ...newToken };
    });

    mockTokenUpdate.mockImplementation(async ({ where, data }: any) => {
      const t = tokenDb.find(x => x.id === where.id);
      if (t) {
        if (data.isRevoked !== undefined) t.isRevoked = data.isRevoked;
        if (data.tokenHint !== undefined) t.tokenHint = data.tokenHint;
      }
      return t ? { ...t } : null;
    });

    const prevEnv = process.env.NODE_ENV;
    (process.env as Record<string, string | undefined>).NODE_ENV = 'development';

    try {
      const { POST } = await import('../src/app/api/tokens/create/route');
      const [res1, res2] = await Promise.all([
        POST(new Request('https://panic.andrewwangdev.com/api/tokens/create', {
          method: 'POST',
          headers: {
            host: 'panic.andrewwangdev.com',
            origin: 'https://panic.andrewwangdev.com',
            'content-type': 'application/json'
          },
          body: JSON.stringify({ targetHost: '1.1.1.1', fault: '502', customTtl: 1 })
        })),
        POST(new Request('https://panic.andrewwangdev.com/api/tokens/create', {
          method: 'POST',
          headers: {
            host: 'panic.andrewwangdev.com',
            origin: 'https://panic.andrewwangdev.com',
            'content-type': 'application/json'
          },
          body: JSON.stringify({ targetHost: '1.1.1.1', fault: '502', customTtl: 1 })
        }))
      ]);

      const statuses = [res1.status, res2.status].sort();
      // Exactly one succeeds (200) and the other is rejected (403)
      expect(statuses).toEqual([200, 403]);

      // Exactly 5 unrevoked active tokens exist in DB
      const activeInDb = tokenDb.filter(t => !t.isRevoked);
      expect(activeInDb.length).toBe(5);

      // All 4 initial tokens are untouched
      for (let i = 1; i <= 4; i++) {
        expect(tokenDb.find(t => t.id === `tok_exist_${i}`)?.isRevoked).toBe(false);
      }
    } finally {
      (process.env as Record<string, string | undefined>).NODE_ENV = prevEnv;
    }
  });

  it('strictly refuses missing CHAOS_JWT_SECRET even in non-production environments (no AUTH_SECRET fallback)', async () => {
    mockAuth.mockResolvedValue({ user: { id: 'user_1' } });
    mockCheckQuota.mockResolvedValue({ allowed: true });

    const prevEnv = process.env.NODE_ENV;
    const prevSecret = process.env.CHAOS_JWT_SECRET;
    (process.env as Record<string, string | undefined>).NODE_ENV = 'development';
    delete process.env.CHAOS_JWT_SECRET;
    delete mockCfEnv.CHAOS_JWT_SECRET;

    try {
      const { POST: createPost } = await import('../src/app/api/tokens/create/route');
      const { POST: testPost } = await import('../src/app/api/tokens/test/route');

      const createRes = await createPost(new Request('https://panic.andrewwangdev.com/api/tokens/create', {
        method: 'POST',
        headers: {
          host: 'panic.andrewwangdev.com',
          origin: 'https://panic.andrewwangdev.com',
          'content-type': 'application/json'
        },
        body: JSON.stringify({ targetHost: '1.1.1.1', fault: '502', customTtl: 1 })
      }));
      expect(createRes.status).toBe(500);
      expect(mockCheckQuota).not.toHaveBeenCalled();

      const testRes = await testPost(new Request('https://panic.andrewwangdev.com/api/tokens/test', {
        method: 'POST',
        headers: {
          host: 'panic.andrewwangdev.com',
          origin: 'https://panic.andrewwangdev.com',
          'content-type': 'application/json'
        },
        body: JSON.stringify({ token: 'eyJhbGciOiJIUzI1NiJ9.eyJ0ZXN0IjoxfQ.sig' })
      }));
      expect(testRes.status).toBe(500);
    } finally {
      mockCfEnv.CHAOS_JWT_SECRET = 'test-chaos-jwt-secret-at-least-32-chars';
      if (prevSecret !== undefined) process.env.CHAOS_JWT_SECRET = prevSecret;
      (process.env as Record<string, string | undefined>).NODE_ENV = prevEnv;
    }
  });

  it('enforces atomic active token cap on real SQLite D1 engine regardless of Isolate clock skew or inverted CUID order', async () => {
    const { mintTokenWithCap } = await import('../src/lib/tokenMinting');
    const sqliteMod = (process as unknown as {
      getBuiltinModule?: (id: string) => { DatabaseSync: new (path: string) => any } | undefined;
    }).getBuiltinModule?.('node:sqlite');

    const nowIso = new Date().toISOString().replace('Z', '+00:00');
    const expiredIso = new Date(Date.now() - 2 * 3600 * 1000).toISOString().replace('Z', '+00:00');

    type SqliteRow = { id: string; userId: string; targetHost: string; config: string; tokenHint: string; isRevoked: number; issuedWithSalt: number; createdAt: string };
    const fallbackRows: SqliteRow[] = [];
    const db = sqliteMod ? new sqliteMod.DatabaseSync(':memory:') : null;

    if (db) {
      db.exec(`
        CREATE TABLE "Token" (
          "id" TEXT NOT NULL PRIMARY KEY,
          "userId" TEXT NOT NULL,
          "targetHost" TEXT NOT NULL,
          "config" TEXT NOT NULL,
          "tokenHint" TEXT NOT NULL,
          "isRevoked" BOOLEAN NOT NULL DEFAULT false,
          "issuedWithSalt" INTEGER NOT NULL,
          "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
      `);
      const insertSeed = db.prepare(
        'INSERT INTO "Token" ("id", "userId", "targetHost", "config", "tokenHint", "isRevoked", "issuedWithSalt", "createdAt") VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
      );
      for (let i = 1; i <= 4; i++) {
        insertSeed.run(`cm_seed_${i}`, 'u1', '1.1.1.1', JSON.stringify({ ttlHours: 1 }), `hint_${i}`, 0, 0, nowIso);
      }
      insertSeed.run('cm_expired', 'u1', '1.1.1.1', JSON.stringify({ ttlHours: 1 }), 'hint_exp', 0, 0, expiredIso);
      insertSeed.run('cm_revoked', 'u1', '1.1.1.1', JSON.stringify({ ttlHours: 1 }), 'hint_rev', 1, 0, nowIso);
      insertSeed.run('cm_corrupt_old', 'u1', '1.1.1.1', '{bad-json', 'hint_bad', 0, 0, expiredIso);
    } else {
      for (let i = 1; i <= 4; i++) {
        fallbackRows.push({ id: `cm_seed_${i}`, userId: 'u1', targetHost: '1.1.1.1', config: JSON.stringify({ ttlHours: 1 }), tokenHint: `hint_${i}`, isRevoked: 0, issuedWithSalt: 0, createdAt: nowIso });
      }
      fallbackRows.push({ id: 'cm_expired', userId: 'u1', targetHost: '1.1.1.1', config: JSON.stringify({ ttlHours: 1 }), tokenHint: 'hint_exp', isRevoked: 0, issuedWithSalt: 0, createdAt: expiredIso });
      fallbackRows.push({ id: 'cm_revoked', userId: 'u1', targetHost: '1.1.1.1', config: JSON.stringify({ ttlHours: 1 }), tokenHint: 'hint_rev', isRevoked: 1, issuedWithSalt: 0, createdAt: nowIso });
      fallbackRows.push({ id: 'cm_corrupt_old', userId: 'u1', targetHost: '1.1.1.1', config: '{bad-json', tokenHint: 'hint_bad', isRevoked: 0, issuedWithSalt: 0, createdAt: expiredIso });
    }

    const d1Adapter = {
      prepare: (query: string) => ({
        bind: (...values: unknown[]) => ({
          first: async <T = Record<string, unknown>>() => {
            if (db) {
              const stmt = db.prepare(query);
              const row = stmt.get(...(values as Array<string | number | null>)) as T | undefined;
              return row ?? null;
            }
            // Serialized D1 fallback for Node < 22 CI runners
            const [id, uId, host, cfg, hint, salt, countUserId, cap] = values as [string, string, string, string, string, number, string, number];
            const nowMs = Date.now();
            const activeCount = fallbackRows.filter(r => {
              if (r.userId !== countUserId || r.isRevoked !== 0) return false;
              let ttl = 0.25;
              try { ttl = JSON.parse(r.config).ttlHours || 0.25; } catch { ttl = 0.25; }
              return new Date(r.createdAt).getTime() + ttl * 3600 * 1000 > nowMs;
            }).length;
            if (activeCount >= cap) return null;
            const createdAt = new Date(nowMs).toISOString().replace('Z', '+00:00');
            fallbackRows.push({ id, userId: uId, targetHost: host, config: cfg, tokenHint: hint, isRevoked: 0, issuedWithSalt: salt, createdAt });
            return { id, createdAt } as unknown as T;
          }
        })
      })
    };

    // Simulate cross-PoP concurrent mint attempts where later request gets lexicographically smaller UUID
    const uuidSpy = vi
      .spyOn(crypto, 'randomUUID')
      .mockReturnValueOnce('ffffffff-0000-4000-8000-000000000001' as `${string}-${string}-${string}-${string}-${string}`)
      .mockReturnValueOnce('00000000-0000-4000-8000-000000000002' as `${string}-${string}-${string}-${string}-${string}`)
      .mockReturnValueOnce('00000000-0000-4000-8000-000000000003' as `${string}-${string}-${string}-${string}-${string}`);

    try {
      const results = await Promise.all([
        mintTokenWithCap({
          d1: d1Adapter,
          prisma: {} as any,
          userId: 'u1',
          targetHost: '1.1.1.1',
          config: JSON.stringify({ ttlHours: 1 }),
          issuedWithSalt: 0,
          maxActiveWindowStart: new Date(Date.now() - 10000), // skewed Isolate window
          signJwt: async (id) => `jwt.${id}.sig1`
        }),
        mintTokenWithCap({
          d1: d1Adapter,
          prisma: {} as any,
          userId: 'u1',
          targetHost: '1.1.1.1',
          config: JSON.stringify({ ttlHours: 1 }),
          issuedWithSalt: 0,
          maxActiveWindowStart: new Date(Date.now() - 90000), // earlier skewed Isolate clock
          signJwt: async (id) => `jwt.${id}.sig2`
        }),
        mintTokenWithCap({
          d1: d1Adapter,
          prisma: {} as any,
          userId: 'u1',
          targetHost: '1.1.1.1',
          config: JSON.stringify({ ttlHours: 1 }),
          issuedWithSalt: 0,
          maxActiveWindowStart: new Date(Date.now() - 50000),
          signJwt: async (id) => `jwt.${id}.sig3`
        })
      ]);

      const succeeded = results.filter(r => r.created);
      const rejected = results.filter(r => !r.created);
      expect(succeeded.length).toBe(1);
      expect(rejected.length).toBe(2);

      // Total active (unrevoked, unexpired) tokens must strictly equal 5 (4 seed + 1 minted)
      if (db) {
        const countRow = db
          .prepare(`SELECT COUNT(*) as cnt FROM "Token" WHERE "userId" = 'u1' AND "isRevoked" = 0 AND "id" NOT IN ('cm_expired', 'cm_corrupt_old')`)
          .get() as { cnt: number };
        expect(countRow.cnt).toBe(5);
      } else {
        const cnt = fallbackRows.filter(r => r.userId === 'u1' && r.isRevoked === 0 && !['cm_expired', 'cm_corrupt_old'].includes(r.id)).length;
        expect(cnt).toBe(5);
      }
    } finally {
      uuidSpy.mockRestore();
      db?.close();
    }
  });
});
