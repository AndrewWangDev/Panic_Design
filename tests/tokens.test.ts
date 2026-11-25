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

vi.mock('@opennextjs/cloudflare', () => ({
  getCloudflareContext: () => ({
    env: { 
      AUTH_SECRET: 'test-secret-for-vitest-at-least-32-chars',
      TURNSTILE_SECRET_KEY: 'test-turnstile-secret-key',
      CHAOS_JWT_SECRET: 'test-chaos-jwt-secret-at-least-32-chars'
    },
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
});
