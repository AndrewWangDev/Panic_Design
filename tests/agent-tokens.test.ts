import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockAuthenticateApiKey = vi.fn();
const mockCheckAndUpdateQuota = vi.fn();
const mockRefundQuota = vi.fn();
const mockTokenFindMany = vi.fn();
const mockTokenCreate = vi.fn();
const mockTokenFindFirst = vi.fn();
const mockTokenUpdate = vi.fn();
const mockChaosLogCreate = vi.fn();
const mockUserFindUnique = vi.fn();
const mockResolveHostIps = vi.fn();

vi.mock('@/lib/security', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/security')>();
  return {
    ...actual,
    resolveHostIps: (host: string) => mockResolveHostIps(host)
  };
});

vi.mock('@/lib/apiKey', () => ({
  authenticateApiKey: (auth: string | null) => mockAuthenticateApiKey(auth)
}));

vi.mock('@/lib/quota', () => ({
  checkAndUpdateQuota: (id: string) => mockCheckAndUpdateQuota(id),
  refundQuota: (id: string) => mockRefundQuota(id)
}));

vi.mock('@/lib/prisma', () => ({
  getPrisma: () => ({
    token: {
      findMany: mockTokenFindMany,
      create: mockTokenCreate,
      findFirst: mockTokenFindFirst,
      update: mockTokenUpdate
    },
    chaosLog: {
      create: mockChaosLogCreate
    },
    user: {
      findUnique: mockUserFindUnique
    }
  })
}));

vi.mock('@opennextjs/cloudflare', () => ({
  getCloudflareContext: () => ({
    env: {
      AUTH_SECRET: 'test-secret-at-least-32-chars-long-for-jwt',
      CHAOS_JWT_SECRET: 'test-chaos-jwt-secret-at-least-32-chars-long-for-jwt'
    }
  })
}));

describe('Agent M2M Tokens Endpoint (POST & DELETE /api/v1/chaos/tokens)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockAuthenticateApiKey.mockResolvedValue({ id: 'user_agent_1', username: 'agent_user' });
    mockCheckAndUpdateQuota.mockResolvedValue({ allowed: true, remaining: 10 });
    mockTokenFindMany.mockResolvedValue([]);
    mockUserFindUnique.mockResolvedValue({ jwtSalt: 0 });
    mockChaosLogCreate.mockResolvedValue({});
    mockTokenUpdate.mockResolvedValue({});
    mockResolveHostIps.mockResolvedValue({ ips: ['93.184.216.34'], primaryIp: '93.184.216.34', error: false });
    mockTokenCreate.mockImplementation(async ({ data }: any) => ({
      id: 'token_agent_999',
      tokenHint: data.tokenHint,
      ...data
    }));
  });

  it('rejects unauthenticated requests with 401', async () => {
    mockAuthenticateApiKey.mockResolvedValueOnce(null);
    const { POST } = await import('../src/app/api/v1/chaos/tokens/route');
    const req = new Request('https://panic.andrewwangdev.com/api/v1/chaos/tokens', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ targetHost: 'example.com', fault: '502' })
    });
    const res = await POST(req);
    expect(res.status).toBe(401);
  });

  it('rejects SSRF target host before quota deduction', async () => {
    const { POST } = await import('../src/app/api/v1/chaos/tokens/route');
    const req = new Request('https://panic.andrewwangdev.com/api/v1/chaos/tokens', {
      method: 'POST',
      headers: {
        'authorization': 'Bearer pd_live_test',
        'content-type': 'application/json'
      },
      body: JSON.stringify({ targetHost: '127.0.0.1:8080', fault: '502' })
    });
    const res = await POST(req);
    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error).toBe('INVALID_TARGET_HOST');
    expect(mockCheckAndUpdateQuota).not.toHaveBeenCalled();
    expect(mockTokenCreate).not.toHaveBeenCalled();
  });

  it('enforces 5 active tokens cap with 403 CONCURRENT_CAP_EXCEEDED', async () => {
    const activeTokens = Array.from({ length: 5 }, (_, i) => ({
      id: `tok_${i}`,
      tokenHint: `hint_${i}`,
      createdAt: new Date().toISOString(),
      config: JSON.stringify({ ttlHours: 1 })
    }));
    mockTokenFindMany.mockResolvedValueOnce(activeTokens);

    const { POST } = await import('../src/app/api/v1/chaos/tokens/route');
    const req = new Request('https://panic.andrewwangdev.com/api/v1/chaos/tokens', {
      method: 'POST',
      headers: {
        'authorization': 'Bearer pd_live_test',
        'content-type': 'application/json'
      },
      body: JSON.stringify({ targetHost: 'example.com', fault: '502' })
    });
    const res = await POST(req);
    expect(res.status).toBe(403);
    const json = await res.json();
    expect(json.error).toBe('CONCURRENT_CAP_EXCEEDED');
    expect(json.activeTokens.length).toBe(5);
    expect(mockTokenCreate).not.toHaveBeenCalled();
  });

  it('filters out expired tokens from activeTokens list in 403 response', async () => {
    const tokens = [
      ...Array.from({ length: 5 }, (_, i) => ({
        id: `tok_active_${i}`,
        tokenHint: `hint_active_${i}`,
        createdAt: new Date().toISOString(),
        config: JSON.stringify({ ttlHours: 1 })
      })),
      {
        id: 'tok_expired_old',
        tokenHint: 'hint_expired',
        createdAt: new Date(Date.now() - 3600 * 1000 * 24).toISOString(), // 24h ago
        config: JSON.stringify({ ttlHours: 1 }) // Expired
      }
    ];
    mockTokenFindMany.mockResolvedValueOnce(tokens);

    const { POST } = await import('../src/app/api/v1/chaos/tokens/route');
    const req = new Request('https://panic.andrewwangdev.com/api/v1/chaos/tokens', {
      method: 'POST',
      headers: {
        'authorization': 'Bearer pd_live_test',
        'content-type': 'application/json'
      },
      body: JSON.stringify({ targetHost: 'example.com', fault: '502' })
    });
    const res = await POST(req);
    expect(res.status).toBe(403);
    const json = await res.json();
    expect(json.error).toBe('CONCURRENT_CAP_EXCEEDED');
    expect(json.activeTokens.length).toBe(5);
    expect(json.activeTokens.some((t: any) => t.id === 'tok_expired_old')).toBe(false);
  });

  it('rejects when jitter exceeds latency for latency fault in M2M API', async () => {
    const { POST } = await import('../src/app/api/v1/chaos/tokens/route');
    const req = new Request('https://panic.andrewwangdev.com/api/v1/chaos/tokens', {
      method: 'POST',
      headers: {
        'authorization': 'Bearer pd_live_test',
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        targetHost: 'example.com',
        fault: 'latency',
        latency: 50,
        jitter: 150
      })
    });
    const res = await POST(req);
    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error).toBe('INVALID_PARAMETERS');
    expect(json.message).toBe('Jitter cannot exceed base latency.');
  });

  it('mints JWT token and records audit log when valid', async () => {
    const { POST } = await import('../src/app/api/v1/chaos/tokens/route');
    const req = new Request('https://panic.andrewwangdev.com/api/v1/chaos/tokens', {
      method: 'POST',
      headers: {
        'authorization': 'Bearer pd_live_test',
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        targetHost: 'httpbin.org',
        fault: '504',
        customTtl: 0.5
      })
    });
    const res = await POST(req);
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.success).toBe(true);
    expect(json.jwtToken).toBeDefined();
    expect(json.tokenId).toBe('token_agent_999');
    expect(json.remainingSlots).toBeDefined();
    expect(json.remainingActiveSlots).toBeDefined();
    expect(mockTokenCreate).toHaveBeenCalled();
    expect(mockChaosLogCreate).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({
        source: 'AGENT_API',
        injectedFault: 'TOKEN_MINTED'
      })
    }));
  });

  it('revokes token via DELETE /api/v1/chaos/tokens/:id', async () => {
    mockTokenFindFirst.mockResolvedValueOnce({
      id: 'token_agent_999',
      userId: 'user_agent_1',
      targetHost: 'httpbin.org',
      tokenHint: 'httpbin.org...',
      isRevoked: false
    });

    const { DELETE } = await import('../src/app/api/v1/chaos/tokens/[id]/route');
    const req = new Request('https://panic.andrewwangdev.com/api/v1/chaos/tokens/token_agent_999', {
      method: 'DELETE',
      headers: { 'authorization': 'Bearer pd_live_test' }
    });
    const res = await DELETE(req, { params: Promise.resolve({ id: 'token_agent_999' }) });
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.success).toBe(true);
    expect(mockTokenUpdate).toHaveBeenCalledWith({
      where: { id: 'token_agent_999' },
      data: { isRevoked: true }
    });
  });

  it('accurately counts active tokens without take: 50 drift in GET /api/v1/chaos/tokens (PD-AUDIT-BUG-01)', async () => {
    const now = Date.now();
    // Mock 2 active tokens in the 7-day window
    const activeUnrevoked = [
      {
        id: 'tok-active-1',
        createdAt: new Date(now - 1000 * 60), // 1 min ago
        config: JSON.stringify({ ttlHours: 2 }) // valid for 2h -> active
      },
      {
        id: 'tok-active-2',
        createdAt: new Date(now - 1000 * 60 * 60), // 1 hour ago
        config: JSON.stringify({ ttlHours: 5 }) // valid for 5h -> active
      }
    ];

    // Mock 50 display tokens (all expired)
    const displayTokens = Array.from({ length: 50 }, (_, i) => ({
      id: `tok-disp-${i}`,
      targetHost: 'httpbin.org',
      tokenHint: 'hint',
      isRevoked: false,
      createdAt: new Date(now - 1000 * 60 * 60 * 24), // 1 day ago
      config: JSON.stringify({ ttlHours: 0.1 }) // expired
    }));

    // First call is unrevokedTokens query (for active count), second call is dbTokens (take: 50)
    mockTokenFindMany
      .mockResolvedValueOnce(activeUnrevoked)
      .mockResolvedValueOnce(displayTokens);

    const { GET } = await import('../src/app/api/v1/chaos/tokens/route');
    const req = new Request('https://panic.andrewwangdev.com/api/v1/chaos/tokens', {
      headers: { 'authorization': 'Bearer pd_live_test' }
    });
    const res = await GET(req);
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.success).toBe(true);
    // Active count must be 2, remaining slots must be 3 (5 - 2), not 0 from displayTokens
    expect(json.activeTokensCount).toBe(2);
    expect(json.remainingSlots).toBe(3);
    expect(json.tokens.length).toBe(50);
  });

  it('does not deadlock or revoke newly created token when historical corrupted tokens exist (PD-BUG-04)', async () => {
    // 5 old corrupted tokens created 2 days ago
    const corruptedOldTokens = Array.from({ length: 5 }, (_, i) => ({
      id: `tok_agent_corrupted_${i}`,
      createdAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000),
      config: 'corrupted-json',
      tokenHint: `hint_${i}`
    }));

    const newlyCreatedToken = {
      id: 'token_agent_999',
      userId: 'user_agent_1',
      targetHost: 'example.com',
      config: JSON.stringify({ fault: '502', ttlHours: 1 }),
      tokenHint: 'hint_new',
      issuedWithSalt: 0,
      isRevoked: false,
      createdAt: new Date()
    };

    mockTokenFindMany
      .mockResolvedValueOnce(corruptedOldTokens) // pre-check
      .mockResolvedValueOnce([...corruptedOldTokens, newlyCreatedToken]); // post-check

    const { POST } = await import('../src/app/api/v1/chaos/tokens/route');
    const req = new Request('https://panic.andrewwangdev.com/api/v1/chaos/tokens', {
      method: 'POST',
      headers: {
        'authorization': 'Bearer pd_live_test',
        'content-type': 'application/json'
      },
      body: JSON.stringify({ targetHost: 'example.com', fault: '502' })
    });

    const res = await POST(req);
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.success).toBe(true);
    expect(json.tokenId).toBe('token_agent_999');
    expect(mockTokenUpdate).not.toHaveBeenCalledWith(expect.objectContaining({
      where: { id: 'token_agent_999' },
      data: { isRevoked: true }
    }));
  });

  it('strictly enforces 5 active tokens cap under high concurrency race conditions on v1/chaos/tokens (BUG-03)', async () => {
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

    // Initially 3 active tokens exist
    for (let i = 1; i <= 3; i++) {
      tokenDb.push({
        id: `tok_agent_init_${i}`,
        userId: 'user_agent_1',
        targetHost: 'example.com',
        config: JSON.stringify({ fault: '502', ttlHours: 1 }),
        tokenHint: `hint_${i}`,
        issuedWithSalt: 0,
        isRevoked: false,
        createdAt: new Date(Date.now() - (10 - i) * 1000)
      });
    }

    mockTokenFindMany.mockImplementation(async () => {
      return tokenDb.filter(t => !t.isRevoked).map(t => ({ ...t }));
    });

    mockTokenCreate.mockImplementation(async ({ data }: any) => {
      const newToken: MockToken = {
        id: `tok_agent_race_${idCounter++}`,
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

    const { POST } = await import('../src/app/api/v1/chaos/tokens/route');

    // Fire 6 parallel requests when only 2 slots remain (3 + 2 = 5 slots max)
    const requests = Array.from({ length: 6 }, () => {
      return POST(new Request('https://panic.andrewwangdev.com/api/v1/chaos/tokens', {
        method: 'POST',
        headers: {
          'authorization': 'Bearer pd_live_test',
          'content-type': 'application/json'
        },
        body: JSON.stringify({ targetHost: 'example.com', fault: '502' })
      }));
    });

    const responses = await Promise.all(requests);
    const activeTokens = tokenDb.filter(t => !t.isRevoked);

    // Assert that active tokens NEVER exceed 5
    expect(activeTokens.length).toBeLessThanOrEqual(5);
    expect(activeTokens.length).toBe(5);

    // Exactly 2 succeeded
    const statuses = responses.map(r => r.status);
    const successful = statuses.filter(s => s === 200).length;
    expect(successful).toBe(2);
  });
});
