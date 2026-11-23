import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockAuth = vi.fn();
const mockAuthenticateApiKey = vi.fn();
const mockChaosLogFindMany = vi.fn();
const mockChaosLogCount = vi.fn();
const mockTokenFindMany = vi.fn();
const mockUserFindFirst = vi.fn();

vi.mock('@/auth', () => ({
  auth: () => mockAuth()
}));

vi.mock('@/lib/apiKey', () => ({
  authenticateApiKey: (auth: string | null) => mockAuthenticateApiKey(auth)
}));

vi.mock('@/lib/prisma', () => ({
  getPrisma: () => ({
    chaosLog: {
      findMany: mockChaosLogFindMany,
      count: mockChaosLogCount
    },
    token: {
      findMany: mockTokenFindMany
    },
    user: {
      findFirst: mockUserFindFirst
    }
  })
}));

describe('Audit Logs API (GET /api/audit/logs)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockUserFindFirst.mockResolvedValue({ id: 'user_session_1', githubId: 'gh_1' });
  });

  it('rejects unauthenticated requests with 401', async () => {
    mockAuth.mockResolvedValueOnce(null);
    mockAuthenticateApiKey.mockResolvedValueOnce(null);

    const { GET } = await import('../src/app/api/audit/logs/route');
    const req = new Request('https://panic.andrewwangdev.com/api/audit/logs');
    const res = await GET(req);
    expect(res.status).toBe(401);
  });

  it('rejects deleted user session (githubId: null) with 401', async () => {
    mockAuth.mockResolvedValueOnce({ user: { id: 'deleted_user' } });
    mockUserFindFirst.mockResolvedValueOnce(null); // No active user with githubId not null

    const { GET } = await import('../src/app/api/audit/logs/route');
    const req = new Request('https://panic.andrewwangdev.com/api/audit/logs');
    const res = await GET(req);
    expect(res.status).toBe(401);
  });

  it('returns structured logs and summary stats when authenticated via Session', async () => {
    mockAuth.mockResolvedValueOnce({ user: { id: 'user_session_1' } });
    mockChaosLogFindMany
      .mockResolvedValueOnce([
        {
          id: 'log_1',
          source: 'AGENT_API',
          targetUrl: 'https://api.example.com',
          injectedFault: '502',
          tokenId: 'tok_1',
          tokenHint: 'tok_1...',
          edgeColo: 'LAX',
          statusCode: 502,
          latencyMs: 0,
          rayId: 'ray_123',
          executedAt: new Date('2026-11-16T12:00:00Z')
        }
      ])
      .mockResolvedValueOnce([
        { injectedFault: '502', targetUrl: 'https://api.example.com' },
        { injectedFault: '502', targetUrl: 'https://api.example.com' }
      ]);
    mockChaosLogCount
      .mockResolvedValueOnce(42) // total
      .mockResolvedValueOnce(5);  // today
    mockTokenFindMany.mockResolvedValueOnce([
      { id: 'tok_1', config: JSON.stringify({ fault: '502' }) }
    ]);

    const { GET } = await import('../src/app/api/audit/logs/route');
    const req = new Request('https://panic.andrewwangdev.com/api/audit/logs?limit=10');
    const res = await GET(req);
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.success).toBe(true);
    expect(json.logs.length).toBe(1);
    expect(json.logs[0].edgeColo).toBe('LAX');
    expect(json.logs[0].faultPolicy).toBeDefined();
    expect(json.logs[0].faultPolicy.fault).toBe('502');
    expect(json.summary.totalInjections).toBe(42);
    expect(json.summary.todayInjections).toBe(5);
    expect(json.summary.topTargets[0]).toEqual({ target: 'api.example.com', count: 2 });
  });

  it('allows access via API Key when no session is present', async () => {
    mockAuth.mockResolvedValueOnce(null);
    mockAuthenticateApiKey.mockResolvedValueOnce({ id: 'user_apikey_2' });
    mockChaosLogFindMany.mockResolvedValue([]);
    mockChaosLogCount.mockResolvedValue(0);

    const { GET } = await import('../src/app/api/audit/logs/route');
    const req = new Request('https://panic.andrewwangdev.com/api/audit/logs', {
      headers: { 'authorization': 'Bearer pd_live_key' }
    });
    const res = await GET(req);
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.success).toBe(true);
  });

  it('correctly aggregates multi-faceted fault breakdown (latency, jitter, drop, distribution, mutilation)', async () => {
    mockAuth.mockResolvedValueOnce({ user: { id: 'user_session_1' } });
    mockChaosLogFindMany
      .mockResolvedValueOnce([
        {
          id: 'log_combo',
          source: 'EDGE_INGRESS',
          targetUrl: 'https://api.example.com',
          injectedFault: 'latency',
          tokenId: 'tok_combo',
          tokenHint: 'tok_combo...',
          edgeColo: 'SJC',
          statusCode: 200,
          latencyMs: 1200,
          rayId: 'ray_combo',
          executedAt: new Date()
        }
      ])
      .mockResolvedValueOnce([
        {
          injectedFault: 'latency',
          targetUrl: 'https://api.example.com',
          tokenId: 'tok_combo',
          latencyMs: 1200
        }
      ]);
    mockChaosLogCount.mockResolvedValue(1);
    mockTokenFindMany.mockResolvedValueOnce([
      {
        id: 'tok_combo',
        config: JSON.stringify({
          fault: 'latency',
          latency: 1200,
          jitter: 300,
          packetLoss: 30,
          distribution: 'Normal',
          mutilationStrategy: 'Unexpected EOF'
        })
      }
    ]);

    const { GET } = await import('../src/app/api/audit/logs/route');
    const req = new Request('https://panic.andrewwangdev.com/api/audit/logs');
    const res = await GET(req);
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.summary.faultCounts).toEqual({
      latency: 1,
      jitter: 1,
      drop: 1,
      'Normal': 1,
      'Unexpected EOF': 1
    });
  });

  it('maintains stable summary metrics across pagination without drift (NEW-02 regression test)', async () => {
    mockAuth.mockResolvedValueOnce({ user: { id: 'user_session_1' } });
    // Simulate page 2 where visible logs have NO tokenId (or different tokenId)
    mockChaosLogFindMany
      .mockResolvedValueOnce([
        {
          id: 'log_page2',
          source: 'DIRECT_DATA_PLANE',
          targetUrl: 'https://other.example.com',
          injectedFault: 'PASSTHROUGH',
          tokenId: null,
          tokenHint: null,
          edgeColo: 'FRA',
          statusCode: 200,
          latencyMs: 10,
          rayId: 'ray_p2',
          executedAt: new Date()
        }
      ])
      // allUserLogs still has tok_combo from earlier
      .mockResolvedValueOnce([
        {
          injectedFault: 'latency',
          targetUrl: 'https://api.example.com',
          tokenId: 'tok_combo',
          latencyMs: 1200
        }
      ]);
    mockChaosLogCount.mockResolvedValue(100);
    mockTokenFindMany.mockResolvedValueOnce([
      {
        id: 'tok_combo',
        config: JSON.stringify({
          fault: 'latency',
          latency: 1200,
          jitter: 250,
          packetLoss: 10,
          distribution: 'Pareto',
          mutilationStrategy: 'Garbage Injection'
        })
      }
    ]);

    const { GET } = await import('../src/app/api/audit/logs/route');
    const req = new Request('https://panic.andrewwangdev.com/api/audit/logs?page=2&limit=25');
    const res = await GET(req);
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.success).toBe(true);
    expect(json.pagination).toEqual({
      page: 2,
      limit: 25,
      total: 100,
      totalPages: 4
    });
    expect(mockChaosLogFindMany).toHaveBeenCalledWith(expect.objectContaining({
      take: 25,
      skip: 25
    }));
    // Verifies that tok_combo was resolved from allUserLogs even though page 2 logs had no tokenId!
    expect(json.summary.faultCounts).toEqual({
      latency: 1,
      jitter: 1,
      drop: 1,
      'Pareto': 1,
      'Garbage Injection': 1
    });
  });

  it('handles invalid/non-numeric page and limit parameters gracefully without NaN (SEC-ISSUE-09)', async () => {
    mockAuth.mockResolvedValueOnce({ user: { id: 'user_session_1' } });
    mockChaosLogFindMany.mockResolvedValueOnce([]);
    mockChaosLogCount.mockResolvedValue(50);
    mockTokenFindMany.mockResolvedValueOnce([]);

    const { GET } = await import('../src/app/api/audit/logs/route');
    const req = new Request('https://panic.andrewwangdev.com/api/audit/logs?page=invalid&limit=xyz');
    const res = await GET(req);
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.success).toBe(true);
    expect(json.pagination).toEqual({
      page: 1,
      limit: 25,
      total: 50,
      totalPages: 2
    });
    expect(mockChaosLogFindMany).toHaveBeenCalledWith(expect.objectContaining({
      take: 25,
      skip: 0
    }));
  });

  it('clamps negative page and out-of-range limit safely (SEC-ISSUE-09)', async () => {
    mockAuth.mockResolvedValueOnce({ user: { id: 'user_session_1' } });
    mockChaosLogFindMany.mockResolvedValueOnce([]);
    mockChaosLogCount.mockResolvedValue(50);
    mockTokenFindMany.mockResolvedValueOnce([]);

    const { GET } = await import('../src/app/api/audit/logs/route');
    const req = new Request('https://panic.andrewwangdev.com/api/audit/logs?page=-5&limit=999');
    const res = await GET(req);
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.success).toBe(true);
    expect(json.pagination).toEqual({
      page: 1,
      limit: 100,
      total: 50,
      totalPages: 1
    });
    expect(mockChaosLogFindMany).toHaveBeenCalledWith(expect.objectContaining({
      take: 100,
      skip: 0
    }));
  });
});
