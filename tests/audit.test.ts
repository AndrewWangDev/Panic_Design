import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockAuth = vi.fn();
const mockAuthenticateApiKey = vi.fn();
const mockChaosLogFindMany = vi.fn();
const mockChaosLogCount = vi.fn();
const mockTokenFindMany = vi.fn();

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
    }
  })
}));

describe('Audit Logs API (GET /api/audit/logs)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('rejects unauthenticated requests with 401', async () => {
    mockAuth.mockResolvedValueOnce(null);
    mockAuthenticateApiKey.mockResolvedValueOnce(null);

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
});
