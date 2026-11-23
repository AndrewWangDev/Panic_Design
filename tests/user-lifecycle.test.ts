import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockAuth = vi.fn();
const mockUserFindFirst = vi.fn();
const mockUserUpdate = vi.fn();
const mockTokenUpdateMany = vi.fn();
const mockChaosLogCreate = vi.fn();
const mockTransaction = vi.fn();

vi.mock('@/auth', () => ({
  auth: () => mockAuth()
}));

vi.mock('@/lib/prisma', () => ({
  getPrisma: () => ({
    user: {
      findFirst: mockUserFindFirst,
      update: mockUserUpdate
    },
    token: {
      updateMany: mockTokenUpdateMany
    },
    chaosLog: {
      create: mockChaosLogCreate
    },
    $transaction: mockTransaction
  })
}));

describe('User Lifecycle APIs: revoke-all and delete', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockTransaction.mockImplementation((promises: any[]) => Promise.all(promises));
    mockUserFindFirst.mockResolvedValue({ id: 'user_test_1', githubId: 'gh_123' });
    mockUserUpdate.mockResolvedValue({ id: 'user_test_1' });
    mockTokenUpdateMany.mockResolvedValue({ count: 3 });
    mockChaosLogCreate.mockResolvedValue({ id: 'log_rev_1' });
  });

  describe('POST /api/user/revoke-all', () => {
    it('rejects unauthenticated requests with 401', async () => {
      mockAuth.mockResolvedValueOnce(null);
      const { POST } = await import('../src/app/api/user/revoke-all/route');
      const req = new Request('https://panic.andrewwangdev.com/api/user/revoke-all', { method: 'POST' });
      const res = await POST(req);
      expect(res.status).toBe(401);
    });

    it('atomically executes user.update and token.updateMany inside $transaction', async () => {
      mockAuth.mockResolvedValueOnce({ user: { id: 'user_test_1' } });
      const { POST } = await import('../src/app/api/user/revoke-all/route');
      const req = new Request('https://panic.andrewwangdev.com/api/user/revoke-all', {
        method: 'POST',
        headers: { 'cf-ray': 'ray_123-LAX' }
      });
      const res = await POST(req);
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.success).toBe(true);

      // Verify that $transaction was called
      expect(mockTransaction).toHaveBeenCalledTimes(1);
      const transactionArgs = mockTransaction.mock.calls[0][0];
      expect(Array.isArray(transactionArgs)).toBe(true);
      expect(transactionArgs.length).toBe(2);

      // Verify audit log creation
      expect(mockChaosLogCreate).toHaveBeenCalledWith(expect.objectContaining({
        data: expect.objectContaining({
          userId: 'user_test_1',
          injectedFault: 'TOKEN_REVOKED',
          source: 'WEB_DASHBOARD'
        })
      }));
    });
  });

  describe('POST /api/user/delete', () => {
    it('rejects unauthenticated requests with 401', async () => {
      mockAuth.mockResolvedValueOnce(null);
      const { POST } = await import('../src/app/api/user/delete/route');
      const req = new Request('https://panic.andrewwangdev.com/api/user/delete', { method: 'POST' });
      const res = await POST(req);
      expect(res.status).toBe(401);
    });

    it('atomically scrambles user profile and revokes tokens inside $transaction', async () => {
      mockAuth.mockResolvedValueOnce({ user: { id: 'user_test_1' } });
      const { POST } = await import('../src/app/api/user/delete/route');
      const req = new Request('https://panic.andrewwangdev.com/api/user/delete', { method: 'POST' });
      const res = await POST(req);
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.success).toBe(true);

      // Verify $transaction was called
      expect(mockTransaction).toHaveBeenCalledTimes(1);
      const transactionArgs = mockTransaction.mock.calls[0][0];
      expect(Array.isArray(transactionArgs)).toBe(true);
      expect(transactionArgs.length).toBe(2);
    });

    it('blocks cross-origin malicious mutation requests with 403 (PD-AUDIT-03)', async () => {
      mockAuth.mockResolvedValueOnce({ user: { id: 'user_test_1' } });
      const { POST: revokePost } = await import('../src/app/api/user/revoke-all/route');
      const maliciousReq = new Request('https://panic.andrewwangdev.com/api/user/revoke-all', {
        method: 'POST',
        headers: {
          origin: 'https://attacker.andrewwangdev.com',
          host: 'panic.andrewwangdev.com'
        }
      });
      const res = await revokePost(maliciousReq);
      expect(res.status).toBe(403);
      expect(await res.json()).toEqual({ error: 'Forbidden: Cross-Origin Request Blocked' });

      // Verify same origin is permitted
      mockAuth.mockResolvedValueOnce({ user: { id: 'user_test_1' } });
      const legitimateReq = new Request('https://panic.andrewwangdev.com/api/user/revoke-all', {
        method: 'POST',
        headers: {
          origin: 'https://panic.andrewwangdev.com',
          host: 'panic.andrewwangdev.com'
        }
      });
      const resOk = await revokePost(legitimateReq);
      expect(resOk.status).toBe(200);
    });
  });

  describe('POST /api/user/api-key (PD-INFO-08)', () => {
    it('generates API key without cascading token revocation by default', async () => {
      mockAuth.mockResolvedValueOnce({ user: { id: 'user_test_1' } });
      const { POST: apiKeyPost } = await import('../src/app/api/user/api-key/route');
      const req = new Request('https://panic.andrewwangdev.com/api/user/api-key', {
        method: 'POST',
        headers: {
          origin: 'https://panic.andrewwangdev.com',
          host: 'panic.andrewwangdev.com',
          'content-type': 'application/json'
        },
        body: JSON.stringify({})
      });
      const res = await apiKeyPost(req);
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.success).toBe(true);
      expect(json.cascadeRevoked).toBe(false);
      expect(json.message).toContain('Active tokens remain valid');
      expect(mockTransaction).not.toHaveBeenCalled();
      expect(mockUserUpdate).toHaveBeenCalledWith(expect.objectContaining({
        where: { id: 'user_test_1' },
        data: expect.objectContaining({ apiKeyHash: expect.any(String) })
      }));
    });

    it('cascades token revocation and increments jwtSalt when cascadeRevokeTokens is true', async () => {
      mockAuth.mockResolvedValueOnce({ user: { id: 'user_test_1' } });
      const { POST: apiKeyPost } = await import('../src/app/api/user/api-key/route');
      const req = new Request('https://panic.andrewwangdev.com/api/user/api-key', {
        method: 'POST',
        headers: {
          origin: 'https://panic.andrewwangdev.com',
          host: 'panic.andrewwangdev.com',
          'content-type': 'application/json'
        },
        body: JSON.stringify({ cascadeRevokeTokens: true })
      });
      const res = await apiKeyPost(req);
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.success).toBe(true);
      expect(json.cascadeRevoked).toBe(true);
      expect(json.message).toContain('all active tokens revoked');
      expect(mockTransaction).toHaveBeenCalledTimes(1);
    });
  });
});
