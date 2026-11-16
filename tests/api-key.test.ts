import { describe, it, expect, vi, beforeEach } from 'vitest';
import { generateRawApiKey, hashApiKey, extractApiKeyPrefix, authenticateApiKey } from '../src/lib/apiKey';

const mockFindUnique = vi.fn();

vi.mock('@/lib/prisma', () => ({
  getPrisma: () => ({
    user: {
      findUnique: mockFindUnique
    }
  })
}));

describe('Developer API Key System', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('generates high-entropy keys with pd_live_ prefix and 40-char length', () => {
    const key1 = generateRawApiKey();
    const key2 = generateRawApiKey();
    expect(key1).toMatch(/^pd_live_[0-9a-zA-Z]{32}$/);
    expect(key2).toMatch(/^pd_live_[0-9a-zA-Z]{32}$/);
    expect(key1).not.toBe(key2);
  });

  it('computes deterministic SHA-256 hash across executions', async () => {
    const testKey = 'pd_live_testkey1234567890abcdefghijklmnopqrstuvwxyz';
    const hash1 = await hashApiKey(testKey);
    const hash2 = await hashApiKey(testKey);
    expect(hash1).toBe(hash2);
    expect(hash1.length).toBe(64); // 256 bits = 64 hex chars
  });

  it('extracts safe prefix for UI display', () => {
    const key = 'pd_live_abcdef1234567890';
    const prefix = extractApiKeyPrefix(key);
    expect(prefix).toBe('pd_live_abcdef...');
    expect(prefix).not.toContain('1234567890');
  });

  it('rejects null, malformed, or non-Bearer authorization headers', async () => {
    expect(await authenticateApiKey(null)).toBeNull();
    expect(await authenticateApiKey('')).toBeNull();
    expect(await authenticateApiKey('Bearer invalid_prefix')).toBeNull();
    expect(await authenticateApiKey('Basic 123456')).toBeNull();
    expect(mockFindUnique).not.toHaveBeenCalled();
  });

  it('resolves user when given a valid API key matching database hash', async () => {
    const rawKey = 'pd_live_validkey123456789012345678901234';
    const expectedHash = await hashApiKey(rawKey);

    mockFindUnique.mockResolvedValueOnce({
      id: 'user_dev_123',
      username: 'dev_user',
      email: 'dev@example.com'
    });

    const user = await authenticateApiKey(`Bearer ${rawKey}`);
    expect(user).not.toBeNull();
    expect(user?.id).toBe('user_dev_123');
    expect(mockFindUnique).toHaveBeenCalledWith({
      where: { apiKeyHash: expectedHash },
      select: { id: true, username: true, email: true }
    });
  });
});
