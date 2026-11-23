import { describe, it, expect, beforeEach } from 'vitest';
import { checkRateLimit, _getRateLimitStoreSize, _clearRateLimitStore } from '../src/lib/rateLimit';

describe('Rate Limit Engine (src/lib/rateLimit.ts) - PD-AUDIT-01', () => {
  beforeEach(() => {
    _clearRateLimitStore();
  });

  it('allows requests within window and blocks exceeding attempts', () => {
    const id = 'test-client-1';
    for (let i = 0; i < 5; i++) {
      const res = checkRateLimit(id, 5, 60000);
      expect(res.allowed).toBe(true);
    }
    const blocked = checkRateLimit(id, 5, 60000);
    expect(blocked.allowed).toBe(false);
    expect(blocked.remaining).toBe(0);
  });

  it('caps memoryStore size to 5000 and evicts oldest entries (PD-AUDIT-01)', () => {
    // Generate 5010 distinct identifiers
    for (let i = 0; i < 5010; i++) {
      checkRateLimit(`ip:203.0.113.${i}`, 15, 60000);
    }

    expect(_getRateLimitStoreSize()).toBe(5000);
  });
});
