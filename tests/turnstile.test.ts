import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockVerifyTurnstileToken = vi.fn();

vi.mock('@/lib/turnstile', () => ({
  verifyTurnstileToken: (token: string) => mockVerifyTurnstileToken(token)
}));

describe('Turnstile API (POST /api/turnstile)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('rejects invalid JSON request body with 400', async () => {
    const { POST } = await import('../src/app/api/turnstile/route');
    const req = new Request('https://panic.andrewwangdev.com/api/turnstile', {
      method: 'POST',
      body: 'invalid-json'
    });
    const res = await POST(req);
    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.success).toBe(false);
  });

  it('rejects missing or abnormally short token with 400', async () => {
    const { POST } = await import('../src/app/api/turnstile/route');
    const req = new Request('https://panic.andrewwangdev.com/api/turnstile', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: 'short' })
    });
    const res = await POST(req);
    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error).toContain('Invalid turnstile token format');
  });

  it('validates legitimate token successfully', async () => {
    mockVerifyTurnstileToken.mockResolvedValueOnce(true);
    const { POST } = await import('../src/app/api/turnstile/route');
    const req = new Request('https://panic.andrewwangdev.com/api/turnstile', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'cf-connecting-ip': '203.0.113.195'
      },
      body: JSON.stringify({ token: '0.valid_turnstile_token_example_1234567890' })
    });
    const res = await POST(req);
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.success).toBe(true);
  });

  it('enforces IP rate limiting (15 req/min)', async () => {
    mockVerifyTurnstileToken.mockResolvedValue(true);
    const { POST } = await import('../src/app/api/turnstile/route');
    const ip = '198.51.100.77';

    // Send 15 requests
    for (let i = 0; i < 15; i++) {
      const req = new Request('https://panic.andrewwangdev.com/api/turnstile', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'cf-connecting-ip': ip
        },
        body: JSON.stringify({ token: '0.valid_turnstile_token_example_1234567890' })
      });
      const res = await POST(req);
      expect(res.status).toBe(200);
    }

    // 16th request should be blocked with 429
    const req = new Request('https://panic.andrewwangdev.com/api/turnstile', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'cf-connecting-ip': ip
      },
      body: JSON.stringify({ token: '0.valid_turnstile_token_example_1234567890' })
    });
    const res = await POST(req);
    expect(res.status).toBe(429);
    const json = await res.json();
    expect(json.error).toContain('Too many verification attempts');
  });
});
