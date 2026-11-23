import { NextResponse } from 'next/server';
import { verifyTurnstileToken } from '@/lib/turnstile';
import { checkRateLimit } from '@/lib/rateLimit';

export async function POST(req: Request) {
  const contentType = req.headers.get('content-type') || '';
  if (!contentType.toLowerCase().includes('application/json')) {
    return NextResponse.json({ error: 'Content-Type must be application/json' }, { status: 415 });
  }

  // 1. IP Rate Limiting: max 15 requests per minute to prevent Turnstile open-proxy abuse.
  const clientIp = req.headers.get('cf-connecting-ip') || req.headers.get('x-forwarded-for') || 'unknown';
  const rateLimit = checkRateLimit(`turnstile:${clientIp}`, 15, 60000);
  if (!rateLimit.allowed) {
    return NextResponse.json({
      success: false,
      error: 'Too many verification attempts. Please wait a moment.'
    }, { status: 429, headers: { 'Retry-After': '5' } });
  }

  // 2. Validate request body
  let body: { token?: unknown };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ success: false, error: 'Invalid JSON request body' }, { status: 400 });
  }

  try {
    const token = typeof body?.token === 'string' ? body.token.trim() : '';
    // Cloudflare Turnstile tokens are base64/hex strings between 20 and 2048 chars
    if (!token || token.length < 20 || token.length > 2048) {
      return NextResponse.json({ success: false, error: 'Invalid turnstile token format' }, { status: 400 });
    }

    const isValid = await verifyTurnstileToken(token);
    if (!isValid) return NextResponse.json({ success: false, error: 'Invalid turnstile token' }, { status: 403 });

    return NextResponse.json({ success: true });
  } catch (e: unknown) {
    console.error('Turnstile verification error:', e);
    return NextResponse.json({ success: false, error: 'Security verification service error' }, { status: 500 });
  }
}
