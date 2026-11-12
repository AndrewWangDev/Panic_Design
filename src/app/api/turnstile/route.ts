import { NextResponse } from 'next/server';
import { verifyTurnstileToken } from '@/lib/turnstile';

export async function POST(req: Request) {
  let body: { token?: unknown };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ success: false, error: 'Invalid JSON request body' }, { status: 400 });
  }

  try {
    const token = typeof body?.token === 'string' ? body.token : '';
    if (!token) return NextResponse.json({ success: false, error: 'No token provided' }, { status: 400 });

    const isValid = await verifyTurnstileToken(token);
    if (!isValid) return NextResponse.json({ success: false, error: 'Invalid turnstile token' }, { status: 403 });

    return NextResponse.json({ success: true });
  } catch (e: unknown) {
    console.error('Turnstile verification error:', e);
    return NextResponse.json({ success: false, error: 'Security verification service error' }, { status: 500 });
  }
}
