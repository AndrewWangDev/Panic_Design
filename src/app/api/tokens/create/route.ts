import { NextResponse } from 'next/server';
import { auth } from '@/auth';
import { getPrisma } from '@/lib/prisma';
import { checkAndUpdateQuota, refundQuota } from '@/lib/quota';
import { SignJWT } from 'jose';
import { isPrivateIp, isValidTargetHost, resolveHostIps } from '@/lib/security';
import { getCloudflareContext } from '@opennextjs/cloudflare';

const ALLOWED_FAULTS = new Set(['502', '504', '429', '444', 'latency']);
const ALLOWED_SCOPES = new Set(['Global', 'Cloud ASNs', 'Cellular', 'Cross-Region', 'Bots Only']);
const ALLOWED_DISTRIBUTIONS = new Set(['Uniform', 'Normal', 'Spikes']);
const ALLOWED_MUTILATIONS = new Set(['None', 'Unexpected EOF', 'Type Poisoning', 'Empty Shell']);

export async function POST(req: Request) {
  let userId: string | null = null;
  let quotaDeducted = false;
  try {
    const session = await auth();
    if (!session?.user?.id) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    userId = session.user.id;

    const contentType = req.headers.get('content-type') || '';
    if (!contentType.toLowerCase().includes('application/json')) {
      return NextResponse.json({ error: 'Content-Type must be application/json' }, { status: 415 });
    }

    let body: any;
    try {
      body = await req.json();
    } catch {
      return NextResponse.json({ error: 'Invalid JSON payload' }, { status: 400 });
    }

    const { targetHost, scope, fault, latency, jitter, distribution, packetLoss, mutilationStrategy, customTtl, turnstileToken } = body ?? {};

    const cleanHost = typeof targetHost === 'string' ? targetHost.trim().toLowerCase() : '';

    if (!cleanHost || !fault) {
      return NextResponse.json({ error: 'Missing required parameters' }, { status: 400 });
    }

    // Strict parameter whitelist & numeric bounds validation
    if (typeof fault !== 'string' || !ALLOWED_FAULTS.has(fault)) {
      return NextResponse.json({ error: 'INVALID_PARAMETERS', message: 'Invalid fault type.' }, { status: 400 });
    }
    if (scope !== undefined && (typeof scope !== 'string' || !ALLOWED_SCOPES.has(scope))) {
      return NextResponse.json({ error: 'INVALID_PARAMETERS', message: 'Invalid scope value.' }, { status: 400 });
    }
    if (distribution !== undefined && (typeof distribution !== 'string' || !ALLOWED_DISTRIBUTIONS.has(distribution))) {
      return NextResponse.json({ error: 'INVALID_PARAMETERS', message: 'Invalid distribution value.' }, { status: 400 });
    }
    if (mutilationStrategy !== undefined && (typeof mutilationStrategy !== 'string' || !ALLOWED_MUTILATIONS.has(mutilationStrategy))) {
      return NextResponse.json({ error: 'INVALID_PARAMETERS', message: 'Invalid mutilation strategy.' }, { status: 400 });
    }
    if (latency !== undefined && (typeof latency !== 'number' || !Number.isFinite(latency) || latency < 0 || latency > 10000)) {
      return NextResponse.json({ error: 'INVALID_PARAMETERS', message: 'Latency must be between 0 and 10000 ms.' }, { status: 400 });
    }
    if (jitter !== undefined && (typeof jitter !== 'number' || !Number.isFinite(jitter) || jitter < 0 || jitter > 10000)) {
      return NextResponse.json({ error: 'INVALID_PARAMETERS', message: 'Jitter must be between 0 and 10000 ms.' }, { status: 400 });
    }
    if (packetLoss !== undefined && (typeof packetLoss !== 'number' || !Number.isFinite(packetLoss) || packetLoss < 0 || packetLoss > 100)) {
      return NextResponse.json({ error: 'INVALID_PARAMETERS', message: 'Packet loss must be between 0 and 100%.' }, { status: 400 });
    }
    if (customTtl !== undefined && customTtl !== null && (typeof customTtl !== 'number' || !Number.isFinite(customTtl) || customTtl < 0.05 || customTtl > 168)) {
      return NextResponse.json({ error: 'INVALID_PARAMETERS', message: 'TTL must be between 0.05 and 168 hours.' }, { status: 400 });
    }

    // SSRF & Host format protection
    if (!isValidTargetHost(cleanHost)) {
      return NextResponse.json({
        error: 'INVALID_TARGET_HOST',
        message: 'Target host is invalid or resolves to a private, loopback, or restricted network.'
      }, { status: 400 });
    }

    // Turnstile Check
    if (process.env.NODE_ENV !== 'development' && !turnstileToken) {
      return NextResponse.json({ error: 'Security verification missing' }, { status: 403 });
    }
    if (turnstileToken) {
      const { verifyTurnstileToken } = await import('@/lib/turnstile');
      const isValid = await verifyTurnstileToken(turnstileToken);
      if (!isValid) return NextResponse.json({ error: 'Security verification failed' }, { status: 403 });
    }

    // Pre-check signing secret before deducting quota or writing to DB
    const { env } = getCloudflareContext();
    const authSecret = (env as any)?.AUTH_SECRET || process.env.AUTH_SECRET;
    if (!authSecret) {
      console.error('Missing AUTH_SECRET in environment');
      return NextResponse.json({ error: 'Server misconfiguration: missing AUTH_SECRET' }, { status: 500 });
    }

    // Pre-flight DNS (A + AAAA) SSRF check before quota deduction or token creation
    const resolvedHost = await resolveHostIps(cleanHost);
    if (resolvedHost.ips.some((ip) => isPrivateIp(ip))) {
      return NextResponse.json({
        error: 'SSRF_DETECTED',
        message: 'Target host resolves to a private or restricted IP address.'
      }, { status: 400 });
    }

    // Check Quota Limit
    const quota = await checkAndUpdateQuota(session.user.id);
    if (!quota.allowed) {
      return NextResponse.json({ error: 'QUOTA_EXCEEDED', message: quota.reason }, { status: 429 });
    }
    quotaDeducted = true;

    const prisma = getPrisma();

    // Check concurrent active tokens before creation
    const unrevokedTokens = await prisma.token.findMany({
      where: {
        userId: session.user.id,
        isRevoked: false
      },
      select: {
        createdAt: true,
        config: true
      }
    });

    let activeCount = 0;
    const nowMs = Date.now();
    for (const t of unrevokedTokens) {
      try {
        const conf = JSON.parse(t.config);
        const ttlHours = conf.ttlHours || conf.ttl || 0.25;
        const expiresAtMs = new Date(t.createdAt).getTime() + (ttlHours * 60 * 60 * 1000);
        if (expiresAtMs > nowMs) {
          activeCount++;
        }
      } catch {
        activeCount++;
      }
    }

    if (activeCount >= 5) {
      if (quotaDeducted && userId) {
        await refundQuota(userId);
        quotaDeducted = false;
      }
      return NextResponse.json({ error: 'CONCURRENT_CAP_EXCEEDED' }, { status: 403 });
    }

    // Fetch latest user salt
    const user = await prisma.user.findUnique({
      where: { id: session.user.id },
      select: { jwtSalt: true }
    });

    if (!user) {
      if (quotaDeducted && userId) {
        await refundQuota(userId);
        quotaDeducted = false;
      }
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
    }

    // Default TTL is 15 minutes if not specified
    const ttlHours = customTtl || 0.25;

    // Prepare Token config JSON
    const config = JSON.stringify({
      fault,
      scope,
      latency,
      jitter,
      distribution,
      packetLoss,
      mutilationStrategy,
      ttlHours
    });

    // Create DB entry first to get the Token ID
    const token = await prisma.token.create({
      data: {
        userId: session.user.id,
        targetHost: cleanHost,
        config,
        tokenHint: '', // Will update later after signing
        issuedWithSalt: user.jwtSalt
      }
    });

    // Post-creation TOCTOU concurrency check: verify active count does not exceed limit
    const postCheckTokens = await prisma.token.findMany({
      where: {
        userId: session.user.id,
        isRevoked: false
      },
      select: {
        id: true,
        createdAt: true,
        config: true
      },
      orderBy: { createdAt: 'asc' }
    });

    let verifiedActive = 0;
    const postNowMs = Date.now();
    for (const t of postCheckTokens) {
      try {
        const conf = JSON.parse(t.config);
        const ttlH = conf.ttlHours || conf.ttl || 0.25;
        const expMs = new Date(t.createdAt).getTime() + (ttlH * 60 * 60 * 1000);
        if (expMs > postNowMs) {
          verifiedActive++;
        }
      } catch {
        verifiedActive++;
      }
    }

    if (verifiedActive > 5) {
      // Revert/revoke the token immediately to maintain strict 5-token cap
      await prisma.token.update({
        where: { id: token.id },
        data: { isRevoked: true }
      });
      if (quotaDeducted && userId) {
        await refundQuota(userId);
        quotaDeducted = false;
      }
      return NextResponse.json({
        error: 'CONCURRENT_CAP_EXCEEDED',
        message: 'Maximum limit of 5 concurrent active tokens reached.'
      }, { status: 403 });
    }

    // Generate JWT using pre-checked authSecret
    const secret = new TextEncoder().encode(authSecret);
    
    // Convert ttlHours to seconds string for expiration
    const expSeconds = Math.floor(ttlHours * 3600);

    // Resolve W3 (Target Host) coordinates using pre-resolved primary IP with timeout
    let w3: [number, number] | undefined = undefined;
    try {
      const address = resolvedHost.primaryIp;
      if (address) {
        // Get geo coordinates
        const geoRes = await fetch(`https://ipapi.co/${address}/json/`, {
          signal: AbortSignal.timeout(3000)
        });
        const geoData = await geoRes.json() as any;
        if (geoData && typeof geoData.longitude === 'number' && typeof geoData.latitude === 'number') {
          w3 = [geoData.longitude, geoData.latitude];
        }
      }
    } catch (geoErr) {
      console.warn('Failed to resolve W3 coordinates:', geoErr);
      // Proceed without w3, backend will handle fallback
    }

    const jwt = await new SignJWT({
      tokenId: token.id,
      targetHost: cleanHost,
      scope,
      fault,
      latency,
      jitter,
      distribution,
      packetLoss,
      mutilationStrategy,
      userId: session.user.id,
      jwtSalt: user.jwtSalt,
      issuedWithSalt: user.jwtSalt,
      w3
    })
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
      .setIssuedAt()
      .setExpirationTime(`${expSeconds}s`)
      .sign(secret);

    // Update token hint
    const tokenHint = `eyJhbGci...${jwt.slice(-4)}`;
    await prisma.token.update({
      where: { id: token.id },
      data: { tokenHint }
    });

    return NextResponse.json({
      success: true,
      jwt,
      token: {
        ...token,
        tokenHint
      }
    });
  } catch (error) {
    if (quotaDeducted && userId) {
      await refundQuota(userId);
      quotaDeducted = false;
    }
    console.error('Create Token Error:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}
