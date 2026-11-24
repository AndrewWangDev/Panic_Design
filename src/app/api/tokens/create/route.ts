import { NextResponse } from 'next/server';
import { auth } from '@/auth';
import { getPrisma } from '@/lib/prisma';
import { checkAndUpdateQuota, refundQuota } from '@/lib/quota';
import { SignJWT } from 'jose';
import { isPrivateIp, isValidTargetHost, parseTargetHost, resolveGeoCoordinates, resolveHostIps, validateSameOrigin } from '@/lib/security';
import { getCloudflareContext } from '@opennextjs/cloudflare';

const ALLOWED_FAULTS = new Set(['502', '504', '429', '444', 'latency']);
const ALLOWED_SCOPES = new Set(['Global', 'Cloud ASNs', 'Cellular', 'Cross-Region', 'Bots Only']);
const ALLOWED_DISTRIBUTIONS = new Set(['Uniform', 'Normal', 'Spikes']);
const ALLOWED_MUTILATIONS = new Set(['None', 'Unexpected EOF', 'Type Poisoning', 'Empty Shell']);

export async function POST(req: Request) {
  if (!validateSameOrigin(req)) {
    return NextResponse.json({ error: "Forbidden: Cross-Origin Request Blocked" }, { status: 403 });
  }

  let userId: string | null = null;
  let quotaDeducted = false;
  let quotaDeductedAt: Date | undefined;
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
    const effLatency = typeof latency === 'number' ? latency : 50;
    const effJitter = typeof jitter === 'number' ? jitter : 0;
    if (fault === 'latency' && effJitter > effLatency) {
      return NextResponse.json({ error: 'INVALID_PARAMETERS', message: 'Jitter cannot exceed base latency.' }, { status: 400 });
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

    // Pre-check signing secret before deducting quota or writing to DB (SEC-03)
    const { env } = getCloudflareContext();
    const hasDedicatedChaosSecret = Boolean((env as any)?.CHAOS_JWT_SECRET || process.env.CHAOS_JWT_SECRET);
    if (!hasDedicatedChaosSecret && process.env.NODE_ENV === 'production') {
      console.warn('[SECURITY WARNING] Dedicated CHAOS_JWT_SECRET is missing in production. Falling back to AUTH_SECRET (SEC-03).');
    }
    const authSecret = (env as any)?.CHAOS_JWT_SECRET || process.env.CHAOS_JWT_SECRET || (env as any)?.AUTH_SECRET || process.env.AUTH_SECRET;
    if (!authSecret) {
      console.error('Missing CHAOS_JWT_SECRET or AUTH_SECRET in environment');
      return NextResponse.json({ error: 'Server misconfiguration: missing signing secret' }, { status: 500 });
    }

    // Pre-flight DNS (A + AAAA) SSRF check before quota deduction or token creation
    const parsedTarget = parseTargetHost(cleanHost);
    const resolvedHost = await resolveHostIps(cleanHost);
    if (!parsedTarget?.isIp && resolvedHost.ips.length === 0) {
      return NextResponse.json({
        error: 'DNS_RESOLUTION_FAILED',
        message: 'Target domain could not be resolved to any valid IP address.'
      }, { status: 400 });
    }
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
    quotaDeductedAt = new Date();

    const prisma = getPrisma();

    // Check concurrent active tokens before creation (bounded by 7d max TTL window to prevent N+1 full table scan)
    const maxActiveWindowStart = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const unrevokedTokens = await prisma.token.findMany({
      where: {
        userId: session.user.id,
        isRevoked: false,
        createdAt: { gte: maxActiveWindowStart }
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
        // Fall back to 0.25h default TTL from creation if config serialization is corrupted.
        const expiresAtMs = new Date(t.createdAt).getTime() + (0.25 * 60 * 60 * 1000);
        if (expiresAtMs > nowMs) {
          activeCount++;
        }
      }
    }

    if (activeCount >= 5) {
      if (quotaDeducted && userId) {
        await refundQuota(userId, quotaDeductedAt);
        quotaDeducted = false;
      }
      return NextResponse.json({ error: 'CONCURRENT_CAP_EXCEEDED' }, { status: 403 });
    }

    // Fetch latest user salt (verify active, non-deleted account)
    const user = await prisma.user.findFirst({
      where: {
        id: session.user.id,
        githubId: { not: null }
      },
      select: { jwtSalt: true }
    });

    if (!user) {
      if (quotaDeducted && userId) {
        await refundQuota(userId, quotaDeductedAt);
        quotaDeducted = false;
      }
      return NextResponse.json({ error: 'User not found or account deleted' }, { status: 401 });
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

    // Post-creation TOCTOU concurrency check: verify active count does not exceed limit (bounded by 7d window)
    const postCheckTokens = await prisma.token.findMany({
      where: {
        userId: session.user.id,
        isRevoked: false,
        createdAt: { gte: maxActiveWindowStart }
      },
      select: {
        id: true,
        createdAt: true,
        config: true
      },
      orderBy: [{ createdAt: 'asc' }, { id: 'asc' }]
    });

    const activeTokens: { id: string }[] = [];
    const postNowMs = Date.now();
    for (const t of postCheckTokens) {
      try {
        const conf = JSON.parse(t.config);
        const ttlH = conf.ttlHours || conf.ttl || 0.25;
        const expMs = new Date(t.createdAt).getTime() + (ttlH * 60 * 60 * 1000);
        if (expMs > postNowMs) {
          activeTokens.push(t);
        }
      } catch {
        // Fall back to 0.25h default TTL from creation if config serialization is corrupted.
        const expMs = new Date(t.createdAt).getTime() + (0.25 * 60 * 60 * 1000);
        if (expMs > postNowMs) {
          activeTokens.push(t);
        }
      }
    }

    let isWithinCap = true;
    if (activeTokens.length > 5) {
      isWithinCap = activeTokens.slice(0, 5).some(t => t.id === token.id);
    }
    if (!isWithinCap) {
      // Revert/revoke the token immediately to maintain strict 5-token cap
      await prisma.token.update({
        where: { id: token.id },
        data: { isRevoked: true }
      });
      if (quotaDeducted && userId) {
        await refundQuota(userId, quotaDeductedAt);
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

    // Resolve W3 (Target Host) coordinates with 300ms fail-fast timeout and 24h LRU caching.
    let w3: [number, number] | undefined = undefined;
    if (resolvedHost.primaryIp) {
      const coords = await resolveGeoCoordinates(resolvedHost.primaryIp);
      if (coords) {
        w3 = coords;
      }
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
      await refundQuota(userId, quotaDeductedAt);
      quotaDeducted = false;
    }
    console.error('Create Token Error:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}
