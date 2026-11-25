import { NextResponse } from 'next/server';
import { auth } from '@/auth';
import { getPrisma } from '@/lib/prisma';
import { checkAndUpdateQuota, refundQuota } from '@/lib/quota';
import { SignJWT } from 'jose';
import { isPrivateIp, isValidTargetHost, parseTargetHost, resolveGeoCoordinates, resolveHostIps, validateSameOrigin } from '@/lib/security';
import { getCloudflareContext } from '@opennextjs/cloudflare';
import {
  countActiveTokens,
  D1DatabaseLike,
  mintTokenWithCap,
  missingChaosJwtSecretResponse,
  requireChaosJwtSecret
} from '@/lib/tokenMinting';

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
    const authedUserId = session.user.id;
    userId = authedUserId;

    const prisma = getPrisma();

    // Verify active, non-deleted user early before quota deduction or state modification (PD-BUG-03)
    const user = await prisma.user.findFirst({
      where: {
        id: session.user.id,
        githubId: { not: null }
      },
      select: { jwtSalt: true }
    });

    if (!user) {
      return NextResponse.json({ error: 'User not found or account deleted' }, { status: 401 });
    }

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

    // Pre-check dedicated signing secret across all environments before deducting quota or writing to DB (SEC-03-EXT)
    const { env } = getCloudflareContext();
    const authSecret = requireChaosJwtSecret(env);
    if (!authSecret) {
      return missingChaosJwtSecretResponse();
    }

    // Pre-flight DNS (A + AAAA) SSRF check before quota deduction or token creation (PD-SEC-02)
    const parsedTarget = parseTargetHost(cleanHost);
    const resolvedHost = await resolveHostIps(cleanHost);
    if (!parsedTarget?.isIp && resolvedHost.error) {
      return NextResponse.json({
        error: 'DNS_RESOLUTION_FAILED',
        message: 'DNS lookup encountered an error or network timeout. Failing closed for security.'
      }, { status: 400 });
    }
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

    // Resolve W3 (Target Host) coordinates with 300ms fail-fast timeout and 24h LRU caching before DB writes
    let w3: [number, number] | undefined = undefined;
    if (resolvedHost.primaryIp) {
      const coords = await resolveGeoCoordinates(resolvedHost.primaryIp);
      if (coords) {
        w3 = coords;
      }
    }

    // Check Quota Limit
    const quota = await checkAndUpdateQuota(session.user.id);
    if (!quota.allowed) {
      return NextResponse.json({ error: 'QUOTA_EXCEEDED', message: quota.reason }, { status: 429 });
    }
    quotaDeducted = true;
    quotaDeductedAt = new Date();

    // Check concurrent active tokens before creation (bounded by 7d max TTL window to prevent N+1 full table scan)
    const { activeCount, windowStart: maxActiveWindowStart } = await countActiveTokens(prisma, session.user.id);

    if (activeCount >= 5) {
      if (quotaDeducted && userId) {
        await refundQuota(userId, quotaDeductedAt);
        quotaDeducted = false;
      }
      return NextResponse.json({ error: 'CONCURRENT_CAP_EXCEEDED' }, { status: 403 });
    }

    // Default TTL is 15 minutes if not specified
    const ttlHours = customTtl || 0.25;

    // Prepare Token config JSON (persisting effLatency for consistent defaults PD-BUG-04)
    const config = JSON.stringify({
      fault,
      scope,
      latency: effLatency,
      jitter: effJitter,
      distribution,
      packetLoss,
      mutilationStrategy,
      ttlHours
    });

    const secret = new TextEncoder().encode(authSecret);
    const expSeconds = Math.floor(ttlHours * 3600);

    const mintResult = await mintTokenWithCap({
      d1: (env as { DB?: D1DatabaseLike } | undefined)?.DB,
      prisma,
      userId: session.user.id,
      targetHost: cleanHost,
      config,
      issuedWithSalt: user.jwtSalt,
      maxActiveWindowStart,
      signJwt: (tokenId) =>
        new SignJWT({
          tokenId,
          targetHost: cleanHost,
          scope,
          fault,
          latency: effLatency,
          jitter: effJitter,
          distribution,
          packetLoss,
          mutilationStrategy,
          userId: authedUserId,
          jwtSalt: user.jwtSalt,
          issuedWithSalt: user.jwtSalt,
          w3
        })
          .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
          .setIssuedAt()
          .setExpirationTime(`${expSeconds}s`)
          .sign(secret)
    });

    if (!mintResult.created) {
      if (quotaDeducted && userId) {
        try {
          await refundQuota(userId, quotaDeductedAt);
        } catch {}
        quotaDeducted = false;
      }
      return NextResponse.json({
        error: 'CONCURRENT_CAP_EXCEEDED',
        message: 'Maximum limit of 5 concurrent active tokens reached.'
      }, { status: 403 });
    }

    const { jwt, tokenHint, token } = mintResult;

    // Record Audit Log for Token Minting (PD-BUG-04)
    if (prisma.chaosLog && typeof prisma.chaosLog.create === 'function') {
      await prisma.chaosLog.create({
        data: {
          userId: authedUserId,
          targetUrl: `https://${cleanHost}`,
          injectedFault: 'TOKEN_MINTED',
          source: 'WEB_DASHBOARD',
          tokenId: token.id,
          tokenHint,
          statusCode: 200,
          latencyMs: effLatency
        }
      }).catch(err => console.warn('Failed to record web token minting audit:', err));
    }

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
      try {
        await refundQuota(userId, quotaDeductedAt);
      } catch {}
      quotaDeducted = false;
    }
    console.error('Create Token Error:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}
