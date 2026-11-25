import { NextResponse } from 'next/server';
import { authenticateApiKey } from '@/lib/apiKey';
import { checkRateLimit } from '@/lib/rateLimit';
import { getPrisma } from '@/lib/prisma';
import { checkAndUpdateQuota, refundQuota } from '@/lib/quota';
import { isPrivateIp, isValidTargetHost, parseTargetHost, resolveHostIps } from '@/lib/security';
import { SignJWT } from 'jose';
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

export async function GET(req: Request) {
  try {
    const user = await authenticateApiKey(req.headers.get('authorization'));
    if (!user) {
      return NextResponse.json({
        error: 'UNAUTHORIZED',
        message: 'Valid API key required in Authorization: Bearer pd_live_...'
      }, { status: 401 });
    }

    const prisma = getPrisma();
    const now = Date.now();

    // 1. Calculate true active token count matching creation cap enforcement logic.
    const { activeCount: trueActiveCount } = await countActiveTokens(prisma, user.id, now);

    // 2. Fetch recent 50 tokens for display list
    const dbTokens = await prisma.token.findMany({
      where: { userId: user.id },
      orderBy: { createdAt: 'desc' },
      take: 50
    });

    const tokens = dbTokens.map(t => {
      let isExpired = false;
      let ttlHours = 0.25;
      try {
        const conf = JSON.parse(t.config);
        ttlHours = parseFloat(conf.ttlHours || conf.ttl) || 0.25;
        const expiresAt = t.createdAt.getTime() + ttlHours * 3600 * 1000;
        isExpired = expiresAt <= now;
      } catch {}

      return {
        id: t.id,
        targetHost: t.targetHost,
        tokenHint: t.tokenHint,
        isRevoked: t.isRevoked,
        isExpired,
        status: t.isRevoked ? 'revoked' : (isExpired ? 'expired' : 'active'),
        createdAt: t.createdAt.toISOString()
      };
    });

    return NextResponse.json({
      success: true,
      activeTokensCount: trueActiveCount,
      remainingSlots: Math.max(0, 5 - trueActiveCount),
      tokens
    });
  } catch (error) {
    console.error('Agent List Tokens Error:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}

export async function POST(req: Request) {
  let userId: string | null = null;
  let quotaDeducted = false;
  let quotaDeductedAt: Date | undefined;

  try {
    const user = await authenticateApiKey(req.headers.get('authorization'));
    if (!user) {
      return NextResponse.json({
        error: 'UNAUTHORIZED',
        message: 'Valid API key required in Authorization: Bearer pd_live_...'
      }, { status: 401 });
    }
    userId = user.id;

    // Rate Limiting (Token Bucket per User: 15 req/min)
    const rate = checkRateLimit(`agent:${user.id}`, 15, 60000);
    if (!rate.allowed) {
      return NextResponse.json({
        error: 'RATE_LIMIT_EXCEEDED',
        message: `Too many token requests. Try again in ${Math.ceil(rate.resetMs / 1000)} seconds.`
      }, { status: 429 });
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

    const {
      targetHost,
      scope = 'Global',
      fault,
      latency = 0,
      jitter = 0,
      distribution = 'Uniform',
      packetLoss = 0,
      mutilationStrategy = 'None',
      customTtl
    } = body ?? {};

    const cleanHost = typeof targetHost === 'string' ? targetHost.trim().toLowerCase() : '';
    if (!cleanHost || !fault) {
      return NextResponse.json({
        error: 'MISSING_PARAMETERS',
        message: 'targetHost and fault are required.'
      }, { status: 400 });
    }

    // Whitelist and range validations
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
    if (typeof latency !== 'number' || !Number.isFinite(latency) || latency < 0 || latency > 10000) {
      return NextResponse.json({ error: 'INVALID_PARAMETERS', message: 'Latency must be between 0 and 10000 ms.' }, { status: 400 });
    }
    if (typeof jitter !== 'number' || !Number.isFinite(jitter) || jitter < 0 || jitter > 10000) {
      return NextResponse.json({ error: 'INVALID_PARAMETERS', message: 'Jitter must be between 0 and 10000 ms.' }, { status: 400 });
    }
    if (fault === 'latency' && jitter > latency) {
      return NextResponse.json({ error: 'INVALID_PARAMETERS', message: 'Jitter cannot exceed base latency.' }, { status: 400 });
    }
    if (typeof packetLoss !== 'number' || !Number.isFinite(packetLoss) || packetLoss < 0 || packetLoss > 100) {
      return NextResponse.json({ error: 'INVALID_PARAMETERS', message: 'Packet loss must be between 0 and 100%.' }, { status: 400 });
    }
    
    // Agent TTL: default 15 minutes (0.25h), maximum allowed 2 hours for safe automated testing
    let ttlHours = 0.25;
    if (customTtl !== undefined && customTtl !== null) {
      if (typeof customTtl !== 'number' || !Number.isFinite(customTtl) || customTtl < 0.05 || customTtl > 2) {
        return NextResponse.json({ error: 'INVALID_PARAMETERS', message: 'Agent TTL must be between 0.05 and 2 hours.' }, { status: 400 });
      }
      ttlHours = customTtl;
    }

    // SSRF target host syntax protection
    if (!isValidTargetHost(cleanHost)) {
      return NextResponse.json({
        error: 'INVALID_TARGET_HOST',
        message: 'Target host is invalid or resolves to a private, loopback, or restricted network.'
      }, { status: 400 });
    }

    // Pre-flight DNS (A + AAAA) SSRF check (PD-SEC-02)
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

    const prisma = getPrisma();

    // Check active tokens concurrency limit (Cap = 5, bounded by 7d TTL window to prevent N+1 full scan)
    const { activeCount, activeTokens: trulyActiveTokens, windowStart: maxActiveWindowStart } =
      await countActiveTokens(prisma, user.id);

    if (activeCount >= 5) {
      return NextResponse.json({
        error: 'CONCURRENT_CAP_EXCEEDED',
        message: 'Account active token limit reached (5 tokens max). Revoke an existing token with DELETE /api/v1/chaos/tokens/:id before creating a new one.',
        activeTokens: trulyActiveTokens
      }, { status: 403 });
    }

    // Pre-check dedicated signing secret across all environments before deducting quota or writing to DB (SEC-03-EXT)
    const { env } = getCloudflareContext();
    const authSecret = requireChaosJwtSecret(env);
    if (!authSecret) {
      return missingChaosJwtSecretResponse();
    }

    // Check & update user quota
    const quota = await checkAndUpdateQuota(user.id);
    if (!quota.allowed) {
      return NextResponse.json({ error: 'QUOTA_EXCEEDED', message: quota.reason }, { status: 429 });
    }
    quotaDeducted = true;
    quotaDeductedAt = new Date();

    // Fetch user jwtSalt
    const userRecord = await prisma.user.findUnique({
      where: { id: user.id },
      select: { jwtSalt: true }
    });

    if (!userRecord) {
      if (quotaDeducted && userId) await refundQuota(userId, quotaDeductedAt);
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
    }

    const configStr = JSON.stringify({
      fault,
      scope,
      latency,
      jitter,
      distribution,
      packetLoss,
      mutilationStrategy,
      ttlHours
    });

    const expSeconds = Math.floor(ttlHours * 3600);
    const secret = new TextEncoder().encode(authSecret);

    const mintResult = await mintTokenWithCap({
      d1: (env as { DB?: D1DatabaseLike } | undefined)?.DB,
      prisma,
      userId: user.id,
      targetHost: cleanHost,
      config: configStr,
      issuedWithSalt: userRecord.jwtSalt,
      maxActiveWindowStart,
      signJwt: (tokenId) =>
        new SignJWT({
          tokenId,
          targetHost: cleanHost,
          fault,
          scope,
          latency,
          jitter,
          distribution,
          packetLoss,
          mutilationStrategy,
          ttlHours,
          source: 'AGENT_API',
          userId: user.id,
          jwtSalt: userRecord.jwtSalt,
          issuedWithSalt: userRecord.jwtSalt
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

    const { jwt: jwtToken, tokenHint, token } = mintResult;

    // Record Audit Log (Token Minted via Agent)
    const rayHeader = req.headers.get('cf-ray') || '';
    const rayColo = rayHeader.includes('-') ? rayHeader.split('-')[1]?.toUpperCase() : null;
    const colo = rayColo || req.headers.get('cf-ipcountry') || 'EDGE';

    await prisma.chaosLog.create({
      data: {
        userId: user.id,
        targetUrl: cleanHost,
        injectedFault: 'TOKEN_MINTED',
        source: 'AGENT_API',
        tokenId: token.id,
        tokenHint,
        edgeColo: colo,
        statusCode: 200,
        latencyMs: latency,
        rayId: rayHeader || undefined
      }
    }).catch(err => console.error('Failed to write mint audit log:', err));

    return NextResponse.json({
      success: true,
      tokenId: token.id,
      tokenHint,
      jwtToken,
      gatewayUrl: 'https://gateway.andrewwangdev.com',
      expiresAt: new Date(Date.now() + ttlHours * 3600 * 1000).toISOString(),
      usageExample: `curl -H "X-Chaos-Token: ${jwtToken}" https://gateway.andrewwangdev.com/your-endpoint`,
      activeTokensCount: activeCount + 1,
      remainingSlots: Math.max(0, 4 - activeCount),
      remainingActiveSlots: Math.max(0, 4 - activeCount)
    });
  } catch (error) {
    if (quotaDeducted && userId) {
      try {
        await refundQuota(userId, quotaDeductedAt);
      } catch {}
    }
    console.error('Agent Mint Token Error:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}
