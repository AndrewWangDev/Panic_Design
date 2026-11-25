import { NextResponse } from 'next/server';
import { authenticateApiKey } from '@/lib/apiKey';
import { checkRateLimit } from '@/lib/rateLimit';
import { getPrisma } from '@/lib/prisma';
import { checkAndUpdateQuota, refundQuota } from '@/lib/quota';
import { isPrivateIp, isValidTargetHost, parseTargetHost, resolveHostIps } from '@/lib/security';
import { SignJWT } from 'jose';
import { getCloudflareContext } from '@opennextjs/cloudflare';

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
    const maxActiveWindowStart = new Date(now - 7 * 24 * 60 * 60 * 1000);

    // 1. Calculate true active token count matching creation cap enforcement logic.
    const unrevokedTokens = await prisma.token.findMany({
      where: {
        userId: user.id,
        isRevoked: false,
        createdAt: { gte: maxActiveWindowStart }
      },
      select: {
        createdAt: true,
        config: true
      }
    });

    let trueActiveCount = 0;
    for (const t of unrevokedTokens) {
      try {
        const conf = JSON.parse(t.config);
        const tTtl = parseFloat(conf.ttlHours || conf.ttl) || 0.25;
        const exp = new Date(t.createdAt).getTime() + tTtl * 3600 * 1000;
        if (exp > now) {
          trueActiveCount++;
        }
      } catch {
        // Fall back to 0.25h default TTL from creation if config serialization is corrupted.
        const exp = new Date(t.createdAt).getTime() + 0.25 * 3600 * 1000;
        if (exp > now) {
          trueActiveCount++;
        }
      }
    }

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
    const maxActiveWindowStart = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const unrevokedTokens = await prisma.token.findMany({
      where: {
        userId: user.id,
        isRevoked: false,
        createdAt: { gte: maxActiveWindowStart }
      },
      select: {
        id: true,
        tokenHint: true,
        createdAt: true,
        config: true
      }
    });

    let activeCount = 0;
    const nowMs = Date.now();
    const trulyActiveTokens: Array<{ id: string; hint: string | null }> = [];
    for (const t of unrevokedTokens) {
      try {
        const conf = JSON.parse(t.config);
        const tTtl = conf.ttlHours || conf.ttl || 0.25;
        const exp = new Date(t.createdAt).getTime() + tTtl * 3600 * 1000;
        if (exp > nowMs) {
          activeCount++;
          trulyActiveTokens.push({ id: t.id, hint: t.tokenHint });
        }
      } catch {
        // Fall back to 0.25h default TTL from creation if config serialization is corrupted.
        const exp = new Date(t.createdAt).getTime() + 0.25 * 3600 * 1000;
        if (exp > nowMs) {
          activeCount++;
          trulyActiveTokens.push({ id: t.id, hint: t.tokenHint });
        }
      }
    }

    if (activeCount >= 5) {
      return NextResponse.json({
        error: 'CONCURRENT_CAP_EXCEEDED',
        message: 'Account active token limit reached (5 tokens max). Revoke an existing token with DELETE /api/v1/chaos/tokens/:id before creating a new one.',
        activeTokens: trulyActiveTokens
      }, { status: 403 });
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

    // Cloudflare signing secret: enforce dedicated CHAOS_JWT_SECRET in production (SEC-03-EXT)
    const { env } = getCloudflareContext();
    const isProd = process.env.NODE_ENV === 'production';
    const chaosSecret = (env as any)?.CHAOS_JWT_SECRET || process.env.CHAOS_JWT_SECRET;
    if (!chaosSecret) {
      if (isProd) {
        if (quotaDeducted && userId) await refundQuota(userId, quotaDeductedAt);
        console.error('[SECURITY FATAL] Dedicated CHAOS_JWT_SECRET is missing in production. Token signing refused (SEC-03-EXT).');
        return NextResponse.json({ error: 'Server misconfiguration: CHAOS_JWT_SECRET required in production' }, { status: 500 });
      }
    }
    const authSecret = chaosSecret || (env as any)?.AUTH_SECRET || process.env.AUTH_SECRET;
    if (!authSecret) {
      if (quotaDeducted && userId) await refundQuota(userId, quotaDeductedAt);
      console.error('Missing CHAOS_JWT_SECRET or AUTH_SECRET in environment');
      return NextResponse.json({ error: 'Server misconfiguration: missing signing secret' }, { status: 500 });
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

    // Persist Token to D1
    const token = await prisma.token.create({
      data: {
        userId: user.id,
        targetHost: cleanHost,
        config: configStr,
        tokenHint: '',
        issuedWithSalt: userRecord.jwtSalt,
        isRevoked: false
      }
    });

    // Strict post-creation TOCTOU concurrency check (Cap = 5, bounded by 7d window)
    const postCheckTokens = await prisma.token.findMany({
      where: {
        userId: user.id,
        isRevoked: false,
        createdAt: { gte: maxActiveWindowStart }
      },
      select: {
        id: true,
        tokenHint: true,
        createdAt: true,
        config: true
      },
      orderBy: [{ createdAt: 'asc' }, { id: 'asc' }]
    });

    interface ActiveTokenRecord {
      id: string;
      isConfirmed: boolean;
      createdAtMs: number;
    }

    const activeTokens: ActiveTokenRecord[] = [];
    const postNowMs = Date.now();
    for (const t of postCheckTokens) {
      let ttlH = 0.25;
      try {
        const conf = JSON.parse(t.config);
        ttlH = conf.ttlHours || conf.ttl || 0.25;
      } catch {
        ttlH = 0.25;
      }
      const expMs = new Date(t.createdAt).getTime() + (ttlH * 60 * 60 * 1000);
      if (expMs > postNowMs) {
        activeTokens.push({
          id: t.id,
          isConfirmed: Boolean(t.tokenHint && t.tokenHint !== ''),
          createdAtMs: new Date(t.createdAt).getTime()
        });
      }
    }

    if (activeTokens.length > 5) {
      // Deterministic prioritization:
      // 1. Confirmed tokens (tokenHint !== '') take absolute priority over pending unconfirmed tokens (tokenHint === '').
      // 2. Earlier createdAtMs first.
      // 3. Smaller id first (deterministic tie-breaker).
      activeTokens.sort((a, b) => {
        if (a.isConfirmed !== b.isConfirmed) {
          return a.isConfirmed ? -1 : 1;
        }
        if (a.createdAtMs !== b.createdAtMs) {
          return a.createdAtMs - b.createdAtMs;
        }
        return a.id.localeCompare(b.id);
      });

      const allowedSlotIds = new Set(activeTokens.slice(0, 5).map(t => t.id));
      if (!allowedSlotIds.has(token.id)) {
        // Current token did not secure one of the top 5 active slots.
        // Self-revoke ONLY this token to eliminate PD-NEW-01 silent revocation regression.
        await prisma.token.update({
          where: { id: token.id },
          data: { isRevoked: true }
        }).catch(() => {});

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
    }

    // Sign JWT
    const expSeconds = Math.floor(ttlHours * 3600);
    const secret = new TextEncoder().encode(authSecret);

    const jwtToken = await new SignJWT({
      tokenId: token.id,
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
      .sign(secret);

    // Compute authentic JWT tokenHint matching Web UI convention
    const tokenHint = `eyJhbGci...${jwtToken.slice(-4)}`;
    await prisma.token.update({
      where: { id: token.id },
      data: { tokenHint }
    });

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
