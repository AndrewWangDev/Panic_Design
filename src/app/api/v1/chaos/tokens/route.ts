import { NextResponse } from 'next/server';
import { authenticateApiKey } from '@/lib/apiKey';
import { checkRateLimit } from '@/lib/rateLimit';
import { getPrisma } from '@/lib/prisma';
import { checkAndUpdateQuota, refundQuota } from '@/lib/quota';
import { isPrivateIp, isValidTargetHost, resolveHostIps } from '@/lib/security';
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
    const dbTokens = await prisma.token.findMany({
      where: { userId: user.id },
      orderBy: { createdAt: 'desc' },
      take: 50
    });

    const now = Date.now();
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

    const activeCount = tokens.filter(t => t.status === 'active').length;

    return NextResponse.json({
      success: true,
      activeTokensCount: activeCount,
      remainingSlots: Math.max(0, 5 - activeCount),
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

    // Pre-flight DNS (A + AAAA) SSRF check
    const resolvedHost = await resolveHostIps(cleanHost);
    if (resolvedHost.ips.some((ip) => isPrivateIp(ip))) {
      return NextResponse.json({
        error: 'SSRF_DETECTED',
        message: 'Target host resolves to a private or restricted IP address.'
      }, { status: 400 });
    }

    const prisma = getPrisma();

    // Check active tokens concurrency limit (Cap = 5)
    const unrevokedTokens = await prisma.token.findMany({
      where: {
        userId: user.id,
        isRevoked: false
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
        activeCount++;
        trulyActiveTokens.push({ id: t.id, hint: t.tokenHint });
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

    // Fetch user jwtSalt
    const userRecord = await prisma.user.findUnique({
      where: { id: user.id },
      select: { jwtSalt: true }
    });

    if (!userRecord) {
      if (quotaDeducted && userId) await refundQuota(userId);
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
    }

    // Cloudflare signing secret (support separate CHAOS_JWT_SECRET with AUTH_SECRET fallback)
    const { env } = getCloudflareContext();
    const authSecret = (env as any)?.CHAOS_JWT_SECRET || (env as any)?.AUTH_SECRET || process.env.CHAOS_JWT_SECRET || process.env.AUTH_SECRET;
    if (!authSecret) {
      if (quotaDeducted && userId) await refundQuota(userId);
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

    // Strict post-creation TOCTOU concurrency check (Cap = 5)
    const postCheckTokens = await prisma.token.findMany({
      where: {
        userId: user.id,
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
      await refundQuota(userId).catch(() => {});
    }
    console.error('Agent Mint Token Error:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}
