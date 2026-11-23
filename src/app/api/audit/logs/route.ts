import { NextResponse } from 'next/server';
import { auth } from '@/auth';
import { authenticateApiKey } from '@/lib/apiKey';
import { getPrisma } from '@/lib/prisma';

export async function GET(req: Request) {
  try {
    let userId: string | null = null;

    // Dual-Auth: Check Web session first, then API Key
    const session = await auth();
    if (session?.user?.id) {
      const prisma = getPrisma();
      const activeUser = await prisma.user.findFirst({
        where: { id: session.user.id, githubId: { not: null } }
      });
      if (activeUser) {
        userId = activeUser.id;
      }
    } else {
      const apiKeyUser = await authenticateApiKey(req.headers.get('authorization'));
      if (apiKeyUser) {
        userId = apiKeyUser.id;
      }
    }

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Rate limit: max 30 requests per minute per user to protect D1 read capacity (PD-ISSUE-06)
    const { checkRateLimit } = await import('@/lib/rateLimit');
    const rateCheck = checkRateLimit(`audit-logs:${userId}`, 30, 60000);
    if (!rateCheck.allowed) {
      return NextResponse.json({
        error: 'RATE_LIMIT_EXCEEDED',
        message: 'Too many audit log requests. Please limit polling interval.'
      }, {
        status: 429,
        headers: { 'Retry-After': '2' }
      });
    }

    const { searchParams } = new URL(req.url);
    const page = Math.max(parseInt(searchParams.get('page') || '1', 10), 1);
    const limit = Math.min(Math.max(parseInt(searchParams.get('limit') || '25', 10), 1), 100);
    const skip = (page - 1) * limit;
    const sourceFilter = searchParams.get('source');
    const faultFilter = searchParams.get('fault');
    const targetFilter = searchParams.get('target');

    const prisma = getPrisma();

    // Build filter clause
    const where: any = { userId };
    if (sourceFilter) {
      where.source = sourceFilter;
    }
    if (faultFilter) {
      where.injectedFault = faultFilter;
    }
    if (targetFilter) {
      where.targetUrl = { contains: targetFilter };
    }

    const todayStart = new Date();
    todayStart.setUTCHours(0, 0, 0, 0);

    const [logs, totalCount, todayCount, allUserLogs] = await Promise.all([
      prisma.chaosLog.findMany({
        where,
        orderBy: { executedAt: 'desc' },
        take: limit,
        skip
      }),
      prisma.chaosLog.count({ where: { userId } }),
      prisma.chaosLog.count({
        where: {
          userId,
          executedAt: { gte: todayStart }
        }
      }),
      prisma.chaosLog.findMany({
        where: { userId },
        select: { injectedFault: true, targetUrl: true, tokenId: true, latencyMs: true },
        orderBy: { executedAt: 'desc' },
        take: 500
      })
    ]);

    // Batch resolve Token configurations for allUserLogs and visible logs to avoid N+1 D1 queries
    // while ensuring aggregated summary KPI metrics do not drift when paging (NEW-02 fix)
    const allTokenIdCandidates = [
      ...allUserLogs.map(l => l.tokenId),
      ...logs.map(l => l.tokenId)
    ].filter((id): id is string => Boolean(id));
    const tokenIds = Array.from(new Set(allTokenIdCandidates));
    const tokenConfigMap: Record<string, any> = {};
    if (tokenIds.length > 0 && (prisma as any).token?.findMany) {
      try {
        // Query by id in batch when under 100, or directly by userId index when exceeding 100 to eliminate any truncation
        const tokens = await prisma.token.findMany({
          where: tokenIds.length <= 100
            ? { id: { in: tokenIds } }
            : { userId },
          select: { id: true, config: true }
        });
        for (const t of tokens) {
          try {
            tokenConfigMap[t.id] = JSON.parse(t.config);
          } catch {}
        }
      } catch (tokenErr) {
        console.warn('Failed to batch query token configs for logs:', tokenErr);
      }
    }

    // Calculate aggregated metrics
    const faultCounts: Record<string, number> = {};
    const targetCounts: Record<string, number> = {};

    const addFaultFacet = (facet: string) => {
      faultCounts[facet] = (faultCounts[facet] || 0) + 1;
    };

    for (const item of allUserLogs) {
      const conf = (item.tokenId && tokenConfigMap[item.tokenId]) || null;
      const isMeta = ['PASSTHROUGH', 'FAIL_OPEN', 'TOKEN_MINTED', 'TOKEN_REVOKED'].includes(item.injectedFault);
      const primaryFault = isMeta ? item.injectedFault : (conf?.fault || item.injectedFault);

      // 1. Primary fault pattern
      if (primaryFault === 'latency' || (item.latencyMs && item.latencyMs > 0 && !isMeta)) {
        addFaultFacet('latency');
      } else if (primaryFault) {
        addFaultFacet(primaryFault);
      }

      // 2. Active multi-faceted chaos parameters from token config (if available)
      if (conf) {
        if (typeof conf.jitter === 'number' && conf.jitter > 0) {
          addFaultFacet('jitter');
        }
        if (typeof conf.packetLoss === 'number' && conf.packetLoss > 0) {
          addFaultFacet('drop');
        }
        if (conf.mutilationStrategy && conf.mutilationStrategy !== 'None') {
          addFaultFacet(conf.mutilationStrategy);
        }
        if (conf.distribution && conf.distribution !== 'Uniform') {
          addFaultFacet(conf.distribution);
        }
      }

      let host = item.targetUrl || 'unknown';
      try {
        if (host.startsWith('http://') || host.startsWith('https://')) {
          host = new URL(host).hostname;
        }
      } catch {}
      targetCounts[host] = (targetCounts[host] || 0) + 1;
    }

    const sortedTargets = Object.entries(targetCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([target, count]) => ({ target, count }));

    return NextResponse.json({
      success: true,
      logs: logs.map(l => {
        // Derive robust edgeColo from record or rayId
        let derivedColo = l.edgeColo;
        if (!derivedColo || derivedColo === 'UNKNOWN' || derivedColo === 'ANYCAST' || derivedColo === 'GLOBAL-EDGE') {
          if (l.rayId && l.rayId.includes('-')) {
            derivedColo = l.rayId.split('-')[1]?.toUpperCase();
          }
        }
        if (!derivedColo || derivedColo === 'UNKNOWN' || derivedColo === 'ANYCAST') {
          derivedColo = 'EDGE';
        }

        // Return raw authentic target URL and tokenHint (QUAL-01: no hardcoded data masking)
        const cleanTarget = l.targetUrl || '';
        const cleanTokenHint = l.tokenHint || '';

        // Construct complete Fault Policy with relation config fallback
        let conf = (l.tokenId && tokenConfigMap[l.tokenId]) || null;
        if (!conf && (l as any).token?.config) {
          try {
            conf = JSON.parse((l as any).token.config);
          } catch {}
        }
        const isMetaFault = ['PASSTHROUGH', 'FAIL_OPEN', 'TOKEN_MINTED', 'TOKEN_REVOKED'].includes(l.injectedFault);
        const effectiveFault = isMetaFault 
          ? l.injectedFault 
          : (conf?.fault || l.injectedFault);

        const faultPolicy = conf ? {
          fault: effectiveFault,
          latency: typeof conf.latency === 'number' ? conf.latency : (l.latencyMs ?? 0),
          jitter: typeof conf.jitter === 'number' ? conf.jitter : 0,
          packetLoss: typeof conf.packetLoss === 'number' ? conf.packetLoss : 0,
          distribution: conf.distribution || 'Normal',
          mutilationStrategy: conf.mutilationStrategy || 'None'
        } : {
          fault: effectiveFault,
          latency: l.latencyMs ?? 0,
          jitter: 0,
          packetLoss: 0,
          distribution: 'Normal',
          mutilationStrategy: 'None'
        };

        return {
          id: l.id,
          source: l.source,
          targetUrl: cleanTarget,
          injectedFault: l.injectedFault,
          faultPolicy,
          tokenId: l.tokenId,
          tokenHint: cleanTokenHint,
          edgeColo: derivedColo,
          statusCode: l.statusCode,
          latencyMs: l.latencyMs,
          rayId: l.rayId,
          executedAt: l.executedAt.toISOString()
        };
      }),
      pagination: {
        page,
        limit,
        total: totalCount,
        totalPages: Math.ceil(totalCount / limit)
      },
      summary: {
        totalInjections: totalCount,
        todayInjections: todayCount,
        topTargets: sortedTargets,
        faultCounts
      }
    });
  } catch (error) {
    console.error('Fetch Audit Logs Error:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}
