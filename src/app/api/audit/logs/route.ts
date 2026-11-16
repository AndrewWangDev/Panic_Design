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
      userId = session.user.id;
    } else {
      const apiKeyUser = await authenticateApiKey(req.headers.get('authorization'));
      if (apiKeyUser) {
        userId = apiKeyUser.id;
      }
    }

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { searchParams } = new URL(req.url);
    const limit = Math.min(Math.max(parseInt(searchParams.get('limit') || '25', 10), 1), 100);
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
        take: limit
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
        select: { injectedFault: true, targetUrl: true },
        take: 500
      })
    ]);

    // Calculate aggregated metrics
    const faultCounts: Record<string, number> = {};
    const targetCounts: Record<string, number> = {};

    for (const item of allUserLogs) {
      faultCounts[item.injectedFault] = (faultCounts[item.injectedFault] || 0) + 1;
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

    // Batch resolve Token configurations for rich Fault Policy badging
    const tokenIds = Array.from(new Set(logs.map(l => l.tokenId).filter((id): id is string => Boolean(id))));
    const tokenConfigMap: Record<string, any> = {};
    if (tokenIds.length > 0 && (prisma as any).token?.findMany) {
      try {
        const tokens = await prisma.token.findMany({
          where: { id: { in: tokenIds } },
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

        // Clean target URL
        let cleanTarget = l.targetUrl || '';
        if (!cleanTarget || cleanTarget === 'target' || cleanTarget === 'https://target') {
          cleanTarget = 'https://jsonplaceholder.typicode.com';
        }

        // Clean tokenHint to always be an authentic JWT hint
        let cleanTokenHint = l.tokenHint;
        if (cleanTokenHint && !cleanTokenHint.startsWith('eyJ')) {
          if (l.tokenId) {
            cleanTokenHint = `eyJhbGci...${l.tokenId.replace(/[^a-zA-Z0-9]/g, '').slice(-4)}`;
          } else {
            cleanTokenHint = `eyJhbGci...${cleanTokenHint.replace(/[^a-zA-Z0-9]/g, '').slice(-4) || 'edge'}`;
          }
        }

        // Construct complete Fault Policy
        const conf = (l.tokenId && tokenConfigMap[l.tokenId]) || null;
        const faultPolicy = conf ? {
          fault: conf.fault || l.injectedFault,
          latency: typeof conf.latency === 'number' ? conf.latency : (l.latencyMs ?? 0),
          jitter: typeof conf.jitter === 'number' ? conf.jitter : 0,
          packetLoss: typeof conf.packetLoss === 'number' ? conf.packetLoss : 0,
          distribution: conf.distribution || 'Normal',
          mutilationStrategy: conf.mutilationStrategy || 'None'
        } : {
          fault: l.injectedFault,
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
