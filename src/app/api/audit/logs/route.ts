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

    return NextResponse.json({
      success: true,
      logs: logs.map(l => ({
        id: l.id,
        source: l.source,
        targetUrl: l.targetUrl,
        injectedFault: l.injectedFault,
        tokenId: l.tokenId,
        tokenHint: l.tokenHint,
        edgeColo: l.edgeColo || 'ANYCAST',
        statusCode: l.statusCode,
        latencyMs: l.latencyMs,
        rayId: l.rayId,
        executedAt: l.executedAt.toISOString()
      })),
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
