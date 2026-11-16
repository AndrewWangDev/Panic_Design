import { NextResponse } from 'next/server';
import { auth } from '@/auth';
import { getPrisma } from '@/lib/prisma';


export async function POST(req: Request) {
  try {
    const session = await auth();
    if (!session?.user?.id) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const prisma = getPrisma();

    // 1. Increment user's jwtSalt to instantly invalidate all tokens globally
    await prisma.user.update({
      where: { id: session.user.id },
      data: { jwtSalt: { increment: 1 } }
    });

    // 2. Mark all active tokens as revoked in DB for UI consistency
    await prisma.token.updateMany({
      where: {
        userId: session.user.id,
        isRevoked: false
      },
      data: {
        isRevoked: true
      }
    });

    // Record Global Revocation Audit Log
    const rayHeader = req.headers.get('cf-ray') || '';
    const rayColo = rayHeader.includes('-') ? rayHeader.split('-')[1]?.toUpperCase() : null;
    const colo = rayColo || req.headers.get('cf-ipcountry') || 'EDGE';

    await prisma.chaosLog.create({
      data: {
        userId: session.user.id,
        targetUrl: 'ALL_ACTIVE_TOKENS',
        injectedFault: 'TOKEN_REVOKED',
        source: 'WEB_DASHBOARD',
        edgeColo: colo,
        statusCode: 200,
        rayId: rayHeader || undefined
      }
    }).catch(err => console.error('Failed to log global revocation audit:', err));

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Revoke All Tokens Error:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}
