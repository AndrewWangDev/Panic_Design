import { NextResponse } from 'next/server';
import { auth } from '@/auth';
import { getPrisma } from '@/lib/prisma';
import { validateSameOrigin } from '@/lib/security';


export async function POST(req: Request) {
  try {
    if (!validateSameOrigin(req)) {
      return NextResponse.json({ error: "Forbidden: Cross-Origin Request Blocked" }, { status: 403 });
    }

    const session = await auth();
    if (!session?.user?.id) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const prisma = getPrisma();

    // Verify active, non-deleted user
    const user = await prisma.user.findFirst({
      where: { id: session.user.id, githubId: { not: null } }
    });
    if (!user) {
      return NextResponse.json({ error: 'User not found or account deleted' }, { status: 401 });
    }

    // Atomically increment user's jwtSalt and mark all active tokens as revoked in D1 batch transaction
    await prisma.$transaction([
      prisma.user.update({
        where: { id: session.user.id },
        data: { jwtSalt: { increment: 1 } }
      }),
      prisma.token.updateMany({
        where: {
          userId: session.user.id,
          isRevoked: false
        },
        data: {
          isRevoked: true
        }
      })
    ]);

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
