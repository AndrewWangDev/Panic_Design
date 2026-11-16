import { NextResponse } from 'next/server';
import { auth } from '@/auth';
import { getPrisma } from '@/lib/prisma';


export async function POST(req: Request) {
  try {
    const session = await auth();
    if (!session?.user?.id) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await req.json() as any;
    const { id } = body;

    if (!id) {
      return NextResponse.json({ error: 'Token ID is required' }, { status: 400 });
    }

    const prisma = getPrisma();

    // Verify token ownership
    const token = await prisma.token.findUnique({
      where: { id }
    });

    if (!token || token.userId !== session.user.id) {
      return NextResponse.json({ error: 'Not found or unauthorized' }, { status: 404 });
    }

    // Update token
    await prisma.token.update({
      where: { id },
      data: { isRevoked: true }
    });

    // Record Audit Log (Token Revocation via Web Dashboard)
    const rayHeader = req.headers.get('cf-ray') || '';
    const rayColo = rayHeader.includes('-') ? rayHeader.split('-')[1]?.toUpperCase() : null;
    const colo = rayColo || req.headers.get('cf-ipcountry') || 'EDGE';

    await prisma.chaosLog.create({
      data: {
        userId: session.user.id,
        targetUrl: token.targetHost,
        injectedFault: 'TOKEN_REVOKED',
        source: 'WEB_DASHBOARD',
        tokenId: token.id,
        tokenHint: token.tokenHint,
        edgeColo: colo,
        statusCode: 200,
        rayId: rayHeader || undefined
      }
    }).catch(err => console.error('Failed to log web revocation audit:', err));

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Revoke Token Error:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}
