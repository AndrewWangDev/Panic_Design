import { NextResponse } from 'next/server';
import { authenticateApiKey } from '@/lib/apiKey';
import { getPrisma } from '@/lib/prisma';

export async function DELETE(
  req: Request,
  props: { params: Promise<{ id: string }> }
) {
  try {
    const user = await authenticateApiKey(req.headers.get('authorization'));
    if (!user) {
      return NextResponse.json({
        error: 'UNAUTHORIZED',
        message: 'Valid API key required in Authorization: Bearer pd_live_...'
      }, { status: 401 });
    }

    const { id } = await props.params;
    if (!id || typeof id !== 'string') {
      return NextResponse.json({ error: 'INVALID_ID', message: 'Token ID is required.' }, { status: 400 });
    }

    const prisma = getPrisma();
    const token = await prisma.token.findFirst({
      where: {
        id,
        userId: user.id
      }
    });

    if (!token) {
      return NextResponse.json({ error: 'NOT_FOUND', message: 'Token not found or does not belong to this account.' }, { status: 404 });
    }

    if (!token.isRevoked) {
      await prisma.token.update({
        where: { id: token.id },
        data: { isRevoked: true }
      });

      // Record Audit Log (Token Revocation via Agent)
      const rayHeader = req.headers.get('cf-ray') || '';
      const rayColo = rayHeader.includes('-') ? rayHeader.split('-')[1]?.toUpperCase() : null;
      const colo = rayColo || req.headers.get('cf-ipcountry') || 'EDGE';

      await prisma.chaosLog.create({
        data: {
          userId: user.id,
          targetUrl: token.targetHost,
          injectedFault: 'TOKEN_REVOKED',
          source: 'AGENT_API',
          tokenId: token.id,
          tokenHint: token.tokenHint,
          edgeColo: colo,
          statusCode: 200,
          rayId: rayHeader || undefined
        }
      }).catch(err => console.error('Failed to log token revocation audit:', err));
    }

    return NextResponse.json({
      success: true,
      message: 'Token revoked successfully.',
      tokenId: token.id
    });
  } catch (error) {
    console.error('Agent Revoke Token Error:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}
