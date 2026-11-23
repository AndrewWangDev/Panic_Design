import { NextResponse } from 'next/server';
import { auth } from '@/auth';
import { getPrisma } from '@/lib/prisma';
import { generateRawApiKey, hashApiKey, extractApiKeyPrefix } from '@/lib/apiKey';
import { validateSameOrigin } from '@/lib/security';

export async function GET() {
  try {
    const session = await auth();
    if (!session?.user?.id) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const prisma = getPrisma();
    const user = await prisma.user.findFirst({
      where: { id: session.user.id, githubId: { not: null } },
      select: { apiKeyPrefix: true, apiKeyCreatedAt: true }
    });
    if (!user) {
      return NextResponse.json({ error: 'Unauthorized: Account deleted' }, { status: 401 });
    }

    return NextResponse.json({
      hasKey: !!user.apiKeyPrefix,
      prefix: user.apiKeyPrefix || null,
      createdAt: user.apiKeyCreatedAt ? user.apiKeyCreatedAt.toISOString() : null
    });
  } catch (error) {
    console.error('Fetch API Key Error:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}

export async function POST(req: Request) {
  try {
    if (!validateSameOrigin(req)) {
      return NextResponse.json({ error: "Forbidden: Cross-Origin Request Blocked" }, { status: 403 });
    }

    const session = await auth();
    if (!session?.user?.id) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const rawKey = generateRawApiKey();
    const hash = await hashApiKey(rawKey);
    const prefix = extractApiKeyPrefix(rawKey);
    const now = new Date();

    const prisma = getPrisma();
    const user = await prisma.user.findFirst({
      where: { id: session.user.id, githubId: { not: null } }
    });
    if (!user) {
      return NextResponse.json({ error: 'User not found or account deleted' }, { status: 401 });
    }

    await prisma.user.update({
      where: { id: session.user.id },
      data: {
        apiKeyHash: hash,
        apiKeyPrefix: prefix,
        apiKeyCreatedAt: now
      }
    });

    // Return full API key ONCE! Client must warn user to copy it now.
    return NextResponse.json({
      success: true,
      apiKey: rawKey,
      prefix: prefix,
      createdAt: now.toISOString(),
      message: 'API Key generated. Copy it now; you will not be able to see it again.'
    });
  } catch (error) {
    console.error('Generate API Key Error:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}

export async function DELETE(req: Request) {
  try {
    if (!validateSameOrigin(req)) {
      return NextResponse.json({ error: "Forbidden: Cross-Origin Request Blocked" }, { status: 403 });
    }

    const session = await auth();
    if (!session?.user?.id) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const prisma = getPrisma();
    const user = await prisma.user.findFirst({
      where: { id: session.user.id, githubId: { not: null } }
    });
    if (!user) {
      return NextResponse.json({ error: 'Unauthorized: Account deleted' }, { status: 401 });
    }

    await prisma.user.update({
      where: { id: session.user.id },
      data: {
        apiKeyHash: null,
        apiKeyPrefix: null,
        apiKeyCreatedAt: null
      }
    });

    return NextResponse.json({
      success: true,
      message: 'API Key revoked successfully.'
    });
  } catch (error) {
    console.error('Revoke API Key Error:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}
