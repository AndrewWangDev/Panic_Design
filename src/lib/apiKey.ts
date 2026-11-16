import { getPrisma } from '@/lib/prisma';

const CHARS = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

export function generateRawApiKey(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let str = '';
  for (let i = 0; i < bytes.length; i++) {
    str += CHARS[bytes[i] % CHARS.length];
  }
  return `pd_live_${str}`;
}

export async function hashApiKey(rawKey: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(rawKey.trim());
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

export function extractApiKeyPrefix(rawKey: string): string {
  const trimmed = rawKey.trim();
  if (trimmed.startsWith('pd_live_') && trimmed.length > 16) {
    return `${trimmed.slice(0, 14)}...`;
  }
  return trimmed.slice(0, 8) + '...';
}

export async function authenticateApiKey(authHeaderOrKey: string | null): Promise<{ id: string; username: string | null; email: string | null } | null> {
  if (!authHeaderOrKey) return null;

  let rawKey = authHeaderOrKey.trim();
  if (rawKey.startsWith('Bearer ')) {
    rawKey = rawKey.slice(7).trim();
  }

  if (!rawKey.startsWith('pd_live_') || rawKey.length < 24) {
    return null;
  }

  const hash = await hashApiKey(rawKey);
  const prisma = getPrisma();

  const user = await prisma.user.findFirst({
    where: {
      apiKeyHash: hash,
      githubId: { not: null }
    },
    select: { id: true, username: true, email: true }
  });

  return user;
}
