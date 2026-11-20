import { getPrisma } from '@/lib/prisma';

const CHARS = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

export function generateRawApiKey(): string {
  // 62 * 4 = 248. Discard random bytes >= 248 to eliminate modulo bias across 0..61.
  const charsLen = CHARS.length;
  const maxValidByte = 256 - (256 % charsLen); // 248
  let str = '';
  while (str.length < 32) {
    const bytes = new Uint8Array(48);
    crypto.getRandomValues(bytes);
    for (let i = 0; i < bytes.length && str.length < 32; i++) {
      if (bytes[i] < maxValidByte) {
        str += CHARS[bytes[i] % charsLen];
      }
    }
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

  const rawKey = authHeaderOrKey.trim().replace(/^Bearer\s+/i, '').trim();

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
