import { getPrisma } from '@/lib/prisma';

/**
 * Validates and atomically increments user API invocation quotas.
 *
 * Architecture & Concurrency Notes:
 * Cloudflare D1 operates on an underlying single-writer SQLite architecture. To prevent
 * row-lock serialization bottlenecks and database deadlocks during high-concurrency bursts,
 * this function utilizes Optimistic Concurrency Control (OCC) via conditional `updateMany`
 * writes rather than heavy pessimistic transactions.
 *
 * If a concurrent write conflict occurs across edge worker isolates, the operation employs
 * jittered exponential backoff (20-50ms) and retries up to 3 times before failing closed.
 *
 * @param userId Unique identifier of the user account.
 * @returns Object indicating whether invocation is permitted and optional failure reason.
 */
export async function checkAndUpdateQuota(userId: string): Promise<{ allowed: boolean, reason?: string }> {
  const prisma = getPrisma();
  const MAX_RETRIES = 3;

  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) return { allowed: false, reason: 'User not found' };
    if (user.githubId === null) return { allowed: false, reason: 'Account deleted' };

    const now = new Date();
    const lastReset = user.lastQuotaReset || new Date(0);

    const isNewDay = now.getUTCFullYear() !== lastReset.getUTCFullYear() || 
                     now.getUTCMonth() !== lastReset.getUTCMonth() || 
                     now.getUTCDate() !== lastReset.getUTCDate();
                     
    const isNewHour = isNewDay || now.getUTCHours() !== lastReset.getUTCHours();

    // Case 1: Within the same time window
    if (!isNewDay && !isNewHour) {
      if (user.dailyQuota >= 100) {
        return { allowed: false, reason: 'Daily quota of 100 requests exceeded' };
      }
      if (user.hourlyQuota >= 30) {
        return { allowed: false, reason: 'Hourly quota of 30 requests exceeded' };
      }

      const updated = await prisma.user.updateMany({
        where: {
          id: userId,
          dailyQuota: { lt: 100 },
          hourlyQuota: { lt: 30 }
        },
        data: {
          dailyQuota: { increment: 1 },
          hourlyQuota: { increment: 1 }
        }
      });

      if (updated.count > 0) {
        return { allowed: true };
      }

      // Check if it failed because quota was reached concurrently
      const freshUser = await prisma.user.findUnique({ where: { id: userId } });
      if (freshUser && (freshUser.dailyQuota >= 100 || freshUser.hourlyQuota >= 30)) {
        return { allowed: false, reason: 'Quota exceeded (Max 30 requests/hour, 100 requests/day)' };
      }

      // Timestamp collision with another worker; backoff before retrying
      if (attempt < MAX_RETRIES - 1) {
        await new Promise(r => setTimeout(r, 20 + Math.random() * 30));
      }
      continue;
    }

    // Case 2: Crossing hour or day window
    const newDaily = isNewDay ? 1 : user.dailyQuota + 1;
    const newHourly = isNewHour ? 1 : user.hourlyQuota + 1;

    if (newDaily > 100) {
      return { allowed: false, reason: 'Daily quota of 100 requests exceeded' };
    }
    if (newHourly > 30) {
      return { allowed: false, reason: 'Hourly quota of 30 requests exceeded' };
    }

    const updated = await prisma.user.updateMany({
      where: {
        id: userId,
        lastQuotaReset: user.lastQuotaReset
      },
      data: {
        dailyQuota: newDaily,
        hourlyQuota: newHourly,
        lastQuotaReset: now
      }
    });

    if (updated.count > 0) {
      return { allowed: true };
    }

    // Concurrent reset conflict at boundary; backoff before retrying
    if (attempt < MAX_RETRIES - 1) {
      await new Promise(r => setTimeout(r, 20 + Math.random() * 30));
    }
  }

  return { allowed: false, reason: 'Concurrent request conflict, please retry' };
}

/**
 * Atomically refunds 1 request to user daily/hourly quota in case downstream
 * Token creation fails or is aborted. Uses an atomic Prisma transaction with
 * conditional decrements to prevent lost updates during concurrent requests.
 *
 * If `deductedAt` is supplied, checks whether the current time window matches
 * the deduction time window. If the hour or day window has rolled over, the
 * respective decrement is safely skipped to avoid cross-window quota pollution (BUG-01, BUG-02).
 */
export async function refundQuota(userId: string, deductedAt?: Date): Promise<void> {
  const prisma = getPrisma();
  try {
    const now = new Date();
    const sameDay = !deductedAt || (
      now.getUTCFullYear() === deductedAt.getUTCFullYear() &&
      now.getUTCMonth() === deductedAt.getUTCMonth() &&
      now.getUTCDate() === deductedAt.getUTCDate()
    );
    const sameHour = !deductedAt || (
      sameDay && now.getUTCHours() === deductedAt.getUTCHours()
    );

    const operations = [];

    if (sameDay) {
      operations.push(
        prisma.user.updateMany({
          where: {
            id: userId,
            dailyQuota: { gt: 0 }
          },
          data: {
            dailyQuota: { decrement: 1 }
          }
        })
      );
    }

    if (sameHour) {
      operations.push(
        prisma.user.updateMany({
          where: {
            id: userId,
            hourlyQuota: { gt: 0 }
          },
          data: {
            hourlyQuota: { decrement: 1 }
          }
        })
      );
    }

    if (operations.length > 0) {
      await prisma.$transaction(operations);
    }
  } catch (err) {
    console.error('Failed to refund quota for user:', userId, err);
  }
}
