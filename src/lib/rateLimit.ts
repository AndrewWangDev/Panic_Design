// Sliding window in-memory rate limiter per user/IP
interface RateLimitRecord {
  timestamps: number[];
}

const memoryStore = new Map<string, RateLimitRecord>();

// Clean up stale entries every 5 minutes
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000;
let lastCleanup = Date.now();

function purgeStale(now: number) {
  if (now - lastCleanup < CLEANUP_INTERVAL_MS) return;
  lastCleanup = now;
  for (const [key, record] of memoryStore.entries()) {
    record.timestamps = record.timestamps.filter(ts => now - ts < 60000);
    if (record.timestamps.length === 0) {
      memoryStore.delete(key);
    }
  }
}

/**
 * Check and record a rate limit attempt.
 * @param identifier e.g. "user:cly123" or "ip:1.2.3.4"
 * @param maxRequests e.g. 15 requests
 * @param windowMs e.g. 60000 ms (1 minute)
 */
export function checkRateLimit(identifier: string, maxRequests: number = 15, windowMs: number = 60000): { allowed: boolean; remaining: number; resetMs: number } {
  const now = Date.now();
  purgeStale(now);

  let record = memoryStore.get(identifier);
  if (!record) {
    record = { timestamps: [] };
    memoryStore.set(identifier, record);
  }

  // Filter timestamps within the rolling window
  record.timestamps = record.timestamps.filter(ts => now - ts < windowMs);

  if (record.timestamps.length >= maxRequests) {
    const oldest = record.timestamps[0];
    const resetMs = Math.max(0, windowMs - (now - oldest));
    return {
      allowed: false,
      remaining: 0,
      resetMs
    };
  }

  record.timestamps.push(now);
  return {
    allowed: true,
    remaining: maxRequests - record.timestamps.length,
    resetMs: windowMs
  };
}
