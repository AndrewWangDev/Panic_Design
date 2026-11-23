/**
 * In-memory sliding window rate limiter for edge Worker isolates.
 *
 * Architecture Notes:
 * Cloudflare Workers isolates are ephemeral and localized to individual edge PoPs.
 * This in-memory store acts as the first-line burst defense (e.g. 15 req/min) to absorb
 * sudden request spikes without putting read pressure on D1. Global, durable limits
 * are enforced downstream by the database quota tier.
 *
 * A bounded ceiling (MAX_STORE_SIZE = 5000) with FIFO oldest-key eviction prevents
 * unbounded memory exhaustion under distributed spoofed identifier attacks.
 */
interface RateLimitRecord {
  timestamps: number[];
}

const memoryStore = new Map<string, RateLimitRecord>();

// Maximum number of distinct tracking identifiers per isolate to prevent unbounded memory growth
const MAX_STORE_SIZE = 5000;

// Clean up stale entries every 5 minutes
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000;
let lastCleanup = Date.now();

function purgeStale(now: number) {
  if (now - lastCleanup < CLEANUP_INTERVAL_MS) return;
  lastCleanup = now;
  for (const [key, record] of memoryStore.entries()) {
    // Purge records older than CLEANUP_INTERVAL_MS (5 min) to support arbitrary windows up to 5 minutes
    record.timestamps = record.timestamps.filter(ts => now - ts < CLEANUP_INTERVAL_MS);
    if (record.timestamps.length === 0) {
      memoryStore.delete(key);
    }
  }
}

export function _getRateLimitStoreSize(): number {
  return memoryStore.size;
}

export function _clearRateLimitStore(): void {
  memoryStore.clear();
}

/**
 * Check and record an in-memory sliding window rate limit attempt for the current Isolate.
 * Acts as the first-line burst defense (e.g. 15 req/min) before downstream D1 database quota checks.
 * @param identifier e.g. "user:cly123" or "ip:1.2.3.4"
 * @param maxRequests e.g. 15 requests
 * @param windowMs e.g. 60000 ms (1 minute)
 */
export function checkRateLimit(identifier: string, maxRequests: number = 15, windowMs: number = 60000): { allowed: boolean; remaining: number; resetMs: number } {
  const now = Date.now();
  purgeStale(now);

  let record = memoryStore.get(identifier);
  if (!record) {
    if (memoryStore.size >= MAX_STORE_SIZE) {
      const oldestKey = memoryStore.keys().next().value;
      if (oldestKey) memoryStore.delete(oldestKey);
    }
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
