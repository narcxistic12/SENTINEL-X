import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetTimeMs: number;
  retryAfterSeconds: number;
}

interface ClientRecord {
  timestamps: number[];
  firstRequest: number;
}

// In-memory sliding window rate limiter
class SlidingWindowRateLimiter {
  private records = new Map<string, ClientRecord>();
  private readonly windowMs: number;
  private readonly maxRequests: number;
  private lastCleanup: number = Date.now();

  constructor(windowMs = 60000, maxRequests = 30) {
    this.windowMs = windowMs;
    this.maxRequests = maxRequests;
  }

  public check(identifier: string): RateLimitResult {
    const now = Date.now();
    this.cleanup(now);

    const client = this.records.get(identifier) || {
      timestamps: [],
      firstRequest: now,
    };

    client.timestamps = client.timestamps.filter((ts) => now - ts < this.windowMs);

    if (client.timestamps.length >= this.maxRequests) {
      const oldest = client.timestamps[0];
      const resetTimeMs = oldest + this.windowMs;
      const retryAfterSeconds = Math.max(1, Math.ceil((resetTimeMs - now) / 1000));
      return { allowed: false, limit: this.maxRequests, remaining: 0, resetTimeMs, retryAfterSeconds };
    }

    client.timestamps.push(now);
    this.records.set(identifier, client);
    return { allowed: true, limit: this.maxRequests, remaining: this.maxRequests - client.timestamps.length, resetTimeMs: now + this.windowMs, retryAfterSeconds: 0 };
  }

  private cleanup(now: number) {
    if (now - this.lastCleanup < 60000) return;
    this.lastCleanup = now;
    for (const [key, record] of this.records.entries()) {
      record.timestamps = record.timestamps.filter((ts) => now - ts < this.windowMs);
      if (record.timestamps.length === 0) this.records.delete(key);
    }
  }
}

class HybridRateLimiter {
  private localFallback: SlidingWindowRateLimiter;
  private upstashLimiter: Ratelimit | null = null;
  private maxRequests: number;
  
  constructor() {
    this.maxRequests = Number(process.env.RATE_LIMIT_MAX_REQUESTS) || 25;
    this.localFallback = new SlidingWindowRateLimiter(
      Number(process.env.RATE_LIMIT_WINDOW_MS) || 60000,
      this.maxRequests
    );
    
    if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
      this.upstashLimiter = new Ratelimit({
        redis: Redis.fromEnv(),
        limiter: Ratelimit.slidingWindow(this.maxRequests, '1 m'),
        analytics: true,
      });
    } else {
      console.warn('⚠️ Upstash Redis not configured. Using local fallback rate limiter (Not recommended for production serverless apps).');
    }
  }

  public async check(identifier: string): Promise<RateLimitResult> {
    if (this.upstashLimiter) {
      try {
        const result = await this.upstashLimiter.limit(identifier);
        return {
          allowed: result.success,
          limit: result.limit,
          remaining: result.remaining,
          resetTimeMs: result.reset,
          retryAfterSeconds: Math.max(1, Math.ceil((result.reset - Date.now()) / 1000)),
        };
      } catch (err) {
        console.error('Upstash Rate Limiter failed, falling back to local memory', err);
      }
    }
    return this.localFallback.check(identifier);
  }
}

export const globalRateLimiter = new HybridRateLimiter();
