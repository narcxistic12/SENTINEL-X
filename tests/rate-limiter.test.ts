import { describe, it, expect } from 'vitest';
import { globalRateLimiter } from '../lib/security/rate-limiter';

describe('Sliding Window Rate Limiter', () => {
  it('permits requests within allowance limit', async () => {
    const testIp = 'test-client-1-' + Date.now();
    const res1 = await globalRateLimiter.check(testIp);
    expect(res1.allowed).toBe(true);
    expect(res1.remaining).toBeGreaterThan(0);
  });

  it('correctly tracks and decrements remaining quota', async () => {
    const testIp = 'test-client-2-' + Date.now();
    const res1 = await globalRateLimiter.check(testIp);
    const res2 = await globalRateLimiter.check(testIp);
    expect(res2.remaining).toBe(res1.remaining - 1);
  });

  it('blocks client when request threshold is exhausted', async () => {
    const testIp = 'test-abuser-' + Date.now();
    let lastRes;
    for (let i = 0; i < 26; i++) {
      lastRes = await globalRateLimiter.check(testIp);
    }
    expect(lastRes?.allowed).toBe(false);
    expect(lastRes?.retryAfterSeconds).toBeGreaterThan(0);
  });
});
