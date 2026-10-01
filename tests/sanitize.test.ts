import { describe, it, expect } from 'vitest';
import { sanitizeAndNormalizeUrl } from '../lib/security/sanitize';

describe('URL Normalization & Sanitization', () => {
  it('prepends https:// when protocol is omitted', () => {
    const result = sanitizeAndNormalizeUrl('example.com/login');
    expect(result.isValid).toBe(true);
    expect(result.normalizedUrl).toBe('https://example.com/login');
  });

  it('preserves explicit http:// and https://', () => {
    const resHttp = sanitizeAndNormalizeUrl('http://example.com');
    expect(resHttp.isValid).toBe(true);
    expect(resHttp.normalizedUrl).toBe('http://example.com/');

    const resHttps = sanitizeAndNormalizeUrl('https://example.com');
    expect(resHttps.isValid).toBe(true);
    expect(resHttps.normalizedUrl).toBe('https://example.com/');
  });

  it('strips embedded credentials (user:pass@)', () => {
    const res = sanitizeAndNormalizeUrl('https://admin:supersecret@phishingsite.com/portal');
    expect(res.isValid).toBe(true);
    expect(res.normalizedUrl).toBe('https://phishingsite.com/portal');
    expect(res.normalizedUrl.includes('supersecret')).toBe(false);
  });

  it('rejects empty or whitespace inputs', () => {
    expect(sanitizeAndNormalizeUrl('').isValid).toBe(false);
    expect(sanitizeAndNormalizeUrl('    ').isValid).toBe(false);
  });

  it('rejects URLs exceeding max length (2048)', () => {
    const hugeUrl = 'https://example.com/' + 'a'.repeat(2500);
    const result = sanitizeAndNormalizeUrl(hugeUrl);
    expect(result.isValid).toBe(false);
    expect(result.error).toContain('maximum allowable length');
  });
});
