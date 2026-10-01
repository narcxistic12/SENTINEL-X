import { describe, it, expect } from 'vitest';
import { extractUrlFeatures, calculateShannonEntropy } from '../lib/detection/url-features';

describe('URL Feature Extraction', () => {
  it('calculates Shannon entropy accurately', () => {
    expect(calculateShannonEntropy('')).toBe(0);
    expect(calculateShannonEntropy('aaaa')).toBe(0);
    // Random string should have higher entropy than repetitive string
    const repetitive = calculateShannonEntropy('abcabcabc');
    const random = calculateShannonEntropy('a8f9z1x3k7p2');
    expect(random).toBeGreaterThan(repetitive);
  });

  it('detects authentication and payment keywords', () => {
    const raw = 'https://portal.com/login/verify/creditcard';
    const features = extractUrlFeatures(raw, raw);

    expect(features.matchedKeywords.length).toBeGreaterThan(0);
    const words = features.matchedKeywords.map((k) => k.keyword);
    expect(words).toContain('login');
    expect(words).toContain('verify');
    expect(words).toContain('creditcard');
  });

  it('detects known URL shorteners', () => {
    const raw = 'https://bit.ly/3xY7zQ';
    const features = extractUrlFeatures(raw, raw);
    expect(features.isKnownShortener).toBe(true);
    expect(features.shortenerName).toBe('Bitly');
  });

  it('detects risky TLDs', () => {
    const raw = 'https://secure-account-login.tk/';
    const features = extractUrlFeatures(raw, raw);
    expect(features.isRiskyTld).toBe(true);
  });

  it('detects homoglyphs / punycode lookalikes', () => {
    // Cyrillic 'a' (\u0430) instead of Latin 'a'
    const raw = 'https://\u0430pple.com/';
    const features = extractUrlFeatures(raw, raw);
    expect(features.hasHomoglyphs).toBe(true);
    expect(features.homoglyphsFound.length).toBeGreaterThan(0);
  });

  it('detects IP address as host', () => {
    const raw = 'http://198.51.100.25/login';
    const features = extractUrlFeatures(raw, raw);
    expect(features.hasIpHost).toBe(true);
  });
});
