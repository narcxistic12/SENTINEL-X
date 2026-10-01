import { describe, it, expect } from 'vitest';
import {
  isPrivateOrBlockedIpv4,
  isPrivateOrBlockedIpv6,
  isPrivateOrBlockedIp,
  validateUrlSsrf,
} from '../lib/security/ssrf';

describe('SSRF Protection Subsystem', () => {
  describe('isPrivateOrBlockedIpv4', () => {
    it('blocks loopback addresses (127.0.0.0/8)', () => {
      expect(isPrivateOrBlockedIpv4('127.0.0.1')).toBe(true);
      expect(isPrivateOrBlockedIpv4('127.0.0.254')).toBe(true);
      expect(isPrivateOrBlockedIpv4('127.255.255.255')).toBe(true);
    });

    it('blocks current network (0.0.0.0/8)', () => {
      expect(isPrivateOrBlockedIpv4('0.0.0.0')).toBe(true);
      expect(isPrivateOrBlockedIpv4('0.1.2.3')).toBe(true);
    });

    it('blocks RFC 1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)', () => {
      expect(isPrivateOrBlockedIpv4('10.0.0.1')).toBe(true);
      expect(isPrivateOrBlockedIpv4('10.255.255.254')).toBe(true);
      expect(isPrivateOrBlockedIpv4('172.16.0.1')).toBe(true);
      expect(isPrivateOrBlockedIpv4('172.31.255.254')).toBe(true);
      expect(isPrivateOrBlockedIpv4('192.168.1.1')).toBe(true);
      expect(isPrivateOrBlockedIpv4('192.168.0.254')).toBe(true);
    });

    it('blocks link-local & AWS/GCP/Azure cloud metadata (169.254.169.254)', () => {
      expect(isPrivateOrBlockedIpv4('169.254.169.254')).toBe(true);
      expect(isPrivateOrBlockedIpv4('169.254.1.1')).toBe(true);
    });

    it('blocks carrier-grade NAT (100.64.0.0/10)', () => {
      expect(isPrivateOrBlockedIpv4('100.64.0.1')).toBe(true);
      expect(isPrivateOrBlockedIpv4('100.127.255.255')).toBe(true);
    });

    it('blocks multicast and broadcast', () => {
      expect(isPrivateOrBlockedIpv4('224.0.0.1')).toBe(true);
      expect(isPrivateOrBlockedIpv4('239.255.255.255')).toBe(true);
      expect(isPrivateOrBlockedIpv4('255.255.255.255')).toBe(true);
    });

    it('allows valid public routable IPv4 addresses', () => {
      expect(isPrivateOrBlockedIpv4('8.8.8.8')).toBe(false);
      expect(isPrivateOrBlockedIpv4('1.1.1.1')).toBe(false);
      expect(isPrivateOrBlockedIpv4('142.250.190.46')).toBe(false);
    });
  });

  describe('isPrivateOrBlockedIpv6', () => {
    it('blocks IPv6 loopback (::1)', () => {
      expect(isPrivateOrBlockedIpv6('::1')).toBe(true);
      expect(isPrivateOrBlockedIpv6('::')).toBe(true);
    });

    it('blocks link-local unicast (fe80::/10)', () => {
      expect(isPrivateOrBlockedIpv6('fe80::1')).toBe(true);
      expect(isPrivateOrBlockedIpv6('fe90::1')).toBe(true);
    });

    it('blocks unique local addresses (fc00::/7)', () => {
      expect(isPrivateOrBlockedIpv6('fc00::1')).toBe(true);
      expect(isPrivateOrBlockedIpv6('fd12:3456:789a::1')).toBe(true);
    });

    it('blocks IPv4-mapped IPv6 addresses pointing to private IPv4', () => {
      expect(isPrivateOrBlockedIpv6('::ffff:127.0.0.1')).toBe(true);
      expect(isPrivateOrBlockedIpv6('::ffff:10.0.0.1')).toBe(true);
      expect(isPrivateOrBlockedIpv6('::ffff:169.254.169.254')).toBe(true);
    });
  });

  describe('validateUrlSsrf', () => {
    it('rejects unsupported protocols (file, ftp, javascript, data)', async () => {
      const fileRes = await validateUrlSsrf('file:///etc/passwd');
      expect(fileRes.isSafe).toBe(false);

      const jsRes = await validateUrlSsrf('javascript:alert(1)');
      expect(jsRes.isSafe).toBe(false);

      const ftpRes = await validateUrlSsrf('ftp://ftp.example.com');
      expect(ftpRes.isSafe).toBe(false);
    });

    it('rejects localhost and cloud metadata hostnames directly', async () => {
      const res1 = await validateUrlSsrf('http://localhost:8080');
      expect(res1.isSafe).toBe(false);

      const res2 = await validateUrlSsrf('http://metadata.google.internal/computeMetadata/v1/');
      expect(res2.isSafe).toBe(false);

      const res3 = await validateUrlSsrf('http://instance-data');
      expect(res3.isSafe).toBe(false);
    });

    it('rejects private IP addresses provided directly as hostname', async () => {
      const res1 = await validateUrlSsrf('http://127.0.0.1/admin');
      expect(res1.isSafe).toBe(false);

      const res2 = await validateUrlSsrf('http://192.168.1.1:8080');
      expect(res2.isSafe).toBe(false);

      const res3 = await validateUrlSsrf('http://169.254.169.254/latest/meta-data');
      expect(res3.isSafe).toBe(false);
    });
  });
});
