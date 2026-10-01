import * as tls from 'node:tls';
import { SslIntelligence } from '@/types/security';

const SSL_DISCLAIMER =
  'HTTPS encrypts data in transit to prevent network eavesdropping, but does NOT prove the website is trustworthy. Over 80% of active phishing sites utilize valid SSL/TLS certificates.';

/**
 * Connects directly to the host via TLS to inspect the real X.509 certificate.
 * Operates with rejectUnauthorized: false to safely inspect invalid/self-signed certs.
 */
export async function analyzeSsl(hostname: string, port = 443, isHttps = true): Promise<SslIntelligence> {
  if (!isHttps) {
    return {
      httpsEnabled: false,
      certificateValid: false,
      hostnameMatches: false,
      issuer: null,
      subject: null,
      validFrom: null,
      validTo: null,
      daysUntilExpiration: null,
      protocol: null,
      cipher: null,
      isSelfSigned: false,
      isExpired: false,
      error: 'Website uses unencrypted HTTP. Data sent to this site is vulnerable to interception.',
      disclaimer: SSL_DISCLAIMER,
    };
  }

  return new Promise<SslIntelligence>((resolve) => {
    let resolved = false;

    const timeout = setTimeout(() => {
      if (!resolved) {
        resolved = true;
        try {
          socket.destroy();
        } catch {
          // ignore
        }
        resolve({
          httpsEnabled: true,
          certificateValid: false,
          hostnameMatches: false,
          issuer: null,
          subject: null,
          validFrom: null,
          validTo: null,
          daysUntilExpiration: null,
          protocol: null,
          cipher: null,
          isSelfSigned: false,
          isExpired: false,
          error: 'TLS handshake timed out after 4000ms.',
          disclaimer: SSL_DISCLAIMER,
        });
      }
    }, 4000);

    const socket = tls.connect(
      {
        host: hostname,
        port: port,
        servername: hostname,
        rejectUnauthorized: false,
        timeout: 4000,
      },
      () => {
        if (resolved) return;
        resolved = true;
        clearTimeout(timeout);

        try {
          const cert = socket.getPeerCertificate(true);
          const cipherInfo = socket.getCipher();
          const protocol = socket.getProtocol();
          const isAuthorized = socket.authorized;

          if (!cert || Object.keys(cert).length === 0) {
            socket.destroy();
            return resolve({
              httpsEnabled: true,
              certificateValid: false,
              hostnameMatches: false,
              issuer: null,
              subject: null,
              validFrom: null,
              validTo: null,
              daysUntilExpiration: null,
              protocol: protocol || null,
              cipher: cipherInfo?.name || null,
              isSelfSigned: false,
              isExpired: false,
              error: 'No peer certificate returned by server.',
              disclaimer: SSL_DISCLAIMER,
            });
          }

          const validFromDate = cert.valid_from ? new Date(cert.valid_from) : null;
          const validToDate = cert.valid_to ? new Date(cert.valid_to) : null;
          const now = Date.now();

          const isExpired = validToDate ? now > validToDate.getTime() : false;
          const daysUntilExpiration = validToDate
            ? Math.floor((validToDate.getTime() - now) / (1000 * 60 * 60 * 24))
            : null;

          // Helper to extract string from string | string[]
          const extractString = (val: unknown): string => {
            if (Array.isArray(val)) return String(val[0] || '');
            return typeof val === 'string' ? val : '';
          };

          // Check issuer vs subject for self-signed
          const issuerCN = typeof cert.issuer === 'object' ? extractString(cert.issuer.CN) || extractString(cert.issuer.O) : '';
          const subjectCN = typeof cert.subject === 'object' ? extractString(cert.subject.CN) || extractString(cert.subject.O) : '';
          const isSelfSigned = Boolean(issuerCN && subjectCN && issuerCN === subjectCN);

          // Verify hostname match
          let hostnameMatches = false;
          if (cert.subjectaltname) {
            const sanList = cert.subjectaltname.split(',').map((s) => s.trim().replace(/^DNS:/, ''));
            hostnameMatches = sanList.some((pattern) => matchesHostnamePattern(pattern, hostname));
          } else if (cert.subject?.CN) {
            hostnameMatches = matchesHostnamePattern(extractString(cert.subject.CN), hostname);
          }

          socket.destroy();

          resolve({
            httpsEnabled: true,
            certificateValid: isAuthorized && !isExpired,
            hostnameMatches,
            issuer: issuerCN || 'Unknown Issuer',
            subject: subjectCN || 'Unknown Subject',
            validFrom: validFromDate?.toISOString() || null,
            validTo: validToDate?.toISOString() || null,
            daysUntilExpiration,
            protocol: protocol || null,
            cipher: cipherInfo?.name || null,
            isSelfSigned,
            isExpired,
            error: isAuthorized ? undefined : socket.authorizationError?.message || undefined,
            disclaimer: SSL_DISCLAIMER,
          });
        } catch (err) {
          socket.destroy();
          const msg = err instanceof Error ? err.message : 'Error reading certificate';
          resolve({
            httpsEnabled: true,
            certificateValid: false,
            hostnameMatches: false,
            issuer: null,
            subject: null,
            validFrom: null,
            validTo: null,
            daysUntilExpiration: null,
            protocol: null,
            cipher: null,
            isSelfSigned: false,
            isExpired: false,
            error: msg,
            disclaimer: SSL_DISCLAIMER,
          });
        }
      }
    );

    socket.on('error', (err) => {
      if (!resolved) {
        resolved = true;
        clearTimeout(timeout);
        socket.destroy();
        resolve({
          httpsEnabled: true,
          certificateValid: false,
          hostnameMatches: false,
          issuer: null,
          subject: null,
          validFrom: null,
          validTo: null,
          daysUntilExpiration: null,
          protocol: null,
          cipher: null,
          isSelfSigned: false,
          isExpired: false,
          error: `TLS Connection Error: ${err.message}`,
          disclaimer: SSL_DISCLAIMER,
        });
      }
    });
  });
}

function matchesHostnamePattern(pattern: string, hostname: string): boolean {
  const p = pattern.toLowerCase().trim();
  const h = hostname.toLowerCase().trim();

  if (p === h) return true;
  if (p.startsWith('*.')) {
    const root = p.substring(2);
    return h.endsWith('.' + root) || h === root;
  }
  return false;
}
