import { DomainRegistrationIntelligence } from '@/types/security';

/**
 * Domain Registration & Age Intelligence Service using public RDAP (Registration Data Access Protocol).
 * Safely queries domain registration events without requiring third-party API keys.
 */
export async function analyzeDomainRegistration(hostname: string): Promise<DomainRegistrationIntelligence> {
  const cleanHost = hostname.toLowerCase().trim();
  
  // Extract registrable domain (e.g., sub.example.com -> example.com)
  const parts = cleanHost.split('.');
  if (parts.length < 2) {
    return {
      status: 'NOT_CONFIGURED',
      domainAgeDays: null,
      registrationDate: null,
      expirationDate: null,
      registrar: null,
      isNewlyRegistered: false,
      isYoungDomain: false,
      nameservers: [],
      details: 'Invalid domain structure for RDAP lookup.',
    };
  }

  // Handle common 2-level TLDs (e.g. .co.uk, .com.au)
  const lastTwo = parts.slice(-2).join('.');
  let registrableDomain = parts.slice(-2).join('.');
  if (parts.length >= 3 && ['co.uk', 'gov.uk', 'com.au', 'net.au', 'co.jp', 'com.br'].includes(lastTwo)) {
    registrableDomain = parts.slice(-3).join('.');
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3000);

    const rdapEndpoint = `https://rdap.org/domain/${registrableDomain}`;
    const res = await fetch(rdapEndpoint, {
      method: 'GET',
      headers: {
        'Accept': 'application/rdap+json, application/json',
        'User-Agent': 'sentinelx-security-scanner/1.0',
      },
      signal: controller.signal,
    });

    clearTimeout(timer);

    if (res.status === 404) {
      return {
        status: 'UNAVAILABLE',
        domainAgeDays: null,
        registrationDate: null,
        expirationDate: null,
        registrar: null,
        isNewlyRegistered: false,
        isYoungDomain: false,
        nameservers: [],
        details: 'Domain registration record not found in public RDAP databases.',
      };
    }

    if (!res.ok) {
      return {
        status: 'UNAVAILABLE',
        domainAgeDays: null,
        registrationDate: null,
        expirationDate: null,
        registrar: null,
        isNewlyRegistered: false,
        isYoungDomain: false,
        nameservers: [],
        details: `RDAP lookup returned HTTP ${res.status}`,
      };
    }

    const data = await res.json();
    const events: any[] = data.events || [];
    
    let registrationDateStr: string | null = null;
    let expirationDateStr: string | null = null;

    for (const ev of events) {
      const action = (ev.eventAction || '').toLowerCase();
      if (['registration', 'created', 'creation'].includes(action)) {
        registrationDateStr = ev.eventDate;
      } else if (['expiration', 'expires', 'expiry'].includes(action)) {
        expirationDateStr = ev.eventDate;
      }
    }

    // Extract registrar
    let registrar: string | null = null;
    const entities: any[] = data.entities || [];
    for (const ent of entities) {
      const roles: string[] = ent.roles || [];
      if (roles.includes('registrar')) {
        const fn = ent.vcardArray?.[1]?.find((v: any) => v[0] === 'fn')?.[3];
        registrar = fn || ent.handle || 'Registered';
        break;
      }
    }

    // Extract nameservers
    const nameservers: string[] = [];
    const nsObjects: any[] = data.nameservers || [];
    for (const ns of nsObjects) {
      if (ns.ldhName) nameservers.push(ns.ldhName.toLowerCase());
    }

    let domainAgeDays: number | null = null;
    let isNewlyRegistered = false;
    let isYoungDomain = false;

    if (registrationDateStr) {
      const regDate = new Date(registrationDateStr);
      if (!isNaN(regDate.getTime())) {
        const diffMs = Date.now() - regDate.getTime();
        domainAgeDays = Math.max(0, Math.floor(diffMs / (1000 * 60 * 60 * 24)));
        isNewlyRegistered = domainAgeDays <= 30;
        isYoungDomain = domainAgeDays <= 90;
      }
    }

    return {
      status: 'CHECKED',
      domainAgeDays,
      registrationDate: registrationDateStr ? new Date(registrationDateStr).toISOString().split('T')[0] : null,
      expirationDate: expirationDateStr ? new Date(expirationDateStr).toISOString().split('T')[0] : null,
      registrar,
      isNewlyRegistered,
      isYoungDomain,
      nameservers,
      details: domainAgeDays !== null ? `Domain age: ${domainAgeDays} days` : 'Registration date unavailable',
    };
  } catch (err: unknown) {
    if (err instanceof Error && err.name === 'AbortError') {
      return {
        status: 'TIMEOUT',
        domainAgeDays: null,
        registrationDate: null,
        expirationDate: null,
        registrar: null,
        isNewlyRegistered: false,
        isYoungDomain: false,
        nameservers: [],
        details: 'RDAP registration lookup timed out (3s).',
      };
    }
    return {
      status: 'UNAVAILABLE',
      domainAgeDays: null,
      registrationDate: null,
      expirationDate: null,
      registrar: null,
      isNewlyRegistered: false,
      isYoungDomain: false,
      nameservers: [],
      details: err instanceof Error ? err.message : 'RDAP lookup failed',
    };
  }
}
