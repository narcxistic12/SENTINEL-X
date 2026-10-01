import * as dns from 'node:dns/promises';
import { DomainIntelligence } from '@/types/security';

/**
 * Performs real DNS queries for the given hostname.
 * Retrieves A, AAAA, MX, TXT, and NS records.
 * Never fabricates missing or unavailable data.
 */
export async function analyzeDomain(hostname: string): Promise<DomainIntelligence> {
  const parts = hostname.toLowerCase().split('.');
  const tld = parts.length > 1 ? parts[parts.length - 1] : '';
  const domain = parts.length >= 2 ? parts.slice(-2).join('.') : hostname;

  const result: DomainIntelligence = {
    domain,
    tld,
    isResolvable: false,
    ipAddresses: [],
    ipv6Addresses: [],
    mxRecords: [],
    txtRecords: [],
    nsRecords: [],
    hasMx: false,
    domainAgeEstimateDays: null,
    registrationDate: null,
    expirationDate: null,
    registrar: null,
    isAvailable: false,
  };

  try {
    // Parallel DNS lookups with individual error isolation
    const [aResult, aaaaResult, mxResult, txtResult, nsResult] = await Promise.allSettled([
      dns.resolve4(hostname),
      dns.resolve6(hostname),
      dns.resolveMx(domain),
      dns.resolveTxt(domain),
      dns.resolveNs(domain),
    ]);

    if (aResult.status === 'fulfilled') {
      result.ipAddresses = aResult.value;
      result.isResolvable = true;
    }

    if (aaaaResult.status === 'fulfilled') {
      result.ipv6Addresses = aaaaResult.value;
      result.isResolvable = true;
    }

    if (mxResult.status === 'fulfilled' && mxResult.value.length > 0) {
      result.mxRecords = mxResult.value;
      result.hasMx = true;
    }

    if (txtResult.status === 'fulfilled') {
      result.txtRecords = txtResult.value;
    }

    if (nsResult.status === 'fulfilled') {
      result.nsRecords = nsResult.value;
    }

    result.isAvailable = result.isResolvable;
    return result;
  } catch (err) {
    result.lookupError = err instanceof Error ? err.message : 'DNS lookup failed';
    return result;
  }
}
