export interface BrandImpersonationResult {
  detected: boolean;
  brandFound?: string;
  evidence: string;
  similarityType?: 'subdomain_spoof' | 'affix_spoof' | 'typosquatting';
  officialDomain?: string;
  isOfficialDomainMatch?: boolean;
}

export interface BrandDefinition {
  name: string;
  officialDomains: string[];
}

export const BRAND_DIRECTORY: BrandDefinition[] = [
  { name: 'paypal', officialDomains: ['paypal.com', 'paypal.me'] },
  { name: 'microsoft', officialDomains: ['microsoft.com', 'live.com', 'office.com', 'msn.com', 'azure.com', 'outlook.com', 'microsoftonline.com'] },
  { name: 'apple', officialDomains: ['apple.com', 'icloud.com'] },
  { name: 'google', officialDomains: ['google.com', 'youtube.com', 'gmail.com', 'googledrive.com', 'withgoogle.com', 'android.com'] },
  { name: 'netflix', officialDomains: ['netflix.com'] },
  { name: 'amazon', officialDomains: ['amazon.com', 'aws.amazon.com', 'media-amazon.com'] },
  { name: 'chase', officialDomains: ['chase.com'] },
  { name: 'wellsfargo', officialDomains: ['wellsfargo.com'] },
  { name: 'bankofamerica', officialDomains: ['bankofamerica.com'] },
  { name: 'facebook', officialDomains: ['facebook.com', 'fb.com', 'meta.com'] },
  { name: 'instagram', officialDomains: ['instagram.com'] },
  { name: 'twitter', officialDomains: ['twitter.com', 'x.com'] },
  { name: 'linkedin', officialDomains: ['linkedin.com'] },
  { name: 'github', officialDomains: ['github.com', 'github.io'] },
  { name: 'dropbox', officialDomains: ['dropbox.com'] },
  { name: 'dhl', officialDomains: ['dhl.com'] },
  { name: 'fedex', officialDomains: ['fedex.com'] },
  { name: 'ups', officialDomains: ['ups.com'] },
  { name: 'usps', officialDomains: ['usps.com'] },
  { name: 'binance', officialDomains: ['binance.com'] },
  { name: 'coinbase', officialDomains: ['coinbase.com'] },
  { name: 'metamask', officialDomains: ['metamask.io'] },
  { name: 'yahoo', officialDomains: ['yahoo.com'] },
  { name: 'aol', officialDomains: ['aol.com'] },
  { name: 'protonmail', officialDomains: ['protonmail.com', 'proton.me'] },
  { name: 'whatsapp', officialDomains: ['whatsapp.com'] },
  { name: 'telegram', officialDomains: ['telegram.org', 't.me'] },
  { name: 'chatgpt', officialDomains: ['chatgpt.com', 'openai.com'] },
  { name: 'openai', officialDomains: ['openai.com', 'chatgpt.com'] },
  { name: 'steam', officialDomains: ['steampowered.com', 'steamcommunity.com'] },
  { name: 'discord', officialDomains: ['discord.com', 'discord.gg'] },
  { name: 'spotify', officialDomains: ['spotify.com'] },
  { name: 'allegro', officialDomains: ['allegro.pl', 'allegro.cz'] },
  { name: 'ebay', officialDomains: ['ebay.com'] },
  { name: 'walmart', officialDomains: ['walmart.com'] },
  { name: 'target', officialDomains: ['target.com'] },
  { name: 'stripe', officialDomains: ['stripe.com'] },
  { name: 'roblox', officialDomains: ['roblox.com'] },
];

/**
 * Calculates Levenshtein distance between two strings to detect typosquatting.
 */
export function calculateLevenshteinDistance(a: string, b: string): number {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const matrix: number[][] = [];
  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }
  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // substitution
          matrix[i][j - 1] + 1,     // insertion
          matrix[i - 1][j] + 1      // deletion
        );
      }
    }
  }

  return matrix[b.length][a.length];
}

/**
 * Helper to extract registrable domain.
 */
function getRegistrableDomain(hostname: string): string {
  const parts = hostname.toLowerCase().split('.');
  if (parts.length <= 2) return hostname.toLowerCase();
  
  const secondLevel = parts[parts.length - 2];
  if (['co', 'com', 'org', 'net', 'gov', 'edu', 'ac'].includes(secondLevel)) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

/**
 * Normalizes leetspeak substitutions (e.g. 0->o, 1->l, 3->e, 5->s, @->a).
 */
function normalizeLeetspeak(str: string): string {
  return str
    .replace(/[-_]/g, '')
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/5/g, 's')
    .replace(/@/g, 'a');
}

/**
 * Detects generic brand impersonation using edit distance, affixes, leetspeak, and subdomain nesting.
 * Compares requested domain against official brand domain registries.
 */
export function detectBrandImpersonation(hostnameOrUrl: string): BrandImpersonationResult {
  let hostname = hostnameOrUrl.toLowerCase().trim();
  if (hostname.startsWith('http://') || hostname.startsWith('https://')) {
    try {
      hostname = new URL(hostname).hostname;
    } catch {
      // ignore
    }
  }

  const cleanHost = hostname.toLowerCase().trim();
  const normalizedCleanHost = normalizeLeetspeak(cleanHost);
  const registrableDomain = getRegistrableDomain(cleanHost);
  const rootName = registrableDomain.split('.')[0];
  const normalizedRootName = normalizeLeetspeak(rootName);
  
  for (const brandDef of BRAND_DIRECTORY) {
    const brand = brandDef.name;
    const isOfficial = brandDef.officialDomains.some(
      (off) => registrableDomain === off || registrableDomain.endsWith('.' + off)
    );

    // 1. If this is an official domain of the brand (e.g., paypal.com, login.paypal.com, aws.amazon.com), skip impersonation alert!
    if (isOfficial || rootName === brand) {
      if (isOfficial) {
        return {
          detected: false,
          brandFound: brand,
          evidence: `Official domain match for brand '${brand}'.`,
          officialDomain: brandDef.officialDomains[0],
          isOfficialDomainMatch: true,
        };
      }
      continue;
    }

    // 2. Exact leetspeak typosquatting root match (e.g. g00gle.com, paypa1.com)
    if (normalizedRootName === brand) {
      return {
        detected: true,
        brandFound: brand,
        similarityType: 'typosquatting',
        evidence: `Domain name '${rootName}' is a lookalike / typosquatting variation of brand '${brand}'.`,
        officialDomain: brandDef.officialDomains[0],
        isOfficialDomainMatch: false,
      };
    }

    // 3. Brand in subdomain: e.g. paypal.security-update.com or paypa1.login.attacker.com
    if (cleanHost.includes(brand) || normalizedCleanHost.includes(brand)) {
      return {
        detected: true,
        brandFound: brand,
        similarityType: 'subdomain_spoof',
        evidence: `Brand '${brand}' appears in the hostname, but the registrable domain is '${registrableDomain}'.`,
        officialDomain: brandDef.officialDomains[0],
        isOfficialDomainMatch: false,
      };
    }
    
    // 4. Typosquatting / Added Affixes on root domain: e.g. paypal-update.com or paypa1-verify-account.com
    if (rootName.includes(brand) || normalizedRootName.includes(brand)) {
      return {
        detected: true,
        brandFound: brand,
        similarityType: 'affix_spoof',
        evidence: `Root domain '${registrableDomain}' appears to impersonate brand '${brand}' using added affixes or keywords.`,
        officialDomain: brandDef.officialDomains[0],
        isOfficialDomainMatch: false,
      };
    }

    // 5. Levenshtein edit distance for typosquatting: e.g. microsft, chatgbt
    if (rootName.length >= 4 && Math.abs(rootName.length - brand.length) <= 2) {
      const distance = calculateLevenshteinDistance(normalizedRootName, brand);
      if (distance > 0 && distance <= (brand.length <= 5 ? 1 : 2)) {
        return {
          detected: true,
          brandFound: brand,
          similarityType: 'typosquatting',
          evidence: `Domain name '${rootName}' is a lookalike / typosquatting variation of brand '${brand}' (edit distance: ${distance}).`,
          officialDomain: brandDef.officialDomains[0],
          isOfficialDomainMatch: false,
        };
      }
    }
  }

  return { detected: false, evidence: '' };
}
