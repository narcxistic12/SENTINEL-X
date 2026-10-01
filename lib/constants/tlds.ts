// Commonly abused top-level domains frequently observed in spam and phishing campaigns
export const RISKY_TLDS = new Set([
  'tk',
  'ml',
  'ga',
  'cf',
  'gq',
  'buzz',
  'top',
  'xyz',
  'fit',
  'icu',
  'cam',
  'rest',
  'bar',
  'surf',
  'monster',
  'quest',
  'country',
  'stream',
  'gdn',
  'mom',
  'work',
  'click',
  'link',
  'casa',
  'kim',
  'vip',
  'space',
  'club',
  'fun',
  'zip',
  'lol',
  'sbs',
  'cfd',
]);

export function isRiskyTld(tld: string): boolean {
  if (!tld) return false;
  const clean = tld.toLowerCase().replace(/^\./, '');
  return RISKY_TLDS.has(clean);
}
