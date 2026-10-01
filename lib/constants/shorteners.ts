export const KNOWN_SHORTENERS = new Map<string, string>([
  ['bit.ly', 'Bitly'],
  ['tinyurl.com', 'TinyURL'],
  ['t.co', 'Twitter / X Shortener'],
  ['is.gd', 'is.gd'],
  ['cutt.ly', 'Cuttly'],
  ['ow.ly', 'Owly'],
  ['buff.ly', 'Buffer'],
  ['goo.gl', 'Google URL Shortener (Legacy)'],
  ['rb.gy', 'Rebrandly'],
  ['shorturl.at', 'ShortURL'],
  ['bit.do', 'Bit.do'],
  ['bl.ink', 'Blink'],
  ['qr.ae', 'Quora'],
  ['v.gd', 'v.gd'],
  ['adf.ly', 'Adf.ly'],
  ['rebrand.ly', 'Rebrandly'],
  ['t.ly', 'T.ly'],
]);

export function getShortenerInfo(hostname: string): { isShortener: boolean; name?: string } {
  const host = hostname.toLowerCase();
  for (const [domain, name] of Array.from(KNOWN_SHORTENERS.entries())) {
    if (host === domain || host.endsWith('.' + domain)) {
      return { isShortener: true, name };
    }
  }
  return { isShortener: false };
}
