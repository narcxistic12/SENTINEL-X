import { RedirectIntelligence, RedirectHop } from '@/types/security';
import { validateUrlSsrf } from '@/lib/security/ssrf';

const MAX_REDIRECTS = 5;
const HOP_TIMEOUT_MS = 2500;

/**
 * Follows HTTP/HTTPS redirects hop-by-hop with independent SSRF verification on every hop.
 */
export async function analyzeRedirects(initialUrl: string): Promise<RedirectIntelligence> {
  const hops: RedirectHop[] = [];
  const visitedUrls = new Set<string>();

  let currentUrl = initialUrl;
  let hopCount = 0;
  let loopDetected = false;
  let ssrfBlocked = false;
  let errorMessage: string | undefined;

  while (hopCount < MAX_REDIRECTS) {
    if (visitedUrls.has(currentUrl)) {
      loopDetected = true;
      break;
    }
    visitedUrls.add(currentUrl);

    // 1. SSRF check before requesting next hop
    const ssrfCheck = await validateUrlSsrf(currentUrl);
    if (!ssrfCheck.isSafe) {
      ssrfBlocked = true;
      errorMessage = `Redirect hop blocked by SSRF defense: ${ssrfCheck.reason}`;
      break;
    }

    const startTime = Date.now();
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), HOP_TIMEOUT_MS);

      // Perform a HEAD request or GET without downloading full body
      const res = await fetch(currentUrl, {
        method: 'HEAD',
        redirect: 'manual', // Do not automatically follow, inspect status code manually
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SentinelXSecurityScanner/1.0',
        },
        signal: controller.signal,
      });

      clearTimeout(timer);
      const durationMs = Date.now() - startTime;

      const isRedirect = [301, 302, 303, 307, 308].includes(res.status);
      const locationHeader = res.headers.get('location');

      if (isRedirect && locationHeader) {
        hopCount++;
        // Resolve relative redirects against current URL
        const nextUrl = new URL(locationHeader, currentUrl).toString();

        const currentHost = new URL(currentUrl).hostname.toLowerCase();
        const nextHost = new URL(nextUrl).hostname.toLowerCase();
        const crossDomain = currentHost !== nextHost;

        hops.push({
          hopNumber: hopCount,
          url: currentUrl,
          statusCode: res.status,
          targetUrl: nextUrl,
          crossDomain,
          durationMs,
        });

        currentUrl = nextUrl;
      } else {
        // No further redirect, reached final destination
        break;
      }
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'AbortError') {
        errorMessage = `Redirect inspection timed out after ${HOP_TIMEOUT_MS}ms.`;
      } else {
        // Many web servers block HEAD requests; fallback to GET with minimal read
        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), HOP_TIMEOUT_MS);
          const getRes = await fetch(currentUrl, {
            method: 'GET',
            redirect: 'manual',
            headers: {
              'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SentinelXSecurityScanner/1.0',
            },
            signal: controller.signal,
          });
          clearTimeout(timer);
          const durationMs = Date.now() - startTime;

          const isRedirect = [301, 302, 303, 307, 308].includes(getRes.status);
          const locationHeader = getRes.headers.get('location');

          if (isRedirect && locationHeader) {
            hopCount++;
            const nextUrl = new URL(locationHeader, currentUrl).toString();
            const currentHost = new URL(currentUrl).hostname.toLowerCase();
            const nextHost = new URL(nextUrl).hostname.toLowerCase();

            hops.push({
              hopNumber: hopCount,
              url: currentUrl,
              statusCode: getRes.status,
              targetUrl: nextUrl,
              crossDomain: currentHost !== nextHost,
              durationMs,
            });

            currentUrl = nextUrl;
          } else {
            break;
          }
        } catch {
          // If server rejects both, record final state without crashing
          break;
        }
      }
      break;
    }
  }

  const initialHost = new URL(initialUrl).hostname.toLowerCase();
  const finalHost = new URL(currentUrl).hostname.toLowerCase();

  return {
    originalUrl: initialUrl,
    finalUrl: currentUrl,
    hopCount,
    hops,
    destinationChanged: initialHost !== finalHost,
    loopDetected,
    ssrfBlocked,
    error: errorMessage,
  };
}
