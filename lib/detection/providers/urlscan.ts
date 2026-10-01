import {
  ExternalAnalysisProvider,
  ExternalAnalysisResult,
  ExternalAnalysisStatus,
  EvidenceItem,
} from '@/types/security';

const KNOWN_BRANDS = [
  { name: 'PayPal', patterns: ['paypal', 'pay-pal', 'paypa1'] },
  { name: 'Microsoft', patterns: ['microsoft', 'office365', 'outlook', 'onedrive', 'msft', 'msoffice'] },
  { name: 'Google', patterns: ['google', 'gmail', 'gdrive', 'g-drive', 'g00gle'] },
  { name: 'Apple', patterns: ['apple', 'icloud', 'appleid', 'app-le'] },
  { name: 'Amazon', patterns: ['amazon', 'aws-verify', 'amazn'] },
  { name: 'Meta', patterns: ['meta', 'facebook', 'instagram', 'whatsapp'] },
  { name: 'Netflix', patterns: ['netflix', 'net-flix'] },
  { name: 'Bank of America', patterns: ['bankofamerica', 'bofa'] },
  { name: 'Wells Fargo', patterns: ['wellsfargo'] },
  { name: 'Chase', patterns: ['chase', 'chase-bank'] },
];

export class URLScanProvider implements ExternalAnalysisProvider {
  public readonly name = 'URLscan';

  public isConfigured(): boolean {
    return Boolean(process.env.URLSCAN_API_KEY && process.env.URLSCAN_API_KEY.trim().length > 0);
  }

  public async analyze(url: string): Promise<ExternalAnalysisResult> {
    if (!this.isConfigured()) {
      return {
        providerName: this.name,
        status: 'NOT_CONFIGURED',
        isFlagged: false,
        details: 'URLSCAN_API_KEY is not configured on server deployment.',
        evidence: [
          {
            source: this.name,
            finding: 'URLscan API key is not configured.',
            impact: 'CONFIDENCE_REDUCTION',
            actual: true,
            category: 'EXTERNAL_ANALYSIS',
          },
        ],
      };
    }

    const apiKey = process.env.URLSCAN_API_KEY!.trim();
    const visibility = process.env.URLSCAN_VISIBILITY || 'private';

    try {
      // Step 1: Submit URL to urlscan.io
      const submitController = new AbortController();
      const submitTimeout = setTimeout(() => submitController.abort(), 6000);

      const submitResp = await fetch('https://urlscan.io/api/v1/scan/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'API-Key': apiKey,
        },
        body: JSON.stringify({ url, visibility }),
        signal: submitController.signal,
      });
      clearTimeout(submitTimeout);

      if (submitResp.status === 429) {
        return {
          providerName: this.name,
          status: 'RATE_LIMITED',
          isFlagged: false,
          details: 'urlscan.io rate limit exceeded (HTTP 429).',
          evidence: [
            {
              source: this.name,
              finding: 'urlscan.io API rate limit exceeded.',
              impact: 'CONFIDENCE_REDUCTION',
              actual: true,
              category: 'EXTERNAL_ANALYSIS',
            },
          ],
        };
      }

      if (!submitResp.ok) {
        const errorText = await submitResp.text().catch(() => '');
        return {
          providerName: this.name,
          status: 'ERROR',
          isFlagged: false,
          details: `urlscan.io submission error (HTTP ${submitResp.status}): ${errorText.substring(0, 100)}`,
          evidence: [],
        };
      }

      const submitData = await submitResp.json().catch(() => null);
      if (!submitData || !submitData.uuid) {
        return {
          providerName: this.name,
          status: 'ERROR',
          isFlagged: false,
          details: 'urlscan.io returned malformed submission response (missing uuid).',
          evidence: [],
        };
      }

      const uuid = submitData.uuid as string;
      const resultApiUrl = submitData.api as string || `https://urlscan.io/api/v1/result/${uuid}/`;
      const resultPageUrl = submitData.result as string || `https://urlscan.io/result/${uuid}/`;

      // Step 2: Bounded Polling Loop for Result
      const resultData = await this.pollResult(resultApiUrl, apiKey, 5, 1500);

      if (!resultData) {
        return {
          providerName: this.name,
          status: 'PENDING',
          isFlagged: false,
          scanUuid: uuid,
          resultUrl: resultPageUrl,
          details: 'urlscan.io scan submitted successfully but result pending / timed out.',
          evidence: [
            {
              source: this.name,
              finding: `urlscan.io scan submitted (UUID: ${uuid}) but page processing is pending.`,
              impact: 'CONFIDENCE_REDUCTION',
              actual: true,
              category: 'EXTERNAL_ANALYSIS',
            },
          ],
          metadata: {
            screenshotUrl: `https://urlscan.io/screenshots/${uuid}.png`,
          },
        };
      }

      // Step 3: Extract Findings and Evidence from Completed Result
      return this.parseResult(uuid, resultPageUrl, resultData);
    } catch (err: unknown) {
      const isAbort = err instanceof Error && err.name === 'AbortError';
      const status: ExternalAnalysisStatus = isAbort ? 'TIMEOUT' : 'UNAVAILABLE';
      return {
        providerName: this.name,
        status,
        isFlagged: false,
        details: isAbort ? 'urlscan.io request timed out.' : (err instanceof Error ? err.message : 'urlscan.io provider failure'),
        evidence: [],
      };
    }
  }

  private async pollResult(
    resultUrl: string,
    apiKey: string,
    maxAttempts = 5,
    intervalMs = 1500
  ): Promise<Record<string, unknown> | null> {
    const delay = process.env.NODE_ENV === 'test' || process.env.VITEST ? 5 : intervalMs;
    for (let i = 0; i < maxAttempts; i++) {
      await new Promise((r) => setTimeout(r, delay));
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 4000);

        const resp = await fetch(resultUrl, {
          method: 'GET',
          headers: { 'API-Key': apiKey },
          signal: controller.signal,
        });
        clearTimeout(timer);

        if (resp.status === 200) {
          const data = await resp.json().catch(() => null);
          if (data && (data.page || data.verdicts || data.task)) {
            return data;
          }
        }
        if (resp.status !== 404 && resp.status !== 200) {
          // Non-404 error during poll
          return null;
        }
      } catch {
        // Retry loop continue
      }
    }
    return null;
  }

  private parseResult(uuid: string, resultUrl: string, data: Record<string, unknown>): ExternalAnalysisResult {
    const evidence: EvidenceItem[] = [];
    const page = (data.page || {}) as Record<string, unknown>;
    const verdicts = (data.verdicts || {}) as Record<string, unknown>;
    const overallVerdicts = (verdicts.overall || {}) as Record<string, unknown>;
    const urlscanVerdicts = (verdicts.urlscan || {}) as Record<string, unknown>;
    const dataSection = (data.data || {}) as Record<string, unknown>;
    const requests = Array.isArray(dataSection.requests) ? dataSection.requests : [];

    const pageDomain = String(page.domain || page.apexDomain || '').toLowerCase();
    const pageTitle = String(page.title || '');
    const score = Number(overallVerdicts.score ?? urlscanVerdicts.score ?? 0);
    const tags = Array.isArray(overallVerdicts.tags)
      ? (overallVerdicts.tags as string[])
      : Array.isArray(urlscanVerdicts.tags)
      ? (urlscanVerdicts.tags as string[])
      : [];

    const isMalicious =
      Boolean(overallVerdicts.malicious) ||
      Boolean(urlscanVerdicts.malicious) ||
      score >= 50 ||
      tags.some((t) => t.toLowerCase().includes('phish') || t.toLowerCase().includes('malicious'));

    const status: ExternalAnalysisStatus = isMalicious ? 'FLAGGED' : 'CLEAN';

    // 1. Phishing / Malicious Verdict Evidence
    if (isMalicious) {
      evidence.push({
        source: this.name,
        finding: `urlscan.io explicit threat detection (Score: ${score}, Tags: ${tags.join(', ') || 'phishing'}).`,
        impact: 'HIGH_RISK',
        actual: true,
        category: 'THREAT_INTELLIGENCE',
      });
    } else {
      evidence.push({
        source: this.name,
        finding: `urlscan.io behavioral scan completed with zero malicious verdicts (Verdict score: ${score}).`,
        impact: 'NEUTRAL',
        actual: true,
        category: 'EXTERNAL_ANALYSIS',
      });
    }

    // 2. Password & Credential Form Analysis
    const domStr = typeof dataSection.dom === 'string' ? dataSection.dom.toLowerCase() : '';
    const hasPasswordField =
      domStr.includes('type="password"') ||
      domStr.includes("type='password'") ||
      requests.some((r: any) => JSON.stringify(r).toLowerCase().includes('password'));

    const hasLoginForm =
      hasPasswordField ||
      domStr.includes('login') ||
      domStr.includes('signin') ||
      domStr.includes('account/verify');

    if (hasPasswordField) {
      evidence.push({
        source: this.name,
        finding: 'URLscan DOM snapshot detected password input field (Credential collection form).',
        impact: 'MEDIUM_RISK',
        actual: true,
        category: 'PAGE_CONTENT',
      });
    }

    // 3. Cross-Domain Credential Submission Analysis
    let crossDomainFormSubmission = false;
    let formTargetDomain = '';

    // Inspect form action matches in DOM snapshot
    const actionMatches = domStr.match(/<form[^>]*action=["']?([^"'\s>]+)["']?/gi);
    if (actionMatches) {
      for (const formTag of actionMatches) {
        const match = formTag.match(/action=["']?([^"'\s>]+)["']?/i);
        if (match && match[1]) {
          const actionUrl = match[1];
          if (actionUrl.startsWith('http://') || actionUrl.startsWith('https://')) {
            try {
              const targetHost = new URL(actionUrl).hostname.toLowerCase();
              if (targetHost && targetHost !== pageDomain && !targetHost.endsWith('.' + pageDomain)) {
                crossDomainFormSubmission = true;
                formTargetDomain = targetHost;
                break;
              }
            } catch {
              // Invalid action URL string
            }
          }
        }
      }
    }

    if (crossDomainFormSubmission) {
      evidence.push({
        source: this.name,
        finding: `Cross-domain credential form submission detected (Scanned host '${pageDomain}' submits data to external host '${formTargetDomain}').`,
        impact: 'HIGH_RISK',
        actual: true,
        category: 'CROSS_DOMAIN_CREDENTIAL_SUBMISSION',
      });
    }

    // 4. Brand Impersonation Correlation
    let detectedBrand: string | undefined;
    if (pageTitle) {
      const lowerTitle = pageTitle.toLowerCase();
      for (const brand of KNOWN_BRANDS) {
        if (brand.patterns.some((p) => lowerTitle.includes(p))) {
          const isOfficial = brand.patterns.some((p) => pageDomain.includes(p));
          if (!isOfficial) {
            detectedBrand = brand.name;
            evidence.push({
              source: this.name,
              finding: `Brand impersonation detected: Page title '${pageTitle}' references brand '${brand.name}' on unofficial domain '${pageDomain}'.`,
              impact: 'HIGH_RISK',
              actual: true,
              category: 'BRAND_IMPERSONATION',
            });
            break;
          }
        }
      }
    }

    const contactedDomainsCount = Array.isArray(dataSection.links) ? dataSection.links.length : undefined;
    const contactedIpsCount = Array.isArray(dataSection.ips) ? dataSection.ips.length : undefined;

    return {
      providerName: this.name,
      status,
      isFlagged: isMalicious,
      threatType: isMalicious ? 'Phishing / Web Threat' : undefined,
      scanUuid: uuid,
      resultUrl,
      evidence,
      metadata: {
        screenshotUrl: `https://urlscan.io/screenshots/${uuid}.png`,
        pageTitle,
        pageDomain,
        hasLoginForm,
        hasPasswordField,
        crossDomainFormSubmission,
        formTargetDomain,
        detectedBrand,
        verdictScore: score,
        tags,
        contactedDomainsCount,
        contactedIpsCount,
      },
    };
  }
}
