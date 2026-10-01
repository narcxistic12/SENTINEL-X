import {
  ExternalAnalysisProvider,
  ExternalAnalysisResult,
  ExternalAnalysisStatus,
  EvidenceItem,
} from '@/types/security';

const SENSITIVE_PARAM_REGEX = /(password|token|secret|api_key|access_token|bearer|auth|session|jwt|key)=([^&]+)/gi;

export class CloudflareUrlScannerProvider implements ExternalAnalysisProvider {
  public readonly name = 'Cloudflare URL Scanner';

  public isConfigured(): boolean {
    return Boolean(
      process.env.CLOUDFLARE_ACCOUNT_ID &&
        process.env.CLOUDFLARE_ACCOUNT_ID.trim().length > 0 &&
        process.env.CLOUDFLARE_URLSCANNER_API_TOKEN &&
        process.env.CLOUDFLARE_URLSCANNER_API_TOKEN.trim().length > 0
    );
  }

  public async analyze(url: string): Promise<ExternalAnalysisResult> {
    if (!this.isConfigured()) {
      return {
        providerName: this.name,
        status: 'NOT_CONFIGURED',
        isFlagged: false,
        details: 'CLOUDFLARE_ACCOUNT_ID or CLOUDFLARE_URLSCANNER_API_TOKEN is not configured.',
        evidence: [
          {
            source: this.name,
            finding: 'Cloudflare URL Scanner API is not configured.',
            impact: 'CONFIDENCE_REDUCTION',
            actual: true,
            category: 'EXTERNAL_ANALYSIS',
          },
        ],
      };
    }

    const accountId = process.env.CLOUDFLARE_ACCOUNT_ID!.trim();
    const apiToken = process.env.CLOUDFLARE_URLSCANNER_API_TOKEN!.trim();
    const visibility = process.env.CLOUDFLARE_URLSCAN_VISIBILITY || 'unlisted';

    // Privacy & secret redaction prior to external submission
    const sanitizedUrlToSubmit = url.replace(SENSITIVE_PARAM_REGEX, '$1=[REDACTED]');

    try {
      // Step 1: Submit URL to Cloudflare URL Scanner v2 API
      const submitController = new AbortController();
      const submitTimer = setTimeout(() => submitController.abort(), 6000);

      const submitResp = await fetch(
        `https://api.cloudflare.com/client/v4/accounts/${accountId}/urlscanner/v2/scan`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${apiToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            url: sanitizedUrlToSubmit,
            visibility,
          }),
          signal: submitController.signal,
        }
      );
      clearTimeout(submitTimer);

      if (submitResp.status === 401 || submitResp.status === 403) {
        return {
          providerName: this.name,
          status: 'ERROR',
          isFlagged: false,
          details: `Cloudflare URL Scanner authorization failed (HTTP ${submitResp.status}).`,
          evidence: [],
        };
      }

      if (submitResp.status === 429) {
        return {
          providerName: this.name,
          status: 'RATE_LIMITED',
          isFlagged: false,
          details: 'Cloudflare URL Scanner rate limit exceeded (HTTP 429).',
          evidence: [
            {
              source: this.name,
              finding: 'Cloudflare URL Scanner API rate limit exceeded.',
              impact: 'CONFIDENCE_REDUCTION',
              actual: true,
              category: 'EXTERNAL_ANALYSIS',
            },
          ],
        };
      }

      if (!submitResp.ok) {
        const errText = await submitResp.text().catch(() => '');
        return {
          providerName: this.name,
          status: 'ERROR',
          isFlagged: false,
          details: `Cloudflare URL Scanner submission error (HTTP ${submitResp.status}): ${errText.substring(0, 100)}`,
          evidence: [],
        };
      }

      const submitData = await submitResp.json().catch(() => null);
      const scanId =
        submitData?.result?.uuid ||
        submitData?.result?.id ||
        submitData?.result?.scanId ||
        submitData?.uuid;

      if (!scanId) {
        return {
          providerName: this.name,
          status: 'ERROR',
          isFlagged: false,
          details: 'Cloudflare URL Scanner returned malformed submission response (missing scanId).',
          evidence: [],
        };
      }

      // Step 2: Poll Cloudflare URL Scanner Result API
      const resultApiUrl = `https://api.cloudflare.com/client/v4/accounts/${accountId}/urlscanner/v2/result/${scanId}`;
      const resultData = await this.pollResult(resultApiUrl, apiToken, 5, 1000);

      if (!resultData) {
        return {
          providerName: this.name,
          status: 'PENDING',
          isFlagged: false,
          scanUuid: scanId,
          resultUrl: `https://radar.cloudflare.com/scan/${scanId}`,
          details: 'Cloudflare URL Scanner scan submitted, result pending / timed out.',
          evidence: [
            {
              source: this.name,
              finding: `Cloudflare URL Scanner scan submitted (ID: ${scanId}) but processing is pending.`,
              impact: 'CONFIDENCE_REDUCTION',
              actual: true,
              category: 'EXTERNAL_ANALYSIS',
            },
          ],
        };
      }

      // Step 3: Parse and extract evidence
      return this.parseResult(scanId, resultData);
    } catch (err: unknown) {
      const isAbort = err instanceof Error && err.name === 'AbortError';
      const status: ExternalAnalysisStatus = isAbort ? 'TIMEOUT' : 'UNAVAILABLE';
      return {
        providerName: this.name,
        status,
        isFlagged: false,
        details: isAbort ? 'Cloudflare URL Scanner request timed out.' : (err instanceof Error ? err.message : 'Cloudflare provider failure'),
        evidence: [],
      };
    }
  }

  private async pollResult(
    resultUrl: string,
    apiToken: string,
    maxAttempts = 5,
    intervalMs = 1000
  ): Promise<Record<string, unknown> | null> {
    const delay = process.env.NODE_ENV === 'test' || process.env.VITEST ? 5 : intervalMs;

    for (let i = 0; i < maxAttempts; i++) {
      await new Promise((r) => setTimeout(r, delay * Math.pow(1.2, i)));
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 4000);

        const resp = await fetch(resultUrl, {
          method: 'GET',
          headers: { Authorization: `Bearer ${apiToken}` },
          signal: controller.signal,
        });
        clearTimeout(timer);

        if (resp.status === 200) {
          const data = await resp.json().catch(() => null);
          if (data && (data.result || data.success)) {
            return data.result || data;
          }
        }
        if (resp.status !== 404 && resp.status !== 200) {
          return null;
        }
      } catch {
        // Continue loop
      }
    }
    return null;
  }

  private parseResult(scanId: string, data: Record<string, unknown>): ExternalAnalysisResult {
    const evidence: EvidenceItem[] = [];
    const verdicts = (data.verdicts || data.verdict || {}) as Record<string, unknown>;
    const page = (data.page || data.task || {}) as Record<string, unknown>;
    const stats = (data.stats || {}) as Record<string, unknown>;

    const isMalicious =
      Boolean(verdicts.malicious) ||
      Boolean(verdicts.isPhishing) ||
      String(verdicts.overall || '').toLowerCase().includes('malicious') ||
      String(verdicts.overall || '').toLowerCase().includes('phish');

    const status: ExternalAnalysisStatus = isMalicious ? 'FLAGGED' : 'CLEAN';

    if (isMalicious) {
      evidence.push({
        source: this.name,
        finding: `Cloudflare URL Scanner flagged page as malicious threat.`,
        impact: 'HIGH_RISK',
        actual: true,
        category: 'THREAT_INTELLIGENCE',
      });
    } else {
      evidence.push({
        source: this.name,
        finding: 'Cloudflare URL Scanner scan completed with no malicious findings.',
        impact: 'NEUTRAL',
        actual: true,
        category: 'EXTERNAL_ANALYSIS',
      });
    }

    const pageTitle = String(page.title || '');
    const pageDomain = String(page.domain || '');
    const ip = String(page.ip || page.ipAddress || '');
    const asn = String(page.asn || '');
    const country = String(page.country || '');
    const requestCount = Number(stats.requests || stats.requestCount || 0);

    return {
      providerName: this.name,
      status,
      isFlagged: isMalicious,
      threatType: isMalicious ? 'Cloudflare URL Scanner Detection' : undefined,
      scanUuid: scanId,
      resultUrl: `https://radar.cloudflare.com/scan/${scanId}`,
      evidence,
      metadata: {
        pageTitle,
        pageDomain,
        ip,
        asn,
        country,
        requestCount,
      },
    };
  }
}
