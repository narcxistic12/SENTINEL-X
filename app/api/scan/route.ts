import { NextRequest, NextResponse } from 'next/server';
import { sanitizeAndNormalizeUrl } from '@/lib/security/sanitize';
import { validateUrlSsrf } from '@/lib/security/ssrf';
import { globalRateLimiter } from '@/lib/security/rate-limiter';
import { extractUrlFeatures } from '@/lib/detection/url-features';
import { analyzeDomain } from '@/lib/detection/domain-analyzer';
import { analyzeDomainRegistration } from '@/lib/detection/domain-age';
import { analyzeSsl } from '@/lib/detection/ssl-analyzer';
import { analyzeRedirects } from '@/lib/detection/redirect-analyzer';
import { runThreatIntelligenceChecks } from '@/lib/detection/providers/threat-intel';
import { runExternalWebAnalysis } from '@/lib/detection/providers/external-analyzer';
import { MLDetector } from '@/lib/detection/providers/ml-detector';
import { SafePageContentAnalyzer } from '@/lib/detection/page-content-analyzer';
import { calculateRiskScore } from '@/lib/scoring/risk-engine';
import { AnalysisCoverage, ScanReport } from '@/types/security';
import prisma from '@/lib/prisma';

export const dynamic = 'force-dynamic';
export const maxDuration = 15; // Vercel serverless function timeout allowance

export async function POST(req: NextRequest) {
  const startTime = Date.now();

  try {
    // 1. Rate Limiting Check
    const clientIp =
      req.headers.get('x-forwarded-for')?.split(',')[0].trim() ||
      req.headers.get('x-real-ip') ||
      '127.0.0.1';

    const rateLimit = await globalRateLimiter.check(clientIp);
    if (!rateLimit.allowed) {
      return NextResponse.json(
        {
          error: 'Rate limit exceeded. Please wait before submitting another security scan.',
          retryAfterSeconds: rateLimit.retryAfterSeconds,
        },
        {
          status: 429,
          headers: {
            'Retry-After': String(rateLimit.retryAfterSeconds),
            'X-RateLimit-Limit': String(rateLimit.limit),
            'X-RateLimit-Remaining': '0',
          },
        }
      );
    }

    // 2. Body parsing and client input validation
    let body: { url?: unknown };
    try {
      body = await req.json();
    } catch {
      return NextResponse.json(
        { error: 'Invalid JSON request payload. Expected { "url": "..." }' },
        { status: 400 }
      );
    }

    if (!body || typeof body.url !== 'string') {
      return NextResponse.json(
        { error: 'A valid "url" string property is required.' },
        { status: 400 }
      );
    }

    // 3. Sanitization & Normalization
    const sanitizeResult = sanitizeAndNormalizeUrl(body.url);
    if (!sanitizeResult.isValid) {
      return NextResponse.json(
        { error: sanitizeResult.error || 'Invalid URL provided.' },
        { status: 400 }
      );
    }

    const normalizedUrl = sanitizeResult.normalizedUrl;
    const parsed = new URL(normalizedUrl);
    const hostname = parsed.hostname;
    const isHttps = parsed.protocol === 'https:';
    const port = parsed.port ? parseInt(parsed.port, 10) : isHttps ? 443 : 80;

    // 4. SSRF & Target Validation Guard
    const ssrfCheck = await validateUrlSsrf(normalizedUrl);
    if (!ssrfCheck.isSafe) {
      return NextResponse.json(
        {
          error: ssrfCheck.reason || 'Access to this host or address is restricted by security policy.',
          code: 'SSRF_BLOCKED',
        },
        { status: 403 }
      );
    }

    // 5. Sequential & Parallel Security Analysis Pipeline
    // Resolving redirects must happen before Threat Intelligence
    const redirectIntel = await analyzeRedirects(normalizedUrl);
    const urlsToScan = Array.from(new Set([
      normalizedUrl,
      ...redirectIntel.hops.map((hop) => hop.targetUrl)
    ]));

    const [urlFeatures, domainIntel, domainRegIntel, sslIntel, threatIntel, externalAnalysis] =
      await Promise.all([
        Promise.resolve(extractUrlFeatures(body.url, normalizedUrl)),
        analyzeDomain(hostname),
        analyzeDomainRegistration(hostname),
        analyzeSsl(hostname, port, isHttps),
        runThreatIntelligenceChecks(urlsToScan),
        runExternalWebAnalysis(normalizedUrl),
      ]);

    // Page content analyzer architecture check
    const pageContentAnalyzer = new SafePageContentAnalyzer();
    const pageContentIntel = await pageContentAnalyzer.analyze(normalizedUrl);

    // 6. ML Model Feature Vector Extraction & Inference Check
    const mlDetector = new MLDetector();
    const mlDetection = await mlDetector.detect(urlFeatures);

    // 7. Multi-Signal Explainable Risk Calculation
    const scoreResult = calculateRiskScore({
      urlFeatures,
      domainIntel,
      domainRegIntel,
      sslIntel,
      redirectIntel,
      threatIntel,
      mlResult: mlDetection,
      pageContentIntel,
      urlscanResult: externalAnalysis.urlscanResult,
      anyrunResult: externalAnalysis.anyrunResult,
      cloudflareResult: externalAnalysis.cloudflareResult,
      urlscansResult: externalAnalysis.urlscansResult,
      virustotalFreshResult: externalAnalysis.virustotalFreshResult,
    });

    // 8. Determine Analysis Coverage Honestly
    const coverage: AnalysisCoverage = {
      urlStructure: 'CHECKED',
      domainIntelligence: domainIntel.isResolvable ? 'CHECKED' : 'UNAVAILABLE',
      sslTls: isHttps ? (sslIntel.protocol ? 'CHECKED' : 'UNAVAILABLE') : 'NOT_APPLICABLE',
      redirects: redirectIntel.error ? 'UNAVAILABLE' : 'CHECKED',
      threatIntelligence: threatIntel.some((t) => t.status === 'NOT_CONFIGURED')
        ? 'NOT_CONFIGURED'
        : 'CHECKED',
      mlDetection: mlDetection.status === 'NOT_CONFIGURED' ? 'NOT_CONFIGURED' : 'CHECKED',
      externalAnalysis: externalAnalysis.allResults.some((r) => r.status === 'CLEAN' || r.status === 'FLAGGED')
        ? 'CHECKED'
        : externalAnalysis.allResults.some((r) => r.status === 'PENDING')
        ? 'PENDING'
        : externalAnalysis.allResults.some((r) => r.status === 'TIMEOUT')
        ? 'TIMEOUT'
        : 'NOT_CONFIGURED',
    };

    const durationMs = Date.now() - startTime;
    const scanId = `scan_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;

    // Build Provider Status Map and Dynamic Analysis Report
    const providersMap: Record<string, any> = {};
    for (const ti of threatIntel) {
      const key = ti.providerName.toLowerCase().replace(/[^a-z0-9]+/g, '_');
      providersMap[key] = {
        provider: ti.providerName,
        status: ti.status,
        available: ti.status === 'CLEAN' || ti.status === 'FLAGGED' || ti.status === 'CHECKED',
        details: ti.details,
      };
    }
    for (const ext of externalAnalysis.allResults) {
      const key = ext.providerName.toLowerCase().replace(/[^a-z0-9]+/g, '_');
      providersMap[key] = {
        provider: ext.providerName,
        status: ext.status,
        available: ext.status === 'CLEAN' || ext.status === 'FLAGGED',
        scanId: ext.scanUuid,
        reportUrl: ext.resultUrl,
        findingsCount: ext.evidence.length,
        details: ext.details,
      };
    }

    const dynamicAnalysisReport = {
      available: externalAnalysis.allResults.some((r) => r.status === 'CLEAN' || r.status === 'FLAGGED'),
      providers: externalAnalysis.allResults.map((r) => ({
        provider: r.providerName,
        status: r.status,
        available: r.status === 'CLEAN' || r.status === 'FLAGGED',
        scanId: r.scanUuid,
        reportUrl: r.resultUrl,
        findingsCount: r.evidence.length,
        details: r.details,
      })),
      findings: externalAnalysis.allResults.flatMap((r) => r.evidence),
    };

    const report: ScanReport = {
      id: scanId,
      url: body.url,
      normalizedUrl,
      scanTimestamp: new Date().toISOString(),
      durationMs,
      verdict: scoreResult.verdict,
      riskScore: scoreResult.riskScore,
      confidenceScore: scoreResult.confidenceScore,
      riskCategory: scoreResult.riskCategory,
      summary: scoreResult.summary,
      explanation: scoreResult.explanation,
      evidence: scoreResult.evidence,
      signals: scoreResult.signals,
      urlFeatures,
      domainIntel,
      domainRegIntel,
      sslIntel,
      redirectIntel,
      threatIntel,
      mlDetection,
      pageContentIntel,
      urlscanResult: externalAnalysis.urlscanResult,
      anyrunResult: externalAnalysis.anyrunResult,
      cloudflareResult: externalAnalysis.cloudflareResult,
      urlscansResult: externalAnalysis.urlscansResult,
      virustotalFreshResult: externalAnalysis.virustotalFreshResult,
      externalIntel: externalAnalysis.allResults,
      providers: providersMap,
      dynamicAnalysis: dynamicAnalysisReport,
      coverage,
    };

    if (process.env.DATABASE_URL) {
      try {
        const { authenticateRequest } = await import('@/lib/security/auth');
        const authUser = await authenticateRequest(req);

        await prisma.scan.create({
          data: {
            id: scanId,
            url: report.url,
            normalizedUrl: report.normalizedUrl,
            verdict: report.verdict,
            riskScore: report.riskScore,
            confidenceScore: report.confidenceScore,
            summary: report.summary,
            fullReport: report as any,
            userId: authUser?.id || null,
            signals: {
              create: report.signals.map(s => ({
                signalId: s.id,
                title: s.title,
                explanation: s.explanation,
                severity: s.severity,
                status: s.status,
                source: s.source,
                points: s.points,
              }))
            }
          }
        });
      } catch (dbErr) {
        console.error('Failed to save scan to database:', dbErr);
        // Continue and return the report even if DB save fails
      }
    }

    return NextResponse.json(report, {
      status: 200,
      headers: {
        'Cache-Control': 'no-store, max-age=0',
        'X-RateLimit-Limit': String(rateLimit.limit),
        'X-RateLimit-Remaining': String(rateLimit.remaining),
      },
    });
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : 'Internal scan error';
    return NextResponse.json(
      {
        error: 'An unexpected error occurred during security analysis.',
        details: process.env.NODE_ENV === 'development' ? errorMsg : undefined,
      },
      { status: 500 }
    );
  }
}
