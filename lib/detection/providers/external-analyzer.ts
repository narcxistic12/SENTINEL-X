import { ExternalAnalysisResult } from '@/types/security';
import { URLScanProvider } from './urlscan';
import { AnyRunProvider } from './anyrun';
import { CloudflareUrlScannerProvider } from './cloudflare-url-scanner';
import { UrlscansProvider } from './urlscans';
import { VirusTotalFreshProvider } from './virustotal-fresh';

export interface ExternalAnalysisResults {
  urlscanResult?: ExternalAnalysisResult;
  anyrunResult?: ExternalAnalysisResult;
  cloudflareResult?: ExternalAnalysisResult;
  urlscansResult?: ExternalAnalysisResult;
  virustotalFreshResult?: ExternalAnalysisResult;
  allResults: ExternalAnalysisResult[];
}

export async function runExternalWebAnalysis(url: string): Promise<ExternalAnalysisResults> {
  const urlscanProvider = new URLScanProvider();
  const anyrunProvider = new AnyRunProvider();
  const cloudflareProvider = new CloudflareUrlScannerProvider();
  const urlscansProvider = new UrlscansProvider();
  const vtFreshProvider = new VirusTotalFreshProvider();

  const [urlscanRes, anyrunRes, cfRes, urlscansRes, vtFreshRes] = await Promise.allSettled([
    urlscanProvider.analyze(url),
    anyrunProvider.analyze(url),
    cloudflareProvider.analyze(url),
    urlscansProvider.analyze(url),
    vtFreshProvider.analyze(url),
  ]);

  const urlscanResult: ExternalAnalysisResult =
    urlscanRes.status === 'fulfilled'
      ? urlscanRes.value
      : {
          providerName: 'URLscan',
          status: 'UNAVAILABLE',
          isFlagged: false,
          details: urlscanRes.reason instanceof Error ? urlscanRes.reason.message : 'URLscan provider error',
          evidence: [],
        };

  const anyrunResult: ExternalAnalysisResult =
    anyrunRes.status === 'fulfilled'
      ? anyrunRes.value
      : {
          providerName: 'ANY.RUN',
          status: 'UNAVAILABLE',
          isFlagged: false,
          details: anyrunRes.reason instanceof Error ? anyrunRes.reason.message : 'ANY.RUN provider error',
          evidence: [],
        };

  const cloudflareResult: ExternalAnalysisResult =
    cfRes.status === 'fulfilled'
      ? cfRes.value
      : {
          providerName: 'Cloudflare URL Scanner',
          status: 'UNAVAILABLE',
          isFlagged: false,
          details: cfRes.reason instanceof Error ? cfRes.reason.message : 'Cloudflare provider error',
          evidence: [],
        };

  const urlscansResult: ExternalAnalysisResult =
    urlscansRes.status === 'fulfilled'
      ? urlscansRes.value
      : {
          providerName: 'URLScans',
          status: 'UNAVAILABLE',
          isFlagged: false,
          details: urlscansRes.reason instanceof Error ? urlscansRes.reason.message : 'URLScans provider error',
          evidence: [],
        };

  const virustotalFreshResult: ExternalAnalysisResult =
    vtFreshRes.status === 'fulfilled'
      ? vtFreshRes.value
      : {
          providerName: 'VirusTotal Fresh Analysis',
          status: 'UNAVAILABLE',
          isFlagged: false,
          details: vtFreshRes.reason instanceof Error ? vtFreshRes.reason.message : 'VirusTotal Fresh Analysis provider error',
          evidence: [],
        };

  return {
    urlscanResult,
    anyrunResult,
    cloudflareResult,
    urlscansResult,
    virustotalFreshResult,
    allResults: [urlscanResult, anyrunResult, cloudflareResult, urlscansResult, virustotalFreshResult],
  };
}
