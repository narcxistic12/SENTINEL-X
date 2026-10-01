import { PageContentAnalysisResult } from '@/types/security';

export interface PageContentAnalyzer {
  analyze(url: string, htmlSnippet?: string): Promise<PageContentAnalysisResult>;
}

/**
 * Safe Page Content Analyzer Architecture.
 * Prepares backend infrastructure for future secure page content analysis
 * while strictly maintaining SSRF protections, non-blocking behavior,
 * and zero credential submission / JS execution safety guarantees.
 */
export class SafePageContentAnalyzer implements PageContentAnalyzer {
  public async analyze(url: string, htmlSnippet?: string): Promise<PageContentAnalysisResult> {
    if (!htmlSnippet) {
      return {
        status: 'DISABLED',
        note: 'Webpage HTML content analysis disabled for passive scan pipeline. SSRF and execution safety preserved.',
      };
    }

    try {
      const lowerHtml = htmlSnippet.toLowerCase();
      const hasLoginForm = lowerHtml.includes('<form') && (lowerHtml.includes('login') || lowerHtml.includes('signin') || lowerHtml.includes('auth'));
      const hasPasswordField = lowerHtml.includes('type="password"') || lowerHtml.includes("type='password'");
      const hasPaymentForm = lowerHtml.includes('cardnumber') || lowerHtml.includes('cvv') || lowerHtml.includes('expiration');

      return {
        status: 'AVAILABLE',
        hasLoginForm,
        hasPasswordField,
        hasPaymentForm,
        note: 'Static HTML snippet analyzed safely without JS execution.',
      };
    } catch {
      return {
        status: 'UNAVAILABLE',
        note: 'Failed to analyze page content snippet.',
      };
    }
  }
}
