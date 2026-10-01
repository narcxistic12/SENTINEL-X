'use client';

import React, { useState } from 'react';
import { ScanReport } from '@/types/security';
import { RiskGauge } from '@/components/ui/RiskGauge';
import { VerdictBadge } from '@/components/ui/VerdictBadge';
import { ConfidenceBadge } from '@/components/ui/ConfidenceBadge';
import { ExplainableSignals } from '@/components/report/ExplainableSignals';
import { UrlStructureCard } from '@/components/report/UrlStructureCard';
import { DomainIntelCard } from '@/components/report/DomainIntelCard';
import { SslSecurityCard } from '@/components/report/SslSecurityCard';
import { RedirectChainCard } from '@/components/report/RedirectChainCard';
import { ThreatIntelCard } from '@/components/report/ThreatIntelCard';
import { MlFeatureVectorCard } from '@/components/report/MlFeatureVectorCard';
import { CoverageMatrix } from '@/components/report/CoverageMatrix';
import {
  Share2,
  Download,
  RotateCcw,
  Check,
  Calendar,
  Clock,
  ExternalLink,
  Shield,
} from 'lucide-react';

interface SecurityReportViewProps {
  report: ScanReport;
  onRescan?: () => void;
}

export function SecurityReportView({ report, onRescan }: SecurityReportViewProps) {
  const [copied, setCopied] = useState(false);

  const handleCopyLink = async () => {
    try {
      await navigator.clipboard.writeText(window.location.href);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // ignore
    }
  };

  const handleDownloadJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(report, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `sentinelx_report_${report.id}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="w-full max-w-5xl mx-auto space-y-8 animate-in fade-in duration-500 pb-16">
      {/* Top Section: Verdict Banner & Risk Gauge */}
      <div className="relative overflow-hidden rounded-3xl bg-white dark:bg-cyber-900 border border-slate-200 dark:border-cyber-750 shadow-xl">
        {/* Subtle Background Accent Glow */}
        <div
          className="absolute -top-24 -right-24 w-96 h-96 rounded-full blur-3xl pointer-events-none opacity-20"
          style={{
            backgroundColor:
              report.riskScore >= 80
                ? '#ef4444'
                : report.riskScore >= 60
                ? '#f97316'
                : report.riskScore >= 40
                ? '#f59e0b'
                : '#10b981',
          }}
        />

        <div className="p-6 sm:p-10 flex flex-col md:flex-row items-center justify-between gap-8 relative z-10">
          <div className="space-y-4 max-w-xl text-center md:text-left">
            <div className="flex flex-wrap items-center justify-center md:justify-start gap-2">
              <span className="text-xs font-mono font-bold tracking-wider uppercase text-slate-400 dark:text-cyber-400">
                Security Assessment:
              </span>
              <VerdictBadge verdict={report.verdict} size="lg" />
            </div>

            <div className="p-3 rounded-xl bg-slate-50 dark:bg-cyber-950/80 border border-slate-200/80 dark:border-cyber-800 font-mono text-xs break-all text-slate-800 dark:text-white flex items-center gap-2">
              <Shield className="w-4 h-4 text-cyber-500 flex-shrink-0" />
              <span className="truncate">{report.normalizedUrl}</span>
            </div>

            <p className="text-sm text-slate-600 dark:text-cyber-200 leading-relaxed font-medium">
              {report.summary}
            </p>

            {/* Confidence Badge & Scan Meta */}
            <div className="flex flex-wrap items-center justify-center md:justify-start gap-4 pt-2">
              <ConfidenceBadge confidence={report.confidenceScore} />
              <div className="flex items-center gap-3 text-xs font-mono text-slate-400 dark:text-cyber-500">
                <span className="flex items-center gap-1">
                  <Clock className="w-3.5 h-3.5" />
                  {report.durationMs}ms
                </span>
                <span className="flex items-center gap-1">
                  <Calendar className="w-3.5 h-3.5" />
                  {new Date(report.scanTimestamp).toLocaleTimeString()}
                </span>
              </div>
            </div>
          </div>

          {/* Animated Circular Risk Gauge */}
          <div className="flex-shrink-0 flex flex-col items-center">
            <RiskGauge score={report.riskScore} verdict={report.verdict} size={190} strokeWidth={15} />
          </div>
        </div>

        {/* Action Toolbar */}
        <div className="px-6 py-3.5 bg-slate-50 dark:bg-cyber-950/80 border-t border-slate-100 dark:border-cyber-800/80 flex flex-wrap items-center justify-between gap-3 text-xs font-medium">
          <span className="text-slate-500 dark:text-cyber-400 font-mono">
            Scan ID: <strong className="text-slate-800 dark:text-cyber-200">{report.id}</strong>
          </span>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopyLink}
              type="button"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-cyber-750 bg-white dark:bg-cyber-850 text-slate-700 dark:text-cyber-200 hover:bg-slate-100 dark:hover:bg-cyber-800 transition-colors"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Share2 className="w-3.5 h-3.5" />}
              <span>{copied ? 'Link Copied' : 'Share Report'}</span>
            </button>

            <button
              onClick={handleDownloadJson}
              type="button"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-cyber-750 bg-white dark:bg-cyber-850 text-slate-700 dark:text-cyber-200 hover:bg-slate-100 dark:hover:bg-cyber-800 transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export JSON</span>
            </button>

            {onRescan && (
              <button
                onClick={onRescan}
                type="button"
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyber-600 hover:bg-cyber-500 text-white font-semibold transition-colors"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>New Scan</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Coverage Matrix */}
      <CoverageMatrix coverage={report.coverage} />

      {/* Explainable Signals (Why this URL received this score) */}
      <ExplainableSignals signals={report.signals} />

      {/* Deep-Dive Technical Detail Cards */}
      <div className="grid grid-cols-1 gap-8">
        <UrlStructureCard features={report.urlFeatures} />
        <DomainIntelCard intel={report.domainIntel} />
        <SslSecurityCard ssl={report.sslIntel} />
        <RedirectChainCard redirects={report.redirectIntel} />
        <ThreatIntelCard results={report.threatIntel} />
        <MlFeatureVectorCard ml={report.mlDetection} />
      </div>
    </div>
  );
}
