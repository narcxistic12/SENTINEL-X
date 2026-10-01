'use client';

import React, { useState, useEffect, Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import { UrlScannerInput } from '@/components/scanner/UrlScannerInput';
import { ScanProgressStages } from '@/components/scanner/ScanProgressStages';
import { SecurityReportView } from '@/components/scanner/SecurityReportView';
import { ScanReport } from '@/types/security';
import { saveScanReport } from '@/lib/storage/scan-storage';
import { Shield, AlertTriangle } from 'lucide-react';

function ScannerContent() {
  const searchParams = useSearchParams();
  const initialUrl = searchParams.get('url') || '';

  const [isScanning, setIsScanning] = useState(false);
  const [currentStage, setCurrentStage] = useState(0);
  const [targetUrl, setTargetUrl] = useState(initialUrl);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  const executeScan = async (urlToScan: string) => {
    setTargetUrl(urlToScan);
    setIsScanning(true);
    setReport(null);
    setError(null);
    setCurrentStage(0);

    const stageTimer = setInterval(() => {
      setCurrentStage((prev) => (prev < 6 ? prev + 1 : prev));
    }, 450);

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: urlToScan }),
      });

      clearInterval(stageTimer);
      setCurrentStage(7);

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || `Scan error (${res.status})`);
      }

      setTimeout(() => {
        setReport(data as ScanReport);
        saveScanReport(data as ScanReport);
        setIsScanning(false);
      }, 500);
    } catch (err: unknown) {
      clearInterval(stageTimer);
      setIsScanning(false);
      setError(err instanceof Error ? err.message : 'Analysis failed. Please check network connection.');
    }
  };

  useEffect(() => {
    if (initialUrl && !report && !isScanning) {
      executeScan(initialUrl);
    }
  }, [initialUrl]);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10 space-y-10">
      {/* Header */}
      <div className="text-center space-y-3 max-w-2xl mx-auto">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyber-500/10 text-cyber-700 dark:text-cyber-300 text-xs font-mono">
          <Shield className="w-3.5 h-3.5" />
          <span>Automated URL Threat Analysis</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold font-mono text-slate-900 dark:text-white tracking-tight">
          Security URL Scanner
        </h1>
        <p className="text-sm text-slate-600 dark:text-cyber-300">
          Enter any HTTP or HTTPS link to inspect certificate health, DNS records, lexical anomalies, and phishing indicators.
        </p>
      </div>

      {/* Input Form */}
      <div className="max-w-3xl mx-auto">
        <UrlScannerInput
          onScan={executeScan}
          isLoading={isScanning}
          initialValue={initialUrl}
          size="hero"
        />

        {error && (
          <div className="mt-4 p-4 rounded-xl border border-rose-300 dark:border-rose-900/60 bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-300 text-sm flex items-center gap-3 animate-in fade-in">
            <AlertTriangle className="w-5 h-5 flex-shrink-0 text-rose-500" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Dynamic View: Progress vs Report vs Empty */}
      <div className="pt-4">
        {isScanning ? (
          <ScanProgressStages currentStageIndex={currentStage} targetUrl={targetUrl} />
        ) : report ? (
          <SecurityReportView report={report} onRescan={() => setReport(null)} />
        ) : (
          <div className="max-w-xl mx-auto text-center py-12 px-6 rounded-2xl border border-dashed border-slate-300 dark:border-cyber-800 text-slate-400 dark:text-cyber-500 text-xs font-mono space-y-2">
            <p>Ready to inspect. Enter a URL above or pick a sample link to begin.</p>
            <p className="text-[11px] text-slate-400">
              Analysis evaluates over 20 distinct risk signals in real-time.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

export default function ScannerPage() {
  return (
    <Suspense fallback={<div className="text-center py-20 text-xs font-mono text-slate-400">Loading Scanner...</div>}>
      <ScannerContent />
    </Suspense>
  );
}
