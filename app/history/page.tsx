'use client';

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { getStoredScans } from '@/lib/storage/scan-storage';
import { HistoryManager } from '@/components/history/HistoryManager';
import { EmptyState } from '@/components/ui/EmptyState';
import { ScanReport } from '@/types/security';
import { History, Shield } from 'lucide-react';

export default function HistoryPage() {
  const router = useRouter();
  const [scans, setScans] = useState<ScanReport[]>([]);
  const [mounted, setMounted] = useState(false);

  const refreshScans = async () => {
    const { fetchStoredScans } = await import('@/lib/storage/scan-storage');
    setScans(await fetchStoredScans());
  };

  useEffect(() => {
    setMounted(true);
    refreshScans();
  }, []);

  const handleSelectScan = (scan: ScanReport) => {
    router.push(`/scanner?url=${encodeURIComponent(scan.normalizedUrl)}`);
  };

  if (!mounted) {
    return (
      <div className="max-w-7xl mx-auto px-4 py-20 text-center font-mono text-xs text-slate-400">
        Loading Scan History...
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10 space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-200 dark:border-cyber-800 pb-6">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyber-500/10 text-cyber-700 dark:text-cyber-300 text-xs font-mono mb-2">
            <History className="w-3.5 h-3.5" />
            <span>Audit Trail & Records</span>
          </div>
          <h1 className="text-3xl font-extrabold font-mono text-slate-900 dark:text-white tracking-tight">
            Security Scan History
          </h1>
          <p className="text-xs sm:text-sm text-slate-500 dark:text-cyber-400 mt-1">
            Search, filter, export, and inspect full security reports from your previous analyses.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => router.push('/scanner')}
            type="button"
            className="px-4 py-2.5 rounded-xl bg-cyber-600 hover:bg-cyber-500 text-white font-semibold text-xs transition-colors flex items-center gap-2 shadow-md"
          >
            <Shield className="w-4 h-4" />
            <span>Scan New URL</span>
          </button>
        </div>
      </div>

      {scans.length === 0 ? (
        <EmptyState
          title="No scans stored in history"
          description="Your scan history is empty. Analyze a URL with the scanner to begin keeping an audit log."
          actionText="Open URL Scanner"
          actionHref="/scanner"
        />
      ) : (
        <HistoryManager
          initialScans={scans}
          onSelectScan={handleSelectScan}
          onRefresh={refreshScans}
        />
      )}
    </div>
  );
}
