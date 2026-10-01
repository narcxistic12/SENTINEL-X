'use client';

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import {
  getStoredScans,
  computeDashboardMetrics,
  DashboardMetrics,
} from '@/lib/storage/scan-storage';
import { DashboardMetricsCards } from '@/components/dashboard/DashboardMetricsCards';
import { ThreatDistributionChart } from '@/components/dashboard/ThreatDistributionChart';
import { RecentScansList } from '@/components/dashboard/RecentScansList';
import { EmptyState } from '@/components/ui/EmptyState';
import { ScanReport } from '@/types/security';
import { Activity, Shield, Sparkles } from 'lucide-react';

export default function DashboardPage() {
  const router = useRouter();
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [scans, setScans] = useState<ScanReport[]>([]);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    const loadScans = async () => {
      const stored = await import('@/lib/storage/scan-storage').then(m => m.fetchStoredScans());
      setScans(stored);
      setMetrics(computeDashboardMetrics(stored));
    };
    loadScans();
  }, []);

  const handleSelectScan = (scan: ScanReport) => {
    router.push(`/scanner?url=${encodeURIComponent(scan.normalizedUrl)}`);
  };

  if (!mounted || !metrics) {
    return (
      <div className="max-w-7xl mx-auto px-4 py-20 text-center font-mono text-xs text-slate-400">
        Loading Threat Operations Dashboard...
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10 space-y-10">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-200 dark:border-cyber-800 pb-6">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyber-500/10 text-cyber-700 dark:text-cyber-300 text-xs font-mono mb-2">
            <Activity className="w-3.5 h-3.5" />
            <span>Security Operations Center Telemetry</span>
          </div>
          <h1 className="text-3xl font-extrabold font-mono text-slate-900 dark:text-white tracking-tight">
            Threat Intelligence Dashboard
          </h1>
          <p className="text-xs sm:text-sm text-slate-500 dark:text-cyber-400 mt-1">
            Aggregated metrics, historical threat distribution, and risk telemetry across analyzed URLs.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => router.push('/scanner')}
            type="button"
            className="px-4 py-2.5 rounded-xl bg-cyber-600 hover:bg-cyber-500 text-white font-semibold text-xs transition-colors flex items-center gap-2 shadow-md"
          >
            <Shield className="w-4 h-4" />
            <span>New URL Scan</span>
          </button>
        </div>
      </div>

      {metrics.totalScans === 0 ? (
        <EmptyState
          title="No scan data recorded yet"
          description="Start by analyzing your first URL. All scan assessments, risk calculations, and threat distributions will automatically populate here."
          actionText="Launch URL Scanner"
          actionHref="/scanner"
        />
      ) : (
        <div className="space-y-8">
          {/* 1. Key Metric Cards */}
          <DashboardMetricsCards metrics={metrics} />

          {/* 2. Threat Distribution Chart */}
          <ThreatDistributionChart metrics={metrics} />

          {/* 3. Recent Scans Stream */}
          <RecentScansList scans={metrics.recentScans} onSelectScan={handleSelectScan} />
        </div>
      )}
    </div>
  );
}
