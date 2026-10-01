import React from 'react';
import Link from 'next/link';
import { ScanReport } from '@/types/security';
import { VerdictBadge } from '@/components/ui/VerdictBadge';
import { ArrowUpRight, Clock, Shield } from 'lucide-react';

interface RecentScansListProps {
  scans: ScanReport[];
  onSelectScan?: (scan: ScanReport) => void;
}

export function RecentScansList({ scans, onSelectScan }: RecentScansListProps) {
  return (
    <div className="p-6 sm:p-8 rounded-2xl bg-white dark:bg-cyber-900 border border-slate-200 dark:border-cyber-800 shadow-sm space-y-4">
      <div className="flex items-center justify-between border-b border-slate-100 dark:border-cyber-800 pb-4">
        <div>
          <h3 className="text-base sm:text-lg font-bold text-slate-900 dark:text-white">
            Recent Security Analyses
          </h3>
          <p className="text-xs text-slate-500 dark:text-cyber-400">
            Chronological audit log of scanned endpoints.
          </p>
        </div>
        <Link
          href="/history"
          className="text-xs font-semibold text-cyber-600 dark:text-cyber-400 hover:underline flex items-center gap-1"
        >
          <span>View All History</span>
          <ArrowUpRight className="w-3.5 h-3.5" />
        </Link>
      </div>

      <div className="divide-y divide-slate-100 dark:divide-cyber-800/80">
        {scans.map((scan) => (
          <div
            key={scan.id}
            className="py-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-slate-50/50 dark:hover:bg-cyber-850/40 p-2 rounded-xl transition-colors"
          >
            <div className="flex items-start gap-3 min-w-0">
              <div className="p-2 rounded-lg bg-slate-100 dark:bg-cyber-800 text-slate-600 dark:text-cyber-300 mt-0.5 flex-shrink-0">
                <Shield className="w-4 h-4" />
              </div>
              <div className="min-w-0">
                <div className="text-sm font-mono font-semibold text-slate-900 dark:text-white truncate max-w-sm sm:max-w-md">
                  {scan.normalizedUrl}
                </div>
                <div className="flex items-center gap-2 text-[11px] text-slate-400 dark:text-cyber-500 mt-0.5">
                  <span className="flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    {new Date(scan.scanTimestamp).toLocaleTimeString()}
                  </span>
                  <span>&bull;</span>
                  <span>Confidence: {scan.confidenceScore}%</span>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-3 self-end sm:self-center">
              <VerdictBadge verdict={scan.verdict} size="sm" />
              <span className="text-xs font-mono font-bold text-slate-700 dark:text-cyber-300 w-16 text-right">
                {scan.riskScore} / 100
              </span>
              {onSelectScan && (
                <button
                  type="button"
                  onClick={() => onSelectScan(scan)}
                  className="p-1.5 rounded-lg border border-slate-200 dark:border-cyber-750 text-slate-600 dark:text-cyber-300 hover:bg-slate-100 dark:hover:bg-cyber-800"
                  title="View Report"
                >
                  <ArrowUpRight className="w-4 h-4" />
                </button>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
