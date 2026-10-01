import React from 'react';
import { DashboardMetrics } from '@/lib/storage/scan-storage';
import { PieChart, Shield } from 'lucide-react';

interface ThreatDistributionChartProps {
  metrics: DashboardMetrics;
}

export function ThreatDistributionChart({ metrics }: ThreatDistributionChartProps) {
  const dist = metrics.verdictDistribution;
  const total = metrics.totalScans || 1;

  const categories = [
    { label: 'Safe', count: dist.SAFE, color: 'bg-emerald-500', barColor: '#10b981' },
    { label: 'Low Risk', count: dist.LOW_RISK, color: 'bg-sky-500', barColor: '#0ea5e9' },
    { label: 'Suspicious', count: dist.SUSPICIOUS, color: 'bg-amber-500', barColor: '#f59e0b' },
    { label: 'High Risk', count: dist.HIGH_RISK, color: 'bg-orange-500', barColor: '#f97316' },
    { label: 'Critical', count: dist.CRITICAL, color: 'bg-rose-500', barColor: '#ef4444' },
  ];

  return (
    <div className="p-6 sm:p-8 rounded-2xl bg-white dark:bg-cyber-900 border border-slate-200 dark:border-cyber-800 shadow-sm space-y-6">
      <div className="flex items-center justify-between border-b border-slate-100 dark:border-cyber-800 pb-4">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-xl bg-cyber-500/10 dark:bg-cyber-500/20 text-cyber-600 dark:text-cyber-300">
            <PieChart className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base sm:text-lg font-bold text-slate-900 dark:text-white">
              Threat Verdict Distribution
            </h3>
            <p className="text-xs text-slate-500 dark:text-cyber-400">
              Categorical proportion of historical scans evaluated.
            </p>
          </div>
        </div>
      </div>

      {/* Stacked Proportional Bar */}
      <div className="space-y-2">
        <div className="w-full h-4 rounded-full bg-slate-100 dark:bg-cyber-950 overflow-hidden flex">
          {categories.map((cat) => {
            const pct = (cat.count / total) * 100;
            if (pct === 0) return null;
            return (
              <div
                key={cat.label}
                style={{ width: `${pct}%`, backgroundColor: cat.barColor }}
                title={`${cat.label}: ${cat.count} (${pct.toFixed(1)}%)`}
                className="h-full transition-all duration-500"
              />
            );
          })}
        </div>
      </div>

      {/* Legend & Count Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 pt-2">
        {categories.map((cat) => {
          const pct = Math.round((cat.count / total) * 100);
          return (
            <div
              key={cat.label}
              className="p-3 rounded-xl border border-slate-100 dark:border-cyber-800 bg-slate-50/50 dark:bg-cyber-850/50 space-y-1"
            >
              <div className="flex items-center gap-2">
                <span className={`w-2.5 h-2.5 rounded-full ${cat.color}`} />
                <span className="text-xs font-semibold text-slate-700 dark:text-cyber-200">
                  {cat.label}
                </span>
              </div>
              <div className="flex items-baseline justify-between font-mono">
                <span className="text-lg font-bold text-slate-900 dark:text-white">{cat.count}</span>
                <span className="text-[11px] text-slate-400 dark:text-cyber-500">{pct}%</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
