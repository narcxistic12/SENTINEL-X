import React from 'react';
import { DashboardMetrics } from '@/lib/storage/scan-storage';
import { ShieldCheck, ShieldAlert, AlertTriangle, Activity, Gauge } from 'lucide-react';

interface DashboardMetricsCardsProps {
  metrics: DashboardMetrics;
}

export function DashboardMetricsCards({ metrics }: DashboardMetricsCardsProps) {
  const cards = [
    {
      label: 'Total Scans',
      value: metrics.totalScans,
      icon: Activity,
      color: 'text-cyber-500',
      bg: 'bg-cyber-500/10',
      border: 'border-cyber-500/20',
      description: 'URLs analyzed by engine',
    },
    {
      label: 'Threats Detected',
      value: metrics.threatCount,
      icon: ShieldAlert,
      color: 'text-rose-500',
      bg: 'bg-rose-500/10',
      border: 'border-rose-500/20',
      description: 'High risk or malicious targets',
    },
    {
      label: 'Suspicious URLs',
      value: metrics.suspiciousCount,
      icon: AlertTriangle,
      color: 'text-amber-500',
      bg: 'bg-amber-500/10',
      border: 'border-amber-500/20',
      description: 'Anomalies and redirects',
    },
    {
      label: 'Safe / Low Risk',
      value: metrics.safeCount + metrics.lowRiskCount,
      icon: ShieldCheck,
      color: 'text-emerald-500',
      bg: 'bg-emerald-500/10',
      border: 'border-emerald-500/20',
      description: 'Clean infrastructure signals',
    },
    {
      label: 'Avg Risk Score',
      value: `${metrics.averageRiskScore} / 100`,
      icon: Gauge,
      color: 'text-sky-500',
      bg: 'bg-sky-500/10',
      border: 'border-sky-500/20',
      description: 'Across all evaluated scans',
    },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
      {cards.map((card) => {
        const Icon = card.icon;
        return (
          <div
            key={card.label}
            className="p-5 rounded-2xl bg-white dark:bg-cyber-900 border border-slate-200 dark:border-cyber-800 shadow-sm space-y-3"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-500 dark:text-cyber-400">
                {card.label}
              </span>
              <div className={`p-2 rounded-xl ${card.bg} ${card.color} ${card.border} border`}>
                <Icon className="w-4 h-4" />
              </div>
            </div>

            <div>
              <div className="text-2xl font-black font-mono tracking-tight text-slate-900 dark:text-white">
                {card.value}
              </div>
              <p className="text-[11px] text-slate-400 dark:text-cyber-500 mt-0.5">
                {card.description}
              </p>
            </div>
          </div>
        );
      })}
    </div>
  );
}
