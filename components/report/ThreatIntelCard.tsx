import React from 'react';
import { ThreatIntelResult, ThreatIntelStatus } from '@/types/security';
import { Database, ShieldAlert, CheckCircle2, AlertCircle, HelpCircle } from 'lucide-react';

interface ThreatIntelCardProps {
  results: ThreatIntelResult[];
}

export function ThreatIntelCard({ results }: ThreatIntelCardProps) {
  const getStatusBadge = (status: ThreatIntelStatus, isFlagged: boolean) => {
    if (isFlagged) {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-bold bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/30">
          <ShieldAlert className="w-3.5 h-3.5" /> Blacklisted
        </span>
      );
    }

    switch (status) {
      case 'CLEAN':
      case 'CHECKED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30">
            <CheckCircle2 className="w-3.5 h-3.5" /> Clean / Checked
          </span>
        );
      case 'NOT_CONFIGURED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium bg-slate-100 dark:bg-cyber-800 text-slate-500 dark:text-cyber-400 border border-slate-200 dark:border-cyber-700">
            <HelpCircle className="w-3.5 h-3.5" /> Not Configured
          </span>
        );
      case 'UNAVAILABLE':
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/30">
            <AlertCircle className="w-3.5 h-3.5" /> Unavailable
          </span>
        );
    }
  };

  return (
    <div className="p-6 sm:p-8 rounded-2xl bg-white dark:bg-cyber-900 border border-slate-200 dark:border-cyber-800 shadow-sm space-y-6">
      <div className="flex items-center justify-between border-b border-slate-100 dark:border-cyber-800 pb-4">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-xl bg-indigo-500/10 dark:bg-indigo-500/20 text-indigo-600 dark:text-indigo-400">
            <Database className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base sm:text-lg font-bold text-slate-900 dark:text-white">
              Threat Intelligence Feeds
            </h3>
            <p className="text-xs text-slate-500 dark:text-cyber-400">
              Modular reputation feeds. Unconfigured providers are honestly identified.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {results.map((item) => (
          <div
            key={item.providerName}
            className={`p-4 rounded-xl border transition-all ${
              item.isFlagged
                ? 'bg-rose-50/40 dark:bg-rose-950/20 border-rose-300 dark:border-rose-800'
                : 'bg-slate-50/40 dark:bg-cyber-950/40 border-slate-200/80 dark:border-cyber-800'
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <h4 className="text-sm font-bold text-slate-900 dark:text-white">
                {item.providerName}
              </h4>
              {getStatusBadge(item.status, item.isFlagged)}
            </div>

            <p className="text-xs text-slate-600 dark:text-cyber-300 leading-relaxed">
              {item.details || 'No additional threat telemetry reported.'}
            </p>

            {item.lastChecked && (
              <div className="mt-2 text-[10px] font-mono text-slate-400 dark:text-cyber-500">
                Checked: {new Date(item.lastChecked).toLocaleTimeString()}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
