import React from 'react';
import { AnalysisCoverage } from '@/types/security';
import { CheckCircle2, AlertCircle, HelpCircle, ShieldCheck } from 'lucide-react';

interface CoverageMatrixProps {
  coverage: AnalysisCoverage;
}

export function CoverageMatrix({ coverage }: CoverageMatrixProps) {
  const items = [
    { label: 'URL Structure Analysis', status: coverage.urlStructure },
    { label: 'Domain & DNS Intelligence', status: coverage.domainIntelligence },
    { label: 'SSL / TLS Inspection', status: coverage.sslTls },
    { label: 'Redirect Chain Follower', status: coverage.redirects },
    { label: 'Threat Intelligence Feeds', status: coverage.threatIntelligence },
    { label: 'Machine Learning Classification', status: coverage.mlDetection },
  ];

  const renderBadge = (status: string) => {
    switch (status) {
      case 'CHECKED':
        return (
          <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-emerald-600 dark:text-emerald-400">
            <CheckCircle2 className="w-3.5 h-3.5" /> Checked
          </span>
        );
      case 'NOT_CONFIGURED':
        return (
          <span className="inline-flex items-center gap-1 text-[11px] font-medium text-slate-500 dark:text-cyber-400">
            <HelpCircle className="w-3.5 h-3.5" /> Not Configured
          </span>
        );
      case 'NOT_APPLICABLE':
        return (
          <span className="inline-flex items-center gap-1 text-[11px] font-medium text-slate-400 dark:text-cyber-500">
            N/A (HTTP)
          </span>
        );
      case 'UNAVAILABLE':
      case 'FAILED':
      default:
        return (
          <span className="inline-flex items-center gap-1 text-[11px] font-medium text-amber-600 dark:text-amber-400">
            <AlertCircle className="w-3.5 h-3.5" /> Unavailable
          </span>
        );
    }
  };

  return (
    <div className="p-6 rounded-2xl bg-slate-50/70 dark:bg-cyber-900/60 border border-slate-200/80 dark:border-cyber-800">
      <div className="flex items-center gap-2 mb-4">
        <ShieldCheck className="w-4 h-4 text-cyber-500" />
        <h4 className="text-xs font-bold uppercase tracking-wider font-mono text-slate-900 dark:text-white">
          Analysis Coverage Transparency
        </h4>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
        {items.map((item) => (
          <div
            key={item.label}
            className="p-3 rounded-xl border border-slate-200/60 dark:border-cyber-800/80 bg-white dark:bg-cyber-950/60 flex items-center justify-between gap-2"
          >
            <span className="text-xs font-medium text-slate-700 dark:text-cyber-200 truncate">
              {item.label}
            </span>
            <div className="flex-shrink-0">{renderBadge(item.status)}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
