'use client';

import React, { useState } from 'react';
import { SecuritySignal, SignalStatus } from '@/types/security';
import { CheckCircle2, AlertTriangle, XCircle, Info, Filter } from 'lucide-react';

interface ExplainableSignalsProps {
  signals: SecuritySignal[];
}

export function ExplainableSignals({ signals }: ExplainableSignalsProps) {
  const [filter, setFilter] = useState<'all' | 'issues' | 'passed'>('all');

  const filteredSignals = signals.filter((signal) => {
    if (filter === 'issues') return signal.status === 'warning' || signal.status === 'fail';
    if (filter === 'passed') return signal.status === 'pass';
    return true;
  });

  const getStatusIcon = (status: SignalStatus) => {
    switch (status) {
      case 'pass':
        return <CheckCircle2 className="w-5 h-5 text-emerald-500 flex-shrink-0" />;
      case 'warning':
        return <AlertTriangle className="w-5 h-5 text-amber-500 flex-shrink-0" />;
      case 'fail':
        return <XCircle className="w-5 h-5 text-rose-500 flex-shrink-0" />;
      default:
        return <Info className="w-5 h-5 text-sky-500 flex-shrink-0" />;
    }
  };

  const getSeverityBadge = (severity: string) => {
    const map: Record<string, { bg: string; text: string }> = {
      critical: { bg: 'bg-rose-500/10 dark:bg-rose-950/30', text: 'text-rose-700 dark:text-rose-400' },
      high: { bg: 'bg-orange-500/10 dark:bg-orange-950/30', text: 'text-orange-700 dark:text-orange-400' },
      medium: { bg: 'bg-amber-500/10 dark:bg-amber-950/30', text: 'text-amber-700 dark:text-amber-400' },
      low: { bg: 'bg-blue-500/10 dark:bg-blue-950/30', text: 'text-blue-700 dark:text-blue-400' },
      info: { bg: 'bg-slate-500/10 dark:bg-slate-900/40', text: 'text-slate-600 dark:text-slate-400' },
    };
    const c = map[severity] || map.info;
    return (
      <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full ${c.bg} ${c.text}`}>
        {severity}
      </span>
    );
  };

  const getSourceBadge = (source: string) => (
    <span className="text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 rounded bg-slate-100 dark:bg-cyber-800 text-slate-600 dark:text-cyber-300 border border-slate-200 dark:border-cyber-700">
      {source}
    </span>
  );

  return (
    <div className="p-6 sm:p-8 rounded-2xl bg-white dark:bg-cyber-900 border border-slate-200 dark:border-cyber-800 shadow-sm space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-cyber-800 pb-4">
        <div>
          <h3 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
            <span>Explainable Security Signals</span>
            <span className="text-xs font-mono px-2 py-0.5 rounded-full bg-slate-100 dark:bg-cyber-800 text-slate-600 dark:text-cyber-300">
              {signals.length} evaluated
            </span>
          </h3>
          <p className="text-xs text-slate-500 dark:text-cyber-400 mt-0.5">
            Transparent breakdown of why this URL received its risk assessment.
          </p>
        </div>

        {/* Filter Buttons */}
        <div className="flex items-center gap-1.5 p-1 rounded-xl bg-slate-100 dark:bg-cyber-850 border border-slate-200 dark:border-cyber-800 text-xs font-medium">
          <Filter className="w-3.5 h-3.5 text-slate-400 ml-1.5 hidden sm:inline" />
          <button
            onClick={() => setFilter('all')}
            className={`px-3 py-1 rounded-lg transition-all ${
              filter === 'all'
                ? 'bg-white dark:bg-cyber-700 text-slate-900 dark:text-white shadow-sm font-semibold'
                : 'text-slate-600 dark:text-cyber-400 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            All ({signals.length})
          </button>
          <button
            onClick={() => setFilter('issues')}
            className={`px-3 py-1 rounded-lg transition-all ${
              filter === 'issues'
                ? 'bg-white dark:bg-cyber-700 text-slate-900 dark:text-white shadow-sm font-semibold'
                : 'text-slate-600 dark:text-cyber-400 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            Issues ({signals.filter((s) => s.status === 'warning' || s.status === 'fail').length})
          </button>
          <button
            onClick={() => setFilter('passed')}
            className={`px-3 py-1 rounded-lg transition-all ${
              filter === 'passed'
                ? 'bg-white dark:bg-cyber-700 text-slate-900 dark:text-white shadow-sm font-semibold'
                : 'text-slate-600 dark:text-cyber-400 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            Passed ({signals.filter((s) => s.status === 'pass').length})
          </button>
        </div>
      </div>

      {/* Signals List */}
      <div className="space-y-3">
        {filteredSignals.length === 0 ? (
          <div className="text-center py-8 text-sm text-slate-400 dark:text-cyber-400">
            No signals match the selected filter.
          </div>
        ) : (
          filteredSignals.map((signal) => (
            <div
              key={signal.id}
              className={`p-4 rounded-xl border transition-all ${
                signal.status === 'fail'
                  ? 'bg-rose-50/40 dark:bg-rose-950/15 border-rose-200 dark:border-rose-900/40'
                  : signal.status === 'warning'
                  ? 'bg-amber-50/40 dark:bg-amber-950/15 border-amber-200 dark:border-amber-900/40'
                  : 'bg-slate-50/50 dark:bg-cyber-950/30 border-slate-200/80 dark:border-cyber-800'
              }`}
            >
              <div className="flex items-start gap-3">
                <div className="mt-0.5">{getStatusIcon(signal.status)}</div>
                <div className="flex-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2 mb-1">
                    <h4 className="text-sm font-bold text-slate-900 dark:text-white">
                      {signal.title}
                    </h4>
                    {getSeverityBadge(signal.severity)}
                    {getSourceBadge(signal.source)}
                    {signal.points > 0 && (
                      <span className="text-[10px] font-mono text-rose-600 dark:text-rose-400 font-semibold ml-auto">
                        +{signal.points} Risk Pts
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-600 dark:text-cyber-300 leading-relaxed">
                    {signal.explanation}
                  </p>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
