import React from 'react';
import { RedirectIntelligence } from '@/types/security';
import { ArrowRightLeft, ShieldCheck, AlertTriangle, ArrowDown } from 'lucide-react';

interface RedirectChainCardProps {
  redirects: RedirectIntelligence;
}

export function RedirectChainCard({ redirects }: RedirectChainCardProps) {
  return (
    <div className="p-6 sm:p-8 rounded-2xl bg-white dark:bg-cyber-900 border border-slate-200 dark:border-cyber-800 shadow-sm space-y-6">
      <div className="flex items-center justify-between border-b border-slate-100 dark:border-cyber-800 pb-4">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-xl bg-purple-500/10 dark:bg-purple-500/20 text-purple-600 dark:text-purple-300">
            <ArrowRightLeft className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base sm:text-lg font-bold text-slate-900 dark:text-white">
              HTTP Redirect Chain Analysis
            </h3>
            <p className="text-xs text-slate-500 dark:text-cyber-400">
              Hop-by-hop resolution path with per-destination SSRF verification.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs font-mono px-2.5 py-1 rounded-full bg-slate-100 dark:bg-cyber-800 text-slate-700 dark:text-cyber-300 font-semibold">
            {redirects.hopCount} redirect hop(s)
          </span>
          <span className="inline-flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
            <ShieldCheck className="w-3 h-3" /> SSRF Shielded
          </span>
        </div>
      </div>

      {redirects.destinationChanged && (
        <div className="p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-start gap-2.5 text-xs text-amber-800 dark:text-amber-300">
          <AlertTriangle className="w-4 h-4 text-amber-500 flex-shrink-0 mt-0.5" />
          <span>
            <strong>Domain Shift Alert:</strong> The initial URL redirects to an entirely different root domain. Verify the final landing address carefully.
          </span>
        </div>
      )}

      {redirects.hops.length === 0 ? (
        <div className="p-4 rounded-xl bg-slate-50/50 dark:bg-cyber-950/40 border border-slate-100 dark:border-cyber-800 text-xs font-mono text-slate-600 dark:text-cyber-300 flex items-center justify-between">
          <span>Direct Destination (No intermediate redirects triggered)</span>
          <span className="text-emerald-600 dark:text-emerald-400 font-semibold flex items-center gap-1">
            <ShieldCheck className="w-4 h-4" /> 200 OK / Direct
          </span>
        </div>
      ) : (
        <div className="relative space-y-3 font-mono text-xs">
          {/* Initial URL Hop 0 */}
          <div className="p-3.5 rounded-xl border border-slate-200 dark:border-cyber-800 bg-slate-50 dark:bg-cyber-950/70">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] uppercase font-bold tracking-wider text-slate-400 dark:text-cyber-500">
                Initial Submission
              </span>
              <span className="px-2 py-0.5 rounded bg-slate-200 dark:bg-cyber-800 text-slate-700 dark:text-cyber-300 text-[10px]">
                Start
              </span>
            </div>
            <div className="text-slate-900 dark:text-cyber-100 break-all">{redirects.originalUrl}</div>
          </div>

          {/* Sequential Hops */}
          {redirects.hops.map((hop) => (
            <div key={hop.hopNumber} className="relative pl-6 space-y-2">
              <div className="flex justify-center -my-1 text-slate-400 dark:text-cyber-600">
                <ArrowDown className="w-4 h-4" />
              </div>
              <div className="p-3.5 rounded-xl border border-cyber-500/20 bg-cyber-500/5 dark:bg-cyber-950">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] uppercase font-bold tracking-wider text-cyber-600 dark:text-cyber-400">
                    Hop #{hop.hopNumber} (HTTP {hop.statusCode})
                  </span>
                  <span className="text-[10px] text-slate-400 dark:text-cyber-500">
                    {hop.durationMs}ms
                  </span>
                </div>
                <div className="text-slate-900 dark:text-white break-all">{hop.targetUrl}</div>
              </div>
            </div>
          ))}

          {/* Final Target */}
          <div className="pt-2">
            <div className="p-3.5 rounded-xl border border-emerald-500/30 bg-emerald-500/5 dark:bg-emerald-950/20">
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] uppercase font-bold tracking-wider text-emerald-600 dark:text-emerald-400">
                  Final Landed Destination
                </span>
                <span className="text-emerald-600 dark:text-emerald-400 text-[10px] font-bold">
                  Resolved
                </span>
              </div>
              <div className="text-slate-900 dark:text-white font-bold break-all">
                {redirects.finalUrl}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
