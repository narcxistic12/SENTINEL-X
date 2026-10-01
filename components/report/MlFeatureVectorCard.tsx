import React from 'react';
import { MlDetectionResult } from '@/types/security';
import { Cpu, HelpCircle, CheckCircle2, Sparkles } from 'lucide-react';

interface MlFeatureVectorCardProps {
  ml: MlDetectionResult;
}

export function MlFeatureVectorCard({ ml }: MlFeatureVectorCardProps) {
  return (
    <div className="p-6 sm:p-8 rounded-2xl bg-white dark:bg-cyber-900 border border-slate-200 dark:border-cyber-800 shadow-sm space-y-6">
      <div className="flex items-center justify-between border-b border-slate-100 dark:border-cyber-800 pb-4">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-xl bg-teal-500/10 dark:bg-teal-500/20 text-teal-600 dark:text-teal-400">
            <Cpu className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base sm:text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <span>ML Classifier & Feature Vector</span>
              <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-teal-500/10 text-teal-600 dark:text-teal-400 border border-teal-500/20">
                ML-Ready
              </span>
            </h3>
            <p className="text-xs text-slate-500 dark:text-cyber-400">
              Normalized feature extraction pipeline engineered for machine learning inference.
            </p>
          </div>
        </div>

        <div>
          {ml.status === 'AVAILABLE' ? (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
              <CheckCircle2 className="w-3.5 h-3.5" /> Model Active
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-slate-100 dark:bg-cyber-800 text-slate-500 dark:text-cyber-400 border border-slate-200 dark:border-cyber-700">
              <HelpCircle className="w-3.5 h-3.5" /> Model Not Configured
            </span>
          )}
        </div>
      </div>

      <div className="p-4 rounded-xl bg-slate-50/50 dark:bg-cyber-950/40 border border-slate-100 dark:border-cyber-800 text-xs text-slate-600 dark:text-cyber-300 leading-relaxed">
        <div className="flex items-center gap-1.5 font-semibold text-slate-900 dark:text-white mb-1">
          <Sparkles className="w-3.5 h-3.5 text-teal-500" />
          <span>Status & Architectural Readiness:</span>
        </div>
        <p>{ml.note}</p>
      </div>

      {/* Extracted Feature Vector Preview */}
      <div>
        <h4 className="text-xs font-bold uppercase tracking-wider font-mono text-slate-500 dark:text-cyber-400 mb-3">
          Extracted Feature Vector ({ml.extractedFeatureVector.length} Dimensions)
        </h4>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 font-mono text-xs">
          {ml.extractedFeatureVector.map((feat) => (
            <div
              key={feat.name}
              className="p-3 rounded-xl border border-slate-100 dark:border-cyber-800 bg-slate-50/40 dark:bg-cyber-950/40 space-y-1.5"
            >
              <div className="flex items-center justify-between">
                <span className="text-slate-500 dark:text-cyber-400 text-[11px] truncate" title={feat.name}>
                  {feat.name}
                </span>
                <span className="text-slate-900 dark:text-white font-bold">{feat.value}</span>
              </div>
              <div className="w-full bg-slate-200 dark:bg-cyber-800 h-1.5 rounded-full overflow-hidden">
                <div
                  className="bg-teal-500 h-full rounded-full transition-all"
                  style={{ width: `${Math.min(100, Math.round(feat.normalized * 100))}%` }}
                />
              </div>
              <div className="flex justify-between text-[10px] text-slate-400 dark:text-cyber-500">
                <span>Norm: {feat.normalized.toFixed(2)}</span>
                <span>Wt: {feat.weight}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
