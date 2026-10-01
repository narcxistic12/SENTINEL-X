import React from 'react';
import { UrlFeatures } from '@/types/security';
import { Layers, AlertTriangle, CheckCircle, Hash, Compass } from 'lucide-react';

interface UrlStructureCardProps {
  features: UrlFeatures;
}

export function UrlStructureCard({ features }: UrlStructureCardProps) {
  const structureItems = [
    { label: 'Protocol', value: features.protocol.toUpperCase(), highlight: features.protocol === 'http' ? 'warning' : 'normal' },
    { label: 'Hostname', value: features.hostname, highlight: features.hasIpHost ? 'danger' : 'normal' },
    { label: 'Port', value: features.port ? String(features.port) : 'Default (80/443)' },
    { label: 'Path', value: features.path || '/' },
    { label: 'Query Parameters', value: features.paramCount > 0 ? `${features.paramCount} param(s)` : 'None' },
    { label: 'Fragment / Hash', value: features.fragment ? `#${features.fragment}` : 'None' },
    { label: 'URL Length', value: `${features.length} characters`, highlight: features.length > 100 ? 'warning' : 'normal' },
    { label: 'Subdomains', value: features.subdomainCount > 0 ? features.subdomains.join('.') : 'None' },
    { label: 'Top-Level Domain', value: `.${features.tld}`, highlight: features.isRiskyTld ? 'warning' : 'normal' },
    { label: 'Shannon Entropy', value: `${features.entropy} bits`, highlight: features.entropy > 4.3 ? 'warning' : 'normal' },
  ];

  return (
    <div className="p-6 sm:p-8 rounded-2xl bg-white dark:bg-cyber-900 border border-slate-200 dark:border-cyber-800 shadow-sm space-y-6">
      <div className="flex items-center justify-between border-b border-slate-100 dark:border-cyber-800 pb-4">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-xl bg-cyber-500/10 dark:bg-cyber-500/20 text-cyber-600 dark:text-cyber-300">
            <Layers className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base sm:text-lg font-bold text-slate-900 dark:text-white">
              URL Structure & Lexical Breakdown
            </h3>
            <p className="text-xs text-slate-500 dark:text-cyber-400">
              Grammatical inspection of syntax, components, and obfuscation techniques.
            </p>
          </div>
        </div>
      </div>

      {/* Raw URL Display */}
      <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-cyber-950 border border-slate-200/80 dark:border-cyber-800 font-mono text-xs break-all text-slate-800 dark:text-cyber-200">
        <span className="text-slate-400 dark:text-cyber-500 select-none mr-2">URL:</span>
        {features.rawUrl}
      </div>

      {/* Components Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        {structureItems.map((item) => (
          <div
            key={item.label}
            className="p-3 rounded-xl border border-slate-100 dark:border-cyber-800 bg-slate-50/50 dark:bg-cyber-850/50"
          >
            <span className="text-[10px] uppercase font-mono tracking-wider text-slate-400 dark:text-cyber-400 block mb-1">
              {item.label}
            </span>
            <span
              className={`text-xs font-mono font-semibold truncate block ${
                item.highlight === 'danger'
                  ? 'text-rose-600 dark:text-rose-400'
                  : item.highlight === 'warning'
                  ? 'text-amber-600 dark:text-amber-400'
                  : 'text-slate-900 dark:text-white'
              }`}
              title={item.value}
            >
              {item.value}
            </span>
          </div>
        ))}
      </div>

      {/* Lexical Heuristics Indicators */}
      <div className="space-y-2 pt-2 border-t border-slate-100 dark:border-cyber-800">
        <h4 className="text-xs font-bold uppercase tracking-wider font-mono text-slate-500 dark:text-cyber-400 mb-3">
          Structural Checks
        </h4>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
          <div className="flex items-center justify-between p-2.5 rounded-lg border border-slate-100 dark:border-cyber-800 bg-slate-50/30 dark:bg-cyber-950/30">
            <span className="text-slate-600 dark:text-cyber-300">IP Host Name</span>
            {features.hasIpHost ? (
              <span className="text-rose-600 dark:text-rose-400 font-semibold flex items-center gap-1">
                <AlertTriangle className="w-3.5 h-3.5" /> Direct IP Used
              </span>
            ) : (
              <span className="text-emerald-600 dark:text-emerald-400 font-medium flex items-center gap-1">
                <CheckCircle className="w-3.5 h-3.5" /> Standard Hostname
              </span>
            )}
          </div>

          <div className="flex items-center justify-between p-2.5 rounded-lg border border-slate-100 dark:border-cyber-800 bg-slate-50/30 dark:bg-cyber-950/30">
            <span className="text-slate-600 dark:text-cyber-300">Punycode / Homoglyphs</span>
            {features.hasPunycode || features.hasHomoglyphs ? (
              <span className="text-rose-600 dark:text-rose-400 font-semibold flex items-center gap-1">
                <AlertTriangle className="w-3.5 h-3.5" /> Lookalikes Present
              </span>
            ) : (
              <span className="text-emerald-600 dark:text-emerald-400 font-medium flex items-center gap-1">
                <CheckCircle className="w-3.5 h-3.5" /> Clean Latin Script
              </span>
            )}
          </div>

          <div className="flex items-center justify-between p-2.5 rounded-lg border border-slate-100 dark:border-cyber-800 bg-slate-50/30 dark:bg-cyber-950/30">
            <span className="text-slate-600 dark:text-cyber-300">Sensitive Keywords</span>
            {features.matchedKeywords.length > 0 ? (
              <span className="text-amber-600 dark:text-amber-400 font-semibold flex items-center gap-1">
                <AlertTriangle className="w-3.5 h-3.5" /> {features.matchedKeywords.length} Detected
              </span>
            ) : (
              <span className="text-emerald-600 dark:text-emerald-400 font-medium flex items-center gap-1">
                <CheckCircle className="w-3.5 h-3.5" /> None Found
              </span>
            )}
          </div>

          <div className="flex items-center justify-between p-2.5 rounded-lg border border-slate-100 dark:border-cyber-800 bg-slate-50/30 dark:bg-cyber-950/30">
            <span className="text-slate-600 dark:text-cyber-300">URL Shortener Service</span>
            {features.isKnownShortener ? (
              <span className="text-amber-600 dark:text-amber-400 font-semibold flex items-center gap-1">
                <AlertTriangle className="w-3.5 h-3.5" /> {features.shortenerName || 'Shortener'}
              </span>
            ) : (
              <span className="text-emerald-600 dark:text-emerald-400 font-medium flex items-center gap-1">
                <CheckCircle className="w-3.5 h-3.5" /> Direct URL
              </span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
