'use client';

import React, { useEffect, useState } from 'react';
import {
  ShieldAlert,
  CheckCircle2,
  Loader2,
  Circle,
  Globe,
  Lock,
  ArrowRightLeft,
  Cpu,
  Layers,
} from 'lucide-react';

export interface ScanStage {
  id: string;
  label: string;
  description: string;
  icon: React.ElementType;
}

const STAGES: ScanStage[] = [
  { id: 'init', label: 'Initializing Security Scan', description: 'Bootstrapping scan worker and rate limits', icon: ShieldAlert },
  { id: 'ssrf', label: 'Validating URL & SSRF Defense', description: 'Verifying protocol, DNS rebinding, and IP space', icon: Lock },
  { id: 'parse', label: 'Parsing URL Structure', description: 'Extracting entropy, homoglyphs, and keywords', icon: Layers },
  { id: 'dns', label: 'Analyzing Domain Intelligence', description: 'Querying A, AAAA, MX, and NS records', icon: Globe },
  { id: 'ssl', label: 'Inspecting SSL/TLS Handshake', description: 'Verifying X.509 certificate and hostname match', icon: Lock },
  { id: 'redirects', label: 'Inspecting Redirect Chain', description: 'Tracing HTTP redirect hops with per-hop SSRF validation', icon: ArrowRightLeft },
  { id: 'reputation', label: 'Checking Threat Intelligence', description: 'Querying URLhaus, VirusTotal, and Safe Browsing', icon: Globe },
  { id: 'ml', label: 'Evaluating Heuristic Risk Engine', description: 'Weighing multi-factor security signals and confidence', icon: Cpu },
];

interface ScanProgressStagesProps {
  currentStageIndex: number; // 0 to 7
  targetUrl: string;
}

export function ScanProgressStages({ currentStageIndex, targetUrl }: ScanProgressStagesProps) {
  const [activeStep, setActiveStep] = useState(0);

  useEffect(() => {
    setActiveStep(currentStageIndex);
  }, [currentStageIndex]);

  return (
    <div className="w-full max-w-2xl mx-auto p-6 sm:p-8 rounded-2xl bg-white dark:bg-cyber-900 border border-slate-200 dark:border-cyber-750 shadow-xl transition-all">
      <div className="text-center mb-6">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyber-500/10 dark:bg-cyber-500/20 text-cyber-700 dark:text-cyber-300 text-xs font-mono mb-3">
          <Loader2 className="w-3.5 h-3.5 animate-spin" />
          <span>Active Threat Scan in Progress</span>
        </div>
        <h3 className="text-xl font-extrabold text-slate-900 dark:text-white tracking-tight">
          Analyzing Security Signals
        </h3>
        <p className="text-xs sm:text-sm font-mono text-slate-500 dark:text-cyber-400 truncate max-w-lg mx-auto mt-1">
          Target: {targetUrl}
        </p>
      </div>

      <div className="space-y-3">
        {STAGES.map((stage, idx) => {
          const isCompleted = idx < activeStep;
          const isCurrent = idx === activeStep;
          const isPending = idx > activeStep;

          const Icon = stage.icon;

          return (
            <div
              key={stage.id}
              className={`flex items-center justify-between p-3 rounded-xl border transition-all ${
                isCompleted
                  ? 'bg-emerald-500/5 dark:bg-emerald-950/20 border-emerald-500/20 text-slate-700 dark:text-emerald-300'
                  : isCurrent
                  ? 'bg-cyber-500/10 dark:bg-cyber-800/80 border-cyber-500/40 text-cyber-900 dark:text-white shadow-sm ring-1 ring-cyber-500/20'
                  : 'bg-slate-50/50 dark:bg-cyber-950/40 border-slate-200/60 dark:border-cyber-850 text-slate-400 dark:text-cyber-600 opacity-60'
              }`}
            >
              <div className="flex items-center gap-3 min-w-0">
                <div
                  className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 transition-colors ${
                    isCompleted
                      ? 'bg-emerald-500 text-white'
                      : isCurrent
                      ? 'bg-cyber-600 text-white'
                      : 'bg-slate-200 dark:bg-cyber-800 text-slate-400 dark:text-cyber-500'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                </div>
                <div className="min-w-0 text-left">
                  <div className="text-sm font-semibold truncate flex items-center gap-2">
                    <span>{stage.label}</span>
                  </div>
                  <div className="text-[11px] text-slate-500 dark:text-cyber-400 truncate">
                    {stage.description}
                  </div>
                </div>
              </div>

              <div className="flex-shrink-0 ml-3">
                {isCompleted ? (
                  <CheckCircle2 className="w-5 h-5 text-emerald-500 animate-in fade-in" />
                ) : isCurrent ? (
                  <Loader2 className="w-5 h-5 text-cyber-500 animate-spin" />
                ) : (
                  <Circle className="w-4 h-4 text-slate-300 dark:text-cyber-800" />
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
