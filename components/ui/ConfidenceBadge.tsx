import React from 'react';
import { Gauge, Info } from 'lucide-react';

interface ConfidenceBadgeProps {
  confidence: number; // 0 to 100
  showExplanation?: boolean;
}

export function ConfidenceBadge({ confidence, showExplanation = true }: ConfidenceBadgeProps) {
  return (
    <div className="inline-flex flex-col gap-1">
      <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyber-800/80 border border-cyber-700/60 text-cyber-200 text-xs font-mono font-medium">
        <Gauge className="w-3.5 h-3.5 text-cyber-400" />
        <span>Confidence:</span>
        <span className="font-bold text-cyber-100">{confidence}%</span>
      </div>
      {showExplanation && (
        <span className="text-[11px] text-slate-500 dark:text-cyber-400 flex items-center gap-1">
          <Info className="w-3 h-3 flex-shrink-0" />
          Reliability estimate based on signal coverage, not a guarantee of safety.
        </span>
      )}
    </div>
  );
}
