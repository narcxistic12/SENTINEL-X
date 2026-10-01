import React from 'react';
import { RiskVerdict } from '@/types/security';
import { ShieldCheck, ShieldAlert, AlertTriangle, AlertOctagon, HelpCircle } from 'lucide-react';

interface VerdictBadgeProps {
  verdict: RiskVerdict;
  size?: 'sm' | 'md' | 'lg';
  showIcon?: boolean;
}

export function VerdictBadge({ verdict, size = 'md', showIcon = true }: VerdictBadgeProps) {
  const configs: Record<
    RiskVerdict,
    { label: string; bg: string; text: string; border: string; icon: React.ElementType }
  > = {
    SAFE: {
      label: 'SAFE',
      bg: 'bg-emerald-500/10 dark:bg-emerald-950/40',
      text: 'text-emerald-700 dark:text-emerald-400',
      border: 'border-emerald-500/30',
      icon: ShieldCheck,
    },
    LOW_RISK: {
      label: 'LOW RISK',
      bg: 'bg-sky-500/10 dark:bg-sky-950/40',
      text: 'text-sky-700 dark:text-sky-400',
      border: 'border-sky-500/30',
      icon: ShieldCheck,
    },
    SUSPICIOUS: {
      label: 'SUSPICIOUS',
      bg: 'bg-amber-500/10 dark:bg-amber-950/40',
      text: 'text-amber-700 dark:text-amber-400',
      border: 'border-amber-500/30',
      icon: AlertTriangle,
    },
    HIGH_RISK: {
      label: 'HIGH RISK',
      bg: 'bg-orange-500/10 dark:bg-orange-950/40',
      text: 'text-orange-700 dark:text-orange-400',
      border: 'border-orange-500/30',
      icon: AlertOctagon,
    },
    CRITICAL: {
      label: 'CRITICAL / MALICIOUS',
      bg: 'bg-rose-500/10 dark:bg-rose-950/40',
      text: 'text-rose-700 dark:text-rose-400',
      border: 'border-rose-500/30',
      icon: ShieldAlert,
    },
    UNKNOWN: {
      label: 'UNKNOWN',
      bg: 'bg-slate-500/10 dark:bg-slate-900/40',
      text: 'text-slate-700 dark:text-slate-400',
      border: 'border-slate-500/30',
      icon: HelpCircle,
    },
  };

  const config = configs[verdict] || configs.UNKNOWN;
  const Icon = config.icon;

  const sizeClasses = {
    sm: 'text-xs px-2 py-0.5 gap-1.5 font-medium',
    md: 'text-sm px-3 py-1 gap-2 font-semibold',
    lg: 'text-base px-4 py-1.5 gap-2.5 font-bold tracking-wide',
  };

  const iconSizes = {
    sm: 'w-3.5 h-3.5',
    md: 'w-4 h-4',
    lg: 'w-5 h-5',
  };

  return (
    <span
      className={`inline-flex items-center rounded-full border ${config.bg} ${config.text} ${config.border} ${sizeClasses[size]}`}
    >
      {showIcon && <Icon className={iconSizes[size]} />}
      <span>{config.label}</span>
    </span>
  );
}
