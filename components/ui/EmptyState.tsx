import React from 'react';
import { LucideIcon, Shield } from 'lucide-react';
import Link from 'next/link';

interface EmptyStateProps {
  icon?: LucideIcon;
  title: string;
  description: string;
  actionText?: string;
  actionHref?: string;
  onAction?: () => void;
}

export function EmptyState({
  icon: Icon = Shield,
  title,
  description,
  actionText,
  actionHref,
  onAction,
}: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center p-12 text-center rounded-2xl border border-dashed border-slate-300 dark:border-cyber-750 bg-slate-50/50 dark:bg-cyber-900/30">
      <div className="w-14 h-14 rounded-2xl bg-cyber-500/10 dark:bg-cyber-500/20 text-cyber-600 dark:text-cyber-300 flex items-center justify-center mb-4">
        <Icon className="w-7 h-7" />
      </div>
      <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-2">{title}</h3>
      <p className="text-sm text-slate-600 dark:text-cyber-300 max-w-md mb-6">{description}</p>
      {actionText && (
        actionHref ? (
          <Link
            href={actionHref}
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-cyber-600 hover:bg-cyber-500 text-white font-semibold text-sm transition-all shadow-md shadow-cyber-900/20"
          >
            {actionText}
          </Link>
        ) : (
          <button
            onClick={onAction}
            type="button"
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-cyber-600 hover:bg-cyber-500 text-white font-semibold text-sm transition-all shadow-md shadow-cyber-900/20"
          >
            {actionText}
          </button>
        )
      )}
    </div>
  );
}
