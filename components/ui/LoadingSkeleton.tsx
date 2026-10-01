import React from 'react';

export function LoadingSkeleton({ className = '' }: { className?: string }) {
  return (
    <div
      className={`animate-pulse bg-slate-200 dark:bg-cyber-800/80 rounded-lg ${className}`}
      aria-hidden="true"
    />
  );
}

export function ReportSkeleton() {
  return (
    <div className="w-full max-w-5xl mx-auto space-y-6 animate-pulse">
      {/* Top Banner Skeleton */}
      <div className="p-8 rounded-2xl bg-slate-100 dark:bg-cyber-900 border border-slate-200 dark:border-cyber-800 flex flex-col md:flex-row items-center gap-8 justify-between">
        <div className="space-y-4 w-full max-w-md">
          <LoadingSkeleton className="h-6 w-32" />
          <LoadingSkeleton className="h-8 w-64" />
          <LoadingSkeleton className="h-4 w-full" />
          <LoadingSkeleton className="h-4 w-4/5" />
        </div>
        <div className="w-44 h-44 rounded-full bg-slate-200 dark:bg-cyber-800" />
      </div>

      {/* Grid Cards Skeleton */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="h-64 p-6 rounded-xl bg-slate-100 dark:bg-cyber-900 border border-slate-200 dark:border-cyber-800 space-y-4">
          <LoadingSkeleton className="h-6 w-40" />
          <LoadingSkeleton className="h-4 w-full" />
          <LoadingSkeleton className="h-4 w-3/4" />
          <LoadingSkeleton className="h-12 w-full mt-4" />
        </div>
        <div className="h-64 p-6 rounded-xl bg-slate-100 dark:bg-cyber-900 border border-slate-200 dark:border-cyber-800 space-y-4">
          <LoadingSkeleton className="h-6 w-40" />
          <LoadingSkeleton className="h-4 w-full" />
          <LoadingSkeleton className="h-4 w-3/4" />
          <LoadingSkeleton className="h-12 w-full mt-4" />
        </div>
      </div>
    </div>
  );
}
