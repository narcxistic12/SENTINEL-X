'use client';

import React from 'react';
import { Sun, Moon } from 'lucide-react';
import { useTheme } from '@/components/theme/ThemeProvider';

export function ThemeToggle({ className = '' }: { className?: string }) {
  const { theme, toggleTheme } = useTheme();

  return (
    <button
      onClick={toggleTheme}
      type="button"
      aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
      className={`p-2 rounded-lg transition-colors border ${
        theme === 'dark'
          ? 'bg-cyber-850/80 border-cyber-700/60 text-cyber-300 hover:text-white hover:bg-cyber-800'
          : 'bg-white border-slate-200 text-slate-600 hover:text-slate-900 hover:bg-slate-100'
      } ${className}`}
      title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
    >
      {theme === 'dark' ? (
        <Sun className="w-4 h-4 text-amber-400 transition-transform hover:rotate-45" />
      ) : (
        <Moon className="w-4 h-4 text-cyber-700 transition-transform hover:-rotate-12" />
      )}
    </button>
  );
}
