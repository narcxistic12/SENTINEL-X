'use client';

import React, { useState, useRef } from 'react';
import { Search, X, Clipboard, ArrowRight, ShieldCheck, AlertTriangle } from 'lucide-react';
import { sanitizeAndNormalizeUrl } from '@/lib/security/sanitize';

interface UrlScannerInputProps {
  onScan: (url: string) => void;
  isLoading?: boolean;
  initialValue?: string;
  size?: 'normal' | 'hero';
}

const SAMPLE_URLS = [
  { label: 'Safe Domain', url: 'https://github.com' },
  { label: 'High Risk / Keywords', url: 'http://secure-login-verify-account.xyz/banking/update-password' },
  { label: 'Homoglyph / Punycode', url: 'https://apple.com' },
  { label: 'Unencrypted HTTP', url: 'http://example.com' },
];

export function UrlScannerInput({
  onScan,
  isLoading = false,
  initialValue = '',
  size = 'hero',
}: UrlScannerInputProps) {
  const [url, setUrl] = useState(initialValue);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleSubmit = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setErrorMessage(null);

    const check = sanitizeAndNormalizeUrl(url);
    if (!check.isValid) {
      setErrorMessage(check.error || 'Please enter a valid HTTP or HTTPS URL.');
      return;
    }

    onScan(check.normalizedUrl);
  };

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        setUrl(text);
        setErrorMessage(null);
        inputRef.current?.focus();
      }
    } catch {
      // Clipboard permissions denied
    }
  };

  const handleClear = () => {
    setUrl('');
    setErrorMessage(null);
    inputRef.current?.focus();
  };

  const isHero = size === 'hero';

  return (
    <div className="w-full max-w-3xl mx-auto space-y-3">
      <form onSubmit={handleSubmit} className="relative w-full">
        <div
          className={`relative flex flex-col sm:flex-row items-stretch sm:items-center rounded-2xl border transition-all ${
            errorMessage
              ? 'border-rose-500/80 bg-rose-500/5 dark:bg-rose-950/20'
              : 'border-slate-200 dark:border-cyber-700 bg-white dark:bg-cyber-900 shadow-xl shadow-cyber-950/10 focus-within:border-cyber-500 dark:focus-within:border-cyber-400 focus-within:ring-2 focus-within:ring-cyber-500/20'
          } ${isHero ? 'p-2 sm:p-2.5' : 'p-1.5 sm:p-2'}`}
        >
          {/* Leading Search Icon */}
          <div className="hidden sm:flex items-center pl-3 text-slate-400 dark:text-cyber-400">
            <Search className="w-5 h-5" />
          </div>

          {/* Text Input */}
          <input
            ref={inputRef}
            type="text"
            value={url}
            onChange={(e) => {
              setUrl(e.target.value);
              if (errorMessage) setErrorMessage(null);
            }}
            placeholder="Enter URL to check (e.g., https://example.com/login)"
            disabled={isLoading}
            className="flex-1 w-full bg-transparent px-3 py-3 sm:py-2 text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-cyber-500 text-base sm:text-lg font-mono focus:outline-none disabled:opacity-50"
            aria-label="URL to inspect for phishing"
          />

          {/* Actions: Paste & Clear Buttons */}
          <div className="flex items-center gap-1 px-2 self-end sm:self-center mb-2 sm:mb-0">
            {url ? (
              <button
                type="button"
                onClick={handleClear}
                disabled={isLoading}
                title="Clear input"
                className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 dark:text-cyber-400 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-cyber-800 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            ) : (
              <button
                type="button"
                onClick={handlePaste}
                title="Paste from clipboard"
                className="hidden sm:inline-flex items-center gap-1 px-2.5 py-1 text-xs font-mono rounded-lg border border-slate-200 dark:border-cyber-750 text-slate-500 dark:text-cyber-300 hover:bg-slate-100 dark:hover:bg-cyber-800 transition-colors"
              >
                <Clipboard className="w-3.5 h-3.5" />
                <span>Paste</span>
              </button>
            )}

            {/* Scan URL CTA Button */}
            <button
              type="submit"
              disabled={isLoading || !url.trim()}
              className={`w-full sm:w-auto inline-flex items-center justify-center gap-2 rounded-xl font-bold tracking-wide transition-all shadow-md active:scale-95 disabled:opacity-50 disabled:pointer-events-none ${
                isHero
                  ? 'px-6 sm:px-8 py-3.5 sm:py-3 text-sm sm:text-base bg-gradient-to-r from-cyber-600 via-cyber-500 to-sky-600 hover:from-cyber-500 hover:to-sky-500 text-white shadow-cyber-500/25'
                  : 'px-5 py-2.5 text-sm bg-cyber-600 hover:bg-cyber-500 text-white shadow-cyber-900/20'
              }`}
            >
              {isLoading ? (
                <>
                  <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span>Scanning...</span>
                </>
              ) : (
                <>
                  <span>SCAN URL</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </div>
        </div>
      </form>

      {/* Validation Error Message */}
      {errorMessage && (
        <div className="flex items-center gap-2 text-xs font-medium text-rose-600 dark:text-rose-400 px-2 py-1 rounded-lg bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-900/50 animate-in fade-in">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          <span>{errorMessage}</span>
        </div>
      )}

      {/* Quick Test Samples */}
      <div className="flex flex-wrap items-center gap-2 pt-1 text-xs">
        <span className="text-slate-500 dark:text-cyber-400 font-medium">Try test samples:</span>
        {SAMPLE_URLS.map((sample) => (
          <button
            key={sample.label}
            type="button"
            onClick={() => {
              setUrl(sample.url);
              setErrorMessage(null);
            }}
            disabled={isLoading}
            className="px-2.5 py-1 rounded-md border border-slate-200 dark:border-cyber-800 bg-slate-50 dark:bg-cyber-950/60 text-slate-600 dark:text-cyber-300 hover:text-cyber-700 dark:hover:text-white hover:border-cyber-500 transition-colors font-mono text-[11px]"
          >
            {sample.label}
          </button>
        ))}
      </div>

      {/* Privacy Guarantee Note */}
      <div className="flex items-center justify-center gap-1.5 text-[11px] text-slate-500 dark:text-cyber-400 pt-1 text-center">
        <ShieldCheck className="w-3.5 h-3.5 text-emerald-500 flex-shrink-0" />
        <span>Your URL is analyzed securely. We never ask for passwords or login credentials.</span>
      </div>
    </div>
  );
}
