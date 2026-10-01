import React from 'react';
import { SslIntelligence } from '@/types/security';
import { Lock, ShieldCheck, ShieldAlert, AlertTriangle, Key, Calendar } from 'lucide-react';

interface SslSecurityCardProps {
  ssl: SslIntelligence;
}

export function SslSecurityCard({ ssl }: SslSecurityCardProps) {
  return (
    <div className="p-6 sm:p-8 rounded-2xl bg-white dark:bg-cyber-900 border border-slate-200 dark:border-cyber-800 shadow-sm space-y-6">
      <div className="flex items-center justify-between border-b border-slate-100 dark:border-cyber-800 pb-4">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-xl bg-emerald-500/10 dark:bg-emerald-500/20 text-emerald-600 dark:text-emerald-400">
            <Lock className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base sm:text-lg font-bold text-slate-900 dark:text-white">
              SSL / TLS Connection & Certificate
            </h3>
            <p className="text-xs text-slate-500 dark:text-cyber-400">
              Cryptographic channel security inspection via live socket handshake.
            </p>
            <p className="text-xs font-semibold text-rose-500 mt-1 flex items-center gap-1">
              <AlertTriangle className="w-3.5 h-3.5" />
              HTTPS protects the connection but does not prove website legitimacy.
            </p>
          </div>
        </div>

        <div>
          {ssl.httpsEnabled && ssl.certificateValid ? (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
              <ShieldCheck className="w-3.5 h-3.5" /> Certificate Valid
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20">
              <ShieldAlert className="w-3.5 h-3.5" /> Insecure / Invalid
            </span>
          )}
        </div>
      </div>

      {/* Mandatory Prominent Educational Alert */}
      <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-start gap-3">
        <AlertTriangle className="w-5 h-5 text-amber-500 flex-shrink-0 mt-0.5" />
        <p className="text-xs text-amber-800 dark:text-amber-300 leading-relaxed font-medium">
          <strong>Security Notice:</strong> {ssl.disclaimer}
        </p>
      </div>

      {/* Primary SSL Indicators Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <div className="p-3.5 rounded-xl border border-slate-100 dark:border-cyber-800 bg-slate-50/50 dark:bg-cyber-850/50">
          <span className="text-[10px] uppercase font-mono tracking-wider text-slate-400 dark:text-cyber-400 block mb-1">
            HTTPS Protocol
          </span>
          <span className="text-xs font-bold flex items-center gap-1.5">
            {ssl.httpsEnabled ? (
              <span className="text-emerald-600 dark:text-emerald-400 flex items-center gap-1">
                <ShieldCheck className="w-4 h-4" /> Enabled (Encrypted)
              </span>
            ) : (
              <span className="text-rose-600 dark:text-rose-400 flex items-center gap-1">
                <ShieldAlert className="w-4 h-4" /> Unencrypted HTTP
              </span>
            )}
          </span>
        </div>

        <div className="p-3.5 rounded-xl border border-slate-100 dark:border-cyber-800 bg-slate-50/50 dark:bg-cyber-850/50">
          <span className="text-[10px] uppercase font-mono tracking-wider text-slate-400 dark:text-cyber-400 block mb-1">
            Certificate Authenticity
          </span>
          <span className="text-xs font-bold">
            {ssl.certificateValid ? (
              <span className="text-emerald-600 dark:text-emerald-400 flex items-center gap-1">
                <ShieldCheck className="w-4 h-4" /> Valid Public CA
              </span>
            ) : (
              <span className="text-rose-600 dark:text-rose-400 flex items-center gap-1">
                <ShieldAlert className="w-4 h-4" /> {ssl.error || 'Invalid Certificate'}
              </span>
            )}
          </span>
        </div>

        <div className="p-3.5 rounded-xl border border-slate-100 dark:border-cyber-800 bg-slate-50/50 dark:bg-cyber-850/50">
          <span className="text-[10px] uppercase font-mono tracking-wider text-slate-400 dark:text-cyber-400 block mb-1">
            Hostname Match
          </span>
          <span className="text-xs font-bold">
            {ssl.hostnameMatches ? (
              <span className="text-emerald-600 dark:text-emerald-400 flex items-center gap-1">
                <ShieldCheck className="w-4 h-4" /> Host Matches SAN/CN
              </span>
            ) : (
              <span className="text-amber-600 dark:text-amber-400 flex items-center gap-1">
                <AlertTriangle className="w-4 h-4" /> Hostname Mismatch
              </span>
            )}
          </span>
        </div>
      </div>

      {/* Certificate Detailed Attributes */}
      {ssl.httpsEnabled && (
        <div className="p-4 rounded-xl border border-slate-100 dark:border-cyber-800 bg-slate-50/30 dark:bg-cyber-950/40 space-y-2.5 text-xs font-mono">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 border-b border-slate-100 dark:border-cyber-800/80 pb-2">
            <span className="text-slate-400 flex items-center gap-1.5">
              <Key className="w-3.5 h-3.5 text-cyber-500" /> Certificate Authority / Issuer:
            </span>
            <span className="text-slate-900 dark:text-white font-semibold truncate max-w-sm" title={ssl.issuer || ''}>
              {ssl.issuer || 'Information unavailable'}
            </span>
          </div>

          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 border-b border-slate-100 dark:border-cyber-800/80 pb-2">
            <span className="text-slate-400 flex items-center gap-1.5">
              <Calendar className="w-3.5 h-3.5 text-cyber-500" /> Expiration Validity:
            </span>
            <span className="text-slate-900 dark:text-white font-semibold">
              {ssl.validTo
                ? `${new Date(ssl.validTo).toLocaleDateString()} (${ssl.daysUntilExpiration ?? 0} days remaining)`
                : 'Information unavailable'}
            </span>
          </div>

          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
            <span className="text-slate-400">Cipher & Protocol Version:</span>
            <span className="text-slate-700 dark:text-cyber-300 font-semibold truncate">
              {ssl.protocol ? `${ssl.protocol} (${ssl.cipher || 'Standard Cipher'})` : 'TLS Handshake'}
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
