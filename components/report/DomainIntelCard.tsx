import React from 'react';
import { DomainIntelligence } from '@/types/security';
import { Globe, Server, Mail, ShieldAlert, CheckCircle2 } from 'lucide-react';

interface DomainIntelCardProps {
  intel: DomainIntelligence;
}

export function DomainIntelCard({ intel }: DomainIntelCardProps) {
  return (
    <div className="p-6 sm:p-8 rounded-2xl bg-white dark:bg-cyber-900 border border-slate-200 dark:border-cyber-800 shadow-sm space-y-6">
      <div className="flex items-center justify-between border-b border-slate-100 dark:border-cyber-800 pb-4">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-xl bg-sky-500/10 dark:bg-sky-500/20 text-sky-600 dark:text-sky-300">
            <Globe className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base sm:text-lg font-bold text-slate-900 dark:text-white">
              Domain Intelligence & DNS Records
            </h3>
            <p className="text-xs text-slate-500 dark:text-cyber-400">
              Live DNS infrastructure queries executed during this scan.
            </p>
          </div>
        </div>

        <div>
          {intel.isResolvable ? (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
              <CheckCircle2 className="w-3.5 h-3.5" /> DNS Active
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20">
              <ShieldAlert className="w-3.5 h-3.5" /> Unresolvable
            </span>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 text-xs font-mono">
        <div className="p-3.5 rounded-xl border border-slate-100 dark:border-cyber-800 bg-slate-50/50 dark:bg-cyber-850/50">
          <span className="text-[10px] uppercase tracking-wider text-slate-400 dark:text-cyber-400 block mb-1">
            Apex Domain
          </span>
          <span className="text-slate-900 dark:text-white font-bold">{intel.domain}</span>
        </div>

        <div className="p-3.5 rounded-xl border border-slate-100 dark:border-cyber-800 bg-slate-50/50 dark:bg-cyber-850/50">
          <span className="text-[10px] uppercase tracking-wider text-slate-400 dark:text-cyber-400 block mb-1">
            Top-Level Domain (TLD)
          </span>
          <span className="text-slate-900 dark:text-white font-bold">.{intel.tld}</span>
        </div>

        <div className="p-3.5 rounded-xl border border-slate-100 dark:border-cyber-800 bg-slate-50/50 dark:bg-cyber-850/50">
          <span className="text-[10px] uppercase tracking-wider text-slate-400 dark:text-cyber-400 block mb-1">
            Mail Routing (MX)
          </span>
          <span className={intel.hasMx ? 'text-emerald-600 dark:text-emerald-400 font-bold' : 'text-amber-600 dark:text-amber-400 font-bold'}>
            {intel.hasMx ? `${intel.mxRecords.length} record(s)` : 'No MX records found'}
          </span>
        </div>
      </div>

      {/* DNS Records Section */}
      <div className="space-y-3 pt-2">
        <h4 className="text-xs font-bold uppercase tracking-wider font-mono text-slate-500 dark:text-cyber-400 flex items-center gap-1.5">
          <Server className="w-3.5 h-3.5" /> Resolved DNS Addresses
        </h4>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
          {/* A Records */}
          <div className="p-3 rounded-xl border border-slate-100 dark:border-cyber-800 bg-slate-50/40 dark:bg-cyber-950/40 space-y-1.5">
            <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">
              A Records (IPv4):
            </span>
            {intel.ipAddresses.length > 0 ? (
              <ul className="space-y-1 font-mono text-slate-800 dark:text-cyber-200">
                {intel.ipAddresses.map((ip) => (
                  <li key={ip} className="flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-cyber-500" />
                    {ip}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-slate-400 italic text-[11px]">Information unavailable</p>
            )}
          </div>

          {/* AAAA Records */}
          <div className="p-3 rounded-xl border border-slate-100 dark:border-cyber-800 bg-slate-50/40 dark:bg-cyber-950/40 space-y-1.5">
            <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">
              AAAA Records (IPv6):
            </span>
            {intel.ipv6Addresses.length > 0 ? (
              <ul className="space-y-1 font-mono text-slate-800 dark:text-cyber-200">
                {intel.ipv6Addresses.map((ip) => (
                  <li key={ip} className="flex items-center gap-1.5 truncate" title={ip}>
                    <span className="w-1.5 h-1.5 rounded-full bg-cyber-400" />
                    {ip}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-slate-400 italic text-[11px]">Information unavailable</p>
            )}
          </div>
        </div>

        {/* Nameservers */}
        {intel.nsRecords.length > 0 && (
          <div className="p-3 rounded-xl border border-slate-100 dark:border-cyber-800 bg-slate-50/40 dark:bg-cyber-950/40">
            <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
              Authoritative Nameservers (NS):
            </span>
            <div className="flex flex-wrap gap-1.5 font-mono text-[11px]">
              {intel.nsRecords.map((ns) => (
                <span
                  key={ns}
                  className="px-2 py-0.5 rounded bg-slate-200/60 dark:bg-cyber-800 text-slate-700 dark:text-cyber-300"
                >
                  {ns}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
