import React from 'react';
import Link from 'next/link';
import { Shield, Lock, AlertTriangle, ExternalLink, Github } from 'lucide-react';

export function Footer() {
  return (
    <footer className="border-t border-slate-200 dark:border-cyber-800 bg-slate-50 dark:bg-cyber-950 transition-colors">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-10">
          {/* Brand & Tagline */}
          <div className="md:col-span-2 space-y-3">
            <div className="flex items-center gap-2">
              <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-cyber-600 text-white">
                <Shield className="w-4 h-4" />
              </div>
              <span className="font-extrabold text-lg font-mono tracking-tight text-slate-900 dark:text-white">
                SENTINEL<span className="text-cyber-500">X</span>
              </span>
            </div>
            <p className="text-sm text-slate-600 dark:text-cyber-300 font-medium">
              Intelligent URL Threat Detection
            </p>
            <p className="text-xs text-slate-500 dark:text-cyber-400 max-w-md leading-relaxed">
              Automated multi-factor URL security platform analyzing lexical structure, domain DNS records,
              TLS certificates, HTTP redirect chains, and reputation feeds with zero credential harvesting.
            </p>
          </div>

          {/* Platform Navigation */}
          <div>
            <h4 className="text-xs font-bold uppercase tracking-wider font-mono text-slate-900 dark:text-cyber-200 mb-3">
              Platform
            </h4>
            <ul className="space-y-2 text-sm">
              <li>
                <Link
                  href="/scanner"
                  className="text-slate-600 dark:text-cyber-300 hover:text-cyber-600 dark:hover:text-white transition-colors"
                >
                  URL Scanner
                </Link>
              </li>
              <li>
                <Link
                  href="/dashboard"
                  className="text-slate-600 dark:text-cyber-300 hover:text-cyber-600 dark:hover:text-white transition-colors"
                >
                  Threat Dashboard
                </Link>
              </li>
              <li>
                <Link
                  href="/history"
                  className="text-slate-600 dark:text-cyber-300 hover:text-cyber-600 dark:hover:text-white transition-colors"
                >
                  Scan History
                </Link>
              </li>
              <li>
                <Link
                  href="/methodology"
                  className="text-slate-600 dark:text-cyber-300 hover:text-cyber-600 dark:hover:text-white transition-colors"
                >
                  Security Methodology
                </Link>
              </li>
              <li>
                <Link
                  href="/about"
                  className="text-slate-600 dark:text-cyber-300 hover:text-cyber-600 dark:hover:text-white transition-colors"
                >
                  About & Principles
                </Link>
              </li>
            </ul>
          </div>

          {/* Privacy & Resources */}
          <div>
            <h4 className="text-xs font-bold uppercase tracking-wider font-mono text-slate-900 dark:text-cyber-200 mb-3">
              Security & Privacy
            </h4>
            <ul className="space-y-2 text-sm">
              <li className="flex items-center gap-1 text-slate-600 dark:text-cyber-300">
                <Lock className="w-3.5 h-3.5 text-emerald-500" />
                <span>Zero Credentials Stored</span>
              </li>
              <li className="flex items-center gap-1 text-slate-600 dark:text-cyber-300">
                <Shield className="w-3.5 h-3.5 text-sky-500" />
                <span>SSRF Hardened Guard</span>
              </li>
              <li>
                <a
                  href="https://github.com"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-slate-600 dark:text-cyber-300 hover:text-cyber-600 dark:hover:text-white transition-colors"
                >
                  <Github className="w-3.5 h-3.5" />
                  <span>GitHub Repository</span>
                  <ExternalLink className="w-3 h-3 text-slate-400" />
                </a>
              </li>
            </ul>
          </div>
        </div>

        {/* Security Disclaimer Banner */}
        <div className="pt-6 border-t border-slate-200 dark:border-cyber-800/60 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="flex items-start gap-2 max-w-3xl">
            <AlertTriangle className="w-4 h-4 text-amber-500 flex-shrink-0 mt-0.5" />
            <p className="text-[11px] leading-relaxed text-slate-500 dark:text-cyber-400">
              <strong className="font-semibold text-slate-700 dark:text-cyber-300">Important Security Disclaimer:</strong>{' '}
              SENTINELX provides automated heuristic risk assessment. Security analysis is probabilistic and no automated scanner can guarantee absolute safety. Never submit passwords, financial data, authentication tokens, or private credentials into an untrusted website solely because it received a low-risk rating.
            </p>
          </div>
          <div className="text-[11px] font-mono text-slate-400 dark:text-cyber-500 whitespace-nowrap">
            &copy; {new Date().getFullYear()} SENTINELX
          </div>
        </div>
      </div>
    </footer>
  );
}
