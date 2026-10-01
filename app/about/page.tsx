import React from 'react';
import { Shield, Lock, CheckCircle2, HeartHandshake, Eye, Terminal } from 'lucide-react';
import Link from 'next/link';

export default function AboutPage() {
  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12 space-y-12">
      {/* Header */}
      <div className="text-center space-y-3">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyber-500/10 text-cyber-700 dark:text-cyber-300 text-xs font-mono">
          <Shield className="w-3.5 h-3.5" />
          <span>Our Mission & Defensive Principles</span>
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold font-mono text-slate-900 dark:text-white tracking-tight">
          About SENTINELX
        </h1>
        <p className="text-sm sm:text-base text-slate-600 dark:text-cyber-300 max-w-2xl mx-auto leading-relaxed">
          Empowering individuals and security teams to inspect suspicious links with transparency, zero tracking, and deep technical explainability.
        </p>
      </div>

      {/* Mission */}
      <div className="p-8 rounded-3xl bg-white dark:bg-cyber-900 border border-slate-200 dark:border-cyber-800 shadow-sm space-y-4">
        <h2 className="text-xl font-bold font-mono text-slate-900 dark:text-white flex items-center gap-2">
          <Eye className="w-5 h-5 text-cyber-500" />
          <span>Our Mission</span>
        </h2>
        <p className="text-sm text-slate-600 dark:text-cyber-200 leading-relaxed">
          Traditional security scanners often return opaque verdicts: simply <em>Safe</em> or <em>Unsafe</em>. Users are left in the dark with no insight into how the decision was reached, while advanced phishing campaigns exploit subtle gaps in domain lookalikes and SSL trust assumptions.
        </p>
        <p className="text-sm text-slate-600 dark:text-cyber-200 leading-relaxed">
          SENTINELX was built to answer: <strong>"Can I trust this URL, and exactly why?"</strong> By deconstructing each layer—from lexical entropy and Punycode spoofing to authoritative DNS records, X.509 handshake validity, and redirect hops—we provide actionable, explainable threat intelligence.
        </p>
      </div>

      {/* Core Principles */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="p-6 rounded-2xl bg-white dark:bg-cyber-900 border border-slate-200 dark:border-cyber-800 shadow-sm space-y-3">
          <div className="p-2.5 rounded-xl bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 w-fit">
            <Lock className="w-5 h-5" />
          </div>
          <h3 className="text-base font-bold text-slate-900 dark:text-white font-mono">
            Privacy-First & Zero Retention
          </h3>
          <p className="text-xs text-slate-600 dark:text-cyber-300 leading-relaxed">
            We never harvest credentials, require logins to perform scans, or store passwords. All inspection happens in ephemeral serverless execution.
          </p>
        </div>

        <div className="p-6 rounded-2xl bg-white dark:bg-cyber-900 border border-slate-200 dark:border-cyber-800 shadow-sm space-y-3">
          <div className="p-2.5 rounded-xl bg-sky-500/10 text-sky-600 dark:text-sky-400 w-fit">
            <HeartHandshake className="w-5 h-5" />
          </div>
          <h3 className="text-base font-bold text-slate-900 dark:text-white font-mono">
            Defensive Security Only
          </h3>
          <p className="text-xs text-slate-600 dark:text-cyber-300 leading-relaxed">
            SENTINELX is strictly defensive. We do not clone login portals, bypass access controls, or execute intrusive penetration testing payloads.
          </p>
        </div>

        <div className="p-6 rounded-2xl bg-white dark:bg-cyber-900 border border-slate-200 dark:border-cyber-800 shadow-sm space-y-3">
          <div className="p-2.5 rounded-xl bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 w-fit">
            <CheckCircle2 className="w-5 h-5" />
          </div>
          <h3 className="text-base font-bold text-slate-900 dark:text-white font-mono">
            Honest Signal Transparency
          </h3>
          <p className="text-xs text-slate-600 dark:text-cyber-300 leading-relaxed">
            No simulated data. If a threat intelligence API or DNS record is unavailable or unconfigured, we display "Not configured" rather than pretending it passed.
          </p>
        </div>

        <div className="p-6 rounded-2xl bg-white dark:bg-cyber-900 border border-slate-200 dark:border-cyber-800 shadow-sm space-y-3">
          <div className="p-2.5 rounded-xl bg-purple-500/10 text-purple-600 dark:text-purple-400 w-fit">
            <Terminal className="w-5 h-5" />
          </div>
          <h3 className="text-base font-bold text-slate-900 dark:text-white font-mono">
            SSRF Hardened Architecture
          </h3>
          <p className="text-xs text-slate-600 dark:text-cyber-300 leading-relaxed">
            Engineered with deep SSRF guards that block internal networks, cloud metadata (169.254.169.254), loopback addresses, and dangerous protocols.
          </p>
        </div>
      </div>

      {/* Critical Security Warning */}
      <div className="p-6 rounded-2xl bg-rose-500/10 border border-rose-500/20 shadow-sm space-y-3">
        <h3 className="text-base font-bold text-rose-600 dark:text-rose-400 font-mono flex items-center gap-2">
          <Shield className="w-5 h-5" />
          Critical Security Warning
        </h3>
        <p className="text-sm text-rose-700 dark:text-rose-300/90 leading-relaxed font-semibold">
          Automated analysis cannot guarantee safety. Zero-day phishing campaigns can bypass heuristic checks.
        </p>
        <p className="text-sm text-rose-700 dark:text-rose-300/90 leading-relaxed">
          <strong>NEVER enter:</strong>
        </p>
        <ul className="list-disc list-inside text-sm text-rose-700 dark:text-rose-300/90 ml-2 space-y-1">
          <li>Passwords</li>
          <li>Authentication tokens or cookies</li>
          <li>Payment information</li>
          <li>Private credentials</li>
        </ul>
        <p className="text-sm text-rose-700 dark:text-rose-300/90 leading-relaxed pt-2">
          ...into a website merely because SentinelX (or any scanner) gives it a "Low Risk" result. Always remain vigilant and manually verify the domain for critical services.
        </p>
      </div>

      {/* CTA */}
      <div className="p-8 rounded-2xl bg-slate-100 dark:bg-cyber-900 border border-slate-200 dark:border-cyber-800 text-center space-y-4">
        <h3 className="text-lg font-bold font-mono text-slate-900 dark:text-white">
          Inspect a URL with SENTINELX
        </h3>
        <Link
          href="/scanner"
          className="inline-flex items-center gap-2 px-6 py-2.5 rounded-xl bg-cyber-600 hover:bg-cyber-500 text-white font-semibold text-sm transition-colors shadow-md"
        >
          <span>Launch Scanner</span>
        </Link>
      </div>
    </div>
  );
}
