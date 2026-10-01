'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Lock,
  Layers,
  Globe,
  ArrowRightLeft,
  Database,
  Cpu,
  ArrowRight,
  Eye,
  CheckCircle2,
  AlertTriangle,
  Zap,
  Search,
} from 'lucide-react';
import dynamic from 'next/dynamic';

const ManusHero = dynamic(
  () => import('@/components/scanner/ManusHero').then((mod) => mod.ManusHero),
  { ssr: false }
);
import { ScanProgressStages } from '@/components/scanner/ScanProgressStages';
import { SecurityReportView } from '@/components/scanner/SecurityReportView';
import { ScanReport } from '@/types/security';
import { saveScanReport } from '@/lib/storage/scan-storage';

export default function LandingPage() {
  const router = useRouter();
  const [isScanning, setIsScanning] = useState(false);
  const [currentStage, setCurrentStage] = useState(0);
  const [targetUrl, setTargetUrl] = useState('');
  const [scanResult, setScanResult] = useState<ScanReport | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  const handleStartScan = async (url: string) => {
    setTargetUrl(url);
    setIsScanning(true);
    setScanResult(null);
    setScanError(null);
    setCurrentStage(0);

    // Simulated progress stage increment for smooth visual feedback
    const stageInterval = setInterval(() => {
      setCurrentStage((prev) => (prev < 6 ? prev + 1 : prev));
    }, 450);

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });

      clearInterval(stageInterval);
      setCurrentStage(7);

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || `Scan failed with status ${res.status}`);
      }

      // Allow a brief moment to show stage completion
      setTimeout(() => {
        setScanResult(data as ScanReport);
        saveScanReport(data as ScanReport);
        setIsScanning(false);
      }, 500);
    } catch (err: unknown) {
      clearInterval(stageInterval);
      setIsScanning(false);
      setScanError(err instanceof Error ? err.message : 'Analysis failed. Please try again.');
    }
  };

  return (
    <div className="space-y-24 pb-20">
      {/* 1. HERO SECTION */}
      <section className="relative w-full">
        <ManusHero onScan={handleStartScan} isScanning={isScanning} scanResult={scanResult} />
        
        {scanError && (
          <div className="mt-4 max-w-2xl mx-auto p-4 rounded-xl border border-rose-300 dark:border-rose-900/60 bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-300 text-sm flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 flex-shrink-0 text-rose-500" />
            <span>{scanError}</span>
          </div>
        )}

        <div className="w-full mt-8 relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          {isScanning ? (
            <ScanProgressStages currentStageIndex={currentStage} targetUrl={targetUrl} />
          ) : scanResult ? (
            <div className="space-y-4">
              <div className="flex justify-between items-center max-w-5xl mx-auto px-2">
                <h2 className="text-lg font-bold text-slate-900 dark:text-white font-mono">
                  Live Scan Assessment
                </h2>
                <button
                  onClick={() => setScanResult(null)}
                  type="button"
                  className="text-xs font-semibold text-cyber-600 dark:text-cyber-400 hover:underline"
                >
                  Close Result View
                </button>
              </div>
              <div className="max-w-5xl mx-auto">
                <SecurityReportView report={scanResult} onRescan={() => setScanResult(null)} />
              </div>
            </div>
          ) : null}
        </div>
      </section>

      {/* 2. TRUSTED BY DESIGN (Privacy First) */}
      <section className="px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto">
        <div className="p-8 sm:p-12 rounded-3xl bg-gradient-to-br from-cyber-900 via-cyber-850 to-cyber-950 text-white border border-cyber-750 shadow-2xl relative overflow-hidden">
          <div className="absolute right-0 top-0 w-96 h-96 bg-cyber-500/10 rounded-full blur-3xl pointer-events-none" />
          <div className="max-w-3xl relative z-10 space-y-4">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyber-500/20 text-cyber-300 text-xs font-mono">
              <Lock className="w-3.5 h-3.5" />
              <span>Defensive Privacy Philosophy</span>
            </div>
            <h2 className="text-2xl sm:text-3xl font-extrabold tracking-tight font-mono">
              Trusted by Design. Zero Credential Harvesting.
            </h2>
            <p className="text-sm sm:text-base text-cyber-200 leading-relaxed">
              SENTINELX is engineered solely to protect users. We never store submitted login credentials, session cookies, or private tokens. All scans inspect public metadata and cryptographic signatures without authenticating as users or storing private information.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-4 text-xs font-mono">
              <div className="flex items-center gap-2 text-emerald-400">
                <CheckCircle2 className="w-4 h-4" />
                <span>Zero Password Logging</span>
              </div>
              <div className="flex items-center gap-2 text-sky-400">
                <CheckCircle2 className="w-4 h-4" />
                <span>SSRF Protection Shield</span>
              </div>
              <div className="flex items-center gap-2 text-teal-400">
                <CheckCircle2 className="w-4 h-4" />
                <span>Transparent Heuristics</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* 3. HOW IT WORKS (4 Steps) */}
      <section className="px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto space-y-12">
        <div className="text-center space-y-3 max-w-2xl mx-auto">
          <h2 className="text-xs font-bold uppercase tracking-wider font-mono text-cyber-600 dark:text-cyber-400">
            Scanning Pipeline
          </h2>
          <h3 className="text-3xl sm:text-4xl font-extrabold text-slate-900 dark:text-white font-mono">
            How SENTINELX Analyzes URLs
          </h3>
          <p className="text-sm sm:text-base text-slate-600 dark:text-cyber-300">
            From raw input to explainable risk assessment in under two seconds.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
          {[
            {
              step: '01',
              title: 'Enter URL',
              desc: 'Submit any web link. The system normalizes syntax and performs instantaneous SSRF address validation.',
              icon: Search,
            },
            {
              step: '02',
              title: 'Extract Signals',
              desc: 'Simultaneously parses lexical entropy, DNS records, X.509 certificates, and HTTP redirect chains.',
              icon: Zap,
            },
            {
              step: '03',
              title: 'Calculate Risk',
              desc: 'A modular heuristic risk engine weighs independent risk dimensions against known threat patterns.',
              icon: ShieldCheck,
            },
            {
              step: '04',
              title: 'Understand Verdict',
              desc: 'Receive an explainable report displaying why the score was assigned, with confidence metrics.',
              icon: Eye,
            },
          ].map((item) => {
            const Icon = item.icon;
            return (
              <div
                key={item.step}
                className="p-6 rounded-2xl bg-white dark:bg-cyber-900 border border-slate-200 dark:border-cyber-800 shadow-sm space-y-4 hover:border-cyber-500/50 transition-all group"
              >
                <div className="flex items-center justify-between">
                  <span className="text-2xl font-black font-mono text-slate-300 dark:text-cyber-700 group-hover:text-cyber-500 transition-colors">
                    {item.step}
                  </span>
                  <div className="p-2.5 rounded-xl bg-cyber-500/10 text-cyber-600 dark:text-cyber-400">
                    <Icon className="w-5 h-5" />
                  </div>
                </div>
                <h4 className="text-base font-bold text-slate-900 dark:text-white">{item.title}</h4>
                <p className="text-xs text-slate-600 dark:text-cyber-300 leading-relaxed">
                  {item.desc}
                </p>
              </div>
            );
          })}
        </div>
      </section>

      {/* 4. WHAT WE CHECK (6 Core Capabilities) */}
      <section className="px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto space-y-12">
        <div className="text-center space-y-3 max-w-2xl mx-auto">
          <h2 className="text-xs font-bold uppercase tracking-wider font-mono text-cyber-600 dark:text-cyber-400">
            Multi-Signal Coverage
          </h2>
          <h3 className="text-3xl sm:text-4xl font-extrabold text-slate-900 dark:text-white font-mono">
            What We Check
          </h3>
          <p className="text-sm sm:text-base text-slate-600 dark:text-cyber-300">
            Comprehensive security indicators examined across multiple technical layers.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {[
            {
              title: 'URL Structure & Homoglyphs',
              desc: 'Detects IDN punycode spoofing, Cyrillic lookalike characters, embedded credentials (@), excessive entropy, and suspicious authentication keywords.',
              icon: Layers,
              color: 'text-sky-500',
            },
            {
              title: 'Domain Intelligence & DNS',
              desc: 'Performs live queries for A, AAAA, MX, and NS records. Identifies missing mail infrastructure and unresolvable disposable domains.',
              icon: Globe,
              color: 'text-indigo-500',
            },
            {
              title: 'SSL / TLS Security Handshake',
              desc: 'Inspects real X.509 certificate validity, issuer authority, expiration dates, and hostname matching via direct TLS socket connection.',
              icon: Lock,
              color: 'text-emerald-500',
            },
            {
              title: 'Redirect Chain Follower',
              desc: 'Follows HTTP redirects hop-by-hop up to 5 steps, enforcing SSRF verification on every destination and detecting cross-domain shifts.',
              icon: ArrowRightLeft,
              color: 'text-purple-500',
            },
            {
              title: 'Threat Intelligence Feeds',
              desc: 'Modular adapters querying URLhaus, VirusTotal, and Google Safe Browsing. Honestly flags unconfigured APIs without fabricating results.',
              icon: Database,
              color: 'text-amber-500',
            },
            {
              title: 'Machine Learning Classification',
              desc: 'Extracts a normalized 12-dimensional numeric feature vector ready for Random Forest, XGBoost, or Deep Learning inference pipelines.',
              icon: Cpu,
              color: 'text-teal-500',
            },
          ].map((card) => {
            const Icon = card.icon;
            return (
              <div
                key={card.title}
                className="p-6 rounded-2xl bg-white dark:bg-cyber-900 border border-slate-200 dark:border-cyber-800 shadow-sm space-y-3 hover:border-cyber-500/40 transition-all"
              >
                <div className={`p-2.5 rounded-xl bg-slate-100 dark:bg-cyber-800 w-fit ${card.color}`}>
                  <Icon className="w-5 h-5" />
                </div>
                <h4 className="text-base font-bold text-slate-900 dark:text-white">{card.title}</h4>
                <p className="text-xs text-slate-600 dark:text-cyber-300 leading-relaxed">
                  {card.desc}
                </p>
              </div>
            );
          })}
        </div>
      </section>

      {/* 5. WHY PHISHING DETECTION MATTERS (Educational Section) */}
      <section className="px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto">
        <div className="p-8 sm:p-12 rounded-3xl bg-slate-100 dark:bg-cyber-900/90 border border-slate-200 dark:border-cyber-800">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-center">
            <div className="space-y-4">
              <div className="inline-flex items-center gap-1.5 text-xs font-mono text-amber-600 dark:text-amber-400 font-bold uppercase tracking-wider">
                <AlertTriangle className="w-4 h-4" />
                <span>Threat Intelligence Briefing</span>
              </div>
              <h3 className="text-2xl sm:text-3xl font-extrabold text-slate-900 dark:text-white font-mono">
                Why HTTPS Alone Is Not Enough
              </h3>
              <p className="text-sm text-slate-600 dark:text-cyber-200 leading-relaxed">
                A common misconception is that a padlock icon or HTTPS certificate proves a website is safe. In reality, modern phishing operations obtain automated free SSL certificates within minutes.
              </p>
              <p className="text-sm text-slate-600 dark:text-cyber-300 leading-relaxed">
                HTTPS guarantees encryption in transit, but it does not authenticate the intent of the website owner. SENTINELX looks beyond the certificate to examine structural anomalies, domain history, and obfuscation.
              </p>
            </div>

            <div className="space-y-3 font-mono text-xs">
              <div className="p-4 rounded-xl bg-white dark:bg-cyber-950 border border-slate-200 dark:border-cyber-800 flex items-center justify-between">
                <span className="text-slate-600 dark:text-cyber-300">Phishing Sites with HTTPS:</span>
                <span className="font-bold text-rose-600 dark:text-rose-400 text-sm">&gt; 80%</span>
              </div>
              <div className="p-4 rounded-xl bg-white dark:bg-cyber-950 border border-slate-200 dark:border-cyber-800 flex items-center justify-between">
                <span className="text-slate-600 dark:text-cyber-300">Phishing via Shortened URLs:</span>
                <span className="font-bold text-amber-600 dark:text-amber-400 text-sm">~ 28%</span>
              </div>
              <div className="p-4 rounded-xl bg-white dark:bg-cyber-950 border border-slate-200 dark:border-cyber-800 flex items-center justify-between">
                <span className="text-slate-600 dark:text-cyber-300">Targeting Login Credentials:</span>
                <span className="font-bold text-sky-600 dark:text-sky-400 text-sm">~ 65%</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* 6. TRANSPARENT RESULTS CALLOUT */}
      <section className="px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto text-center space-y-6">
        <div className="max-w-3xl mx-auto space-y-4">
          <h3 className="text-2xl sm:text-3xl font-extrabold text-slate-900 dark:text-white font-mono">
            Transparent Results. No Exaggerated Claims.
          </h3>
          <p className="text-sm text-slate-600 dark:text-cyber-300 leading-relaxed">
            We provide individual indicator severities, sources, and confidence percentages. When an external service is unconfigured, we display "Not configured" rather than pretending it passed.
          </p>
          <div className="pt-2">
            <Link
              href="/methodology"
              className="inline-flex items-center gap-2 text-sm font-semibold text-cyber-600 dark:text-cyber-400 hover:underline"
            >
              <span>Read our complete Security Methodology</span>
              <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        </div>
      </section>

      {/* 7. FINAL CTA */}
      <section className="px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto">
        <div className="p-10 sm:p-14 rounded-3xl bg-gradient-to-r from-cyber-900 via-cyber-800 to-cyber-950 text-white border border-cyber-700 shadow-2xl text-center space-y-6">
          <h3 className="text-3xl sm:text-5xl font-black font-mono tracking-tight">
            Before you click, check it.
          </h3>
          <p className="text-sm sm:text-base text-cyber-200 max-w-xl mx-auto">
            Free, instantaneous URL security analysis powered by real infrastructure signals and zero credential collection.
          </p>
          <div className="pt-2">
            <Link
              href="/scanner"
              className="inline-flex items-center gap-2 px-8 py-3.5 rounded-xl bg-cyber-500 hover:bg-cyber-400 text-white font-bold text-base transition-all shadow-lg shadow-cyber-950/40"
            >
              <span>Scan a URL Now</span>
              <ArrowRight className="w-5 h-5" />
            </Link>
          </div>
        </div>
      </section>
    </div>
  );
}

