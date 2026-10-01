import React from 'react';
import {
  Shield,
  Layers,
  Globe,
  Lock,
  ArrowRightLeft,
  Database,
  Cpu,
  AlertTriangle,
  Scale,
  CheckCircle2,
} from 'lucide-react';
import Link from 'next/link';

export default function MethodologyPage() {
  const sections = [
    {
      id: 'url-structure',
      title: '1. Lexical & Structural URL Analysis',
      icon: Layers,
      color: 'text-sky-500',
      content: (
        <div className="space-y-3">
          <p>
            Phishing attacks frequently construct deceptive URLs designed to confuse users on both desktop and mobile screens. Our lexical analyzer evaluates:
          </p>
          <ul className="list-disc pl-5 space-y-1.5 text-xs text-slate-600 dark:text-cyber-300">
            <li>
              <strong>IDN Homoglyphs & Punycode (RFC 3492):</strong> Detects non-Latin Unicode characters (e.g., Cyrillic <code>а</code> U+0430) visually identical to Latin alphabet characters used for domain spoofing.
            </li>
            <li>
              <strong>Embedded Userinfo / @ Symbol:</strong> Identifies RFC 3986 userinfo delimiters used to conceal the true destination host from unsuspecting users.
            </li>
            <li>
              <strong>Sensitive Keywords:</strong> Scans paths and subdomains for high-risk authentication (<code>login</code>, <code>verify</code>, <code>2fa</code>), financial (<code>banking</code>, <code>wallet</code>), and urgency tokens.
            </li>
            <li>
              <strong>Shannon Character Entropy:</strong> Calculates information entropy across hostnames to flag algorithmically generated domains (DGAs) and automated campaign strings.
            </li>
            <li>
              <strong>Direct IP Addressing:</strong> Detects raw IPv4/IPv6 addresses used in place of domain names to bypass standard domain blocklists.
            </li>
          </ul>
        </div>
      ),
    },
    {
      id: 'domain-dns',
      title: '2. Domain Intelligence & DNS Verification',
      icon: Globe,
      color: 'text-indigo-500',
      content: (
        <div className="space-y-3">
          <p>
            Live DNS infrastructure queries provide immediate insight into domain stability and legitimacy:
          </p>
          <ul className="list-disc pl-5 space-y-1.5 text-xs text-slate-600 dark:text-cyber-300">
            <li>
              <strong>Active Resolution Check:</strong> Verifies whether the domain possesses active authoritative A and AAAA records. Disposable phishing domains are often rapidly abandoned or revoked.
            </li>
            <li>
              <strong>Mail Exchanger (MX) Records:</strong> Legitimate commercial entities maintain synchronized mail infrastructure. Phishing domains set up solely for web landing attacks frequently omit MX records.
            </li>
            <li>
              <strong>High-Abuse Top-Level Domains:</strong> Cross-references TLDs with elevated frequencies of spam and malicious abuse (e.g., <code>.tk</code>, <code>.xyz</code>, <code>.buzz</code>).
            </li>
          </ul>
        </div>
      ),
    },
    {
      id: 'ssl-tls',
      title: '3. SSL / TLS Security & Certificate Validation',
      icon: Lock,
      color: 'text-emerald-500',
      content: (
        <div className="space-y-3">
          <p>
            The analyzer initiates a real TLS handshake socket connection to inspect the peer X.509 certificate:
          </p>
          <ul className="list-disc pl-5 space-y-1.5 text-xs text-slate-600 dark:text-cyber-300">
            <li>
              <strong>Certificate Authority (CA) Trust:</strong> Validates whether the certificate is issued by a recognized public CA or is self-signed/untrusted.
            </li>
            <li>
              <strong>Expiration & Revocation:</strong> Checks valid from/to timestamps and verifies that the certificate has not expired.
            </li>
            <li>
              <strong>Hostname Matching:</strong> Ensures Subject Alternative Names (SAN) and Common Names (CN) match the URL target.
            </li>
          </ul>
          <div className="p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/20 text-xs text-amber-800 dark:text-amber-300 font-medium">
            <strong>Critical Security Reality:</strong> Over 80% of modern phishing websites actively employ valid HTTPS certificates. A valid certificate encrypts data in transit but does NOT establish that the site owner is trustworthy.
          </div>
        </div>
      ),
    },
    {
      id: 'redirects',
      title: '4. Redirect Tracking with SSRF Defense',
      icon: ArrowRightLeft,
      color: 'text-purple-500',
      content: (
        <div className="space-y-3">
          <p>
            Attackers frequently chain redirects through legitimate-looking URL shorteners to mask final attack landing pages. SENTINELX follows redirects hop-by-hop (up to 5 hops):
          </p>
          <ul className="list-disc pl-5 space-y-1.5 text-xs text-slate-600 dark:text-cyber-300">
            <li>
              <strong>Hop-by-Hop SSRF Validation:</strong> Every single destination IP is resolved and vetted against private IPv4/IPv6 ranges, link-local endpoints, and cloud metadata (169.254.169.254) before establishing a connection.
            </li>
            <li>
              <strong>Cross-Domain Traversal:</strong> Detects silent domain transfers where an innocuous shortener redirects to a high-risk host.
            </li>
            <li>
              <strong>Loop Prevention:</strong> Halts cyclic redirects and recursive routing attacks.
            </li>
          </ul>
        </div>
      ),
    },
    {
      id: 'threat-intel',
      title: '5. Modular Threat Intelligence',
      icon: Database,
      color: 'text-amber-500',
      content: (
        <div className="space-y-3">
          <p>
            SENTINELX integrates provider adapters for industry reputation feeds including PhishTank, URLhaus (abuse.ch), VirusTotal, and Google Safe Browsing:
          </p>
          <ul className="list-disc pl-5 space-y-1.5 text-xs text-slate-600 dark:text-cyber-300">
            <li>
              <strong>Transparent Status:</strong> Distinguishes between <code>Checked</code>, <code>Not Configured</code>, and <code>Unavailable</code> without fabricating clean results.
            </li>
            <li>
              <strong>Instant Blacklist Override:</strong> If an active threat listing is verified by a reputation database, the system elevates the verdict to Critical / Malicious.
            </li>
          </ul>
        </div>
      ),
    },
    {
      id: 'risk-scoring',
      title: '6. Multi-Factor Risk Scoring Engine',
      icon: Scale,
      color: 'text-rose-500',
      content: (
        <div className="space-y-3">
          <p>
            Risk is calculated heuristically across all validated signals. The score (0 to 100) maps to 5 transparent operational categories:
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
            <div className="p-2.5 rounded-lg border border-emerald-500/20 bg-emerald-500/5 text-emerald-700 dark:text-emerald-400">
              <strong>0 – 19:</strong> Safe / Very Low Risk
            </div>
            <div className="p-2.5 rounded-lg border border-sky-500/20 bg-sky-500/5 text-sky-700 dark:text-sky-400">
              <strong>20 – 39:</strong> Low Risk
            </div>
            <div className="p-2.5 rounded-lg border border-amber-500/20 bg-amber-500/5 text-amber-700 dark:text-amber-400">
              <strong>40 – 59:</strong> Suspicious
            </div>
            <div className="p-2.5 rounded-lg border border-orange-500/20 bg-orange-500/5 text-orange-700 dark:text-orange-400">
              <strong>60 – 79:</strong> High Risk
            </div>
            <div className="p-2.5 rounded-lg border border-rose-500/20 bg-rose-500/5 text-rose-700 dark:text-rose-400 sm:col-span-2">
              <strong>80 – 100:</strong> Critical / Malicious Threat
            </div>
          </div>
          <p className="text-xs text-slate-500 dark:text-cyber-400 italic">
            The score represents a heuristic risk assessment based on observable security signals during the scan. It is not an arbitrary single-point metric.
          </p>
        </div>
      ),
    },
    {
      id: 'ml-architecture',
      title: '7. Machine Learning Pipeline (ML-Ready)',
      icon: Cpu,
      color: 'text-teal-500',
      content: (
        <div className="space-y-3">
          <p>
            The system extracts a normalized 12-dimensional feature vector (entropy, length, keyword counts, subdomain depth, homoglyphs) suitable for machine learning classification.
          </p>
          <p className="text-xs text-slate-600 dark:text-cyber-300">
            If an ML inference endpoint is not configured in the deployment environment, SENTINELX honestly reports "Not configured" rather than generating simulated predictions.
          </p>
        </div>
      ),
    },
  ];

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12 space-y-12">
      {/* Header */}
      <div className="text-center space-y-3">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyber-500/10 text-cyber-700 dark:text-cyber-300 text-xs font-mono">
          <Shield className="w-3.5 h-3.5" />
          <span>Technical Documentation & Threat Model</span>
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold font-mono text-slate-900 dark:text-white tracking-tight">
          Security Methodology
        </h1>
        <p className="text-sm sm:text-base text-slate-600 dark:text-cyber-300 max-w-2xl mx-auto leading-relaxed">
          How SENTINELX evaluates URL security, inspects network signals, and calculates transparent risk scores.
        </p>
      </div>

      {/* Mandatory Limitations Notice */}
      <div className="p-6 rounded-2xl bg-amber-50 dark:bg-amber-950/20 border border-amber-300 dark:border-amber-900/50 space-y-2 text-xs sm:text-sm text-amber-900 dark:text-amber-200">
        <div className="flex items-center gap-2 font-bold font-mono text-amber-800 dark:text-amber-400 uppercase tracking-wider">
          <AlertTriangle className="w-4 h-4 text-amber-500 flex-shrink-0" />
          <span>Core Limitations & Safety Disclosure</span>
        </div>
        <p className="leading-relaxed">
          <strong>No automated URL scanner can guarantee that a website is safe.</strong> Phishing campaigns evolve constantly, deploying dynamic cloaking, geofencing, and one-time tokens to evade automated detection. A low-risk assessment indicates absence of detected malicious anomalies at scan time, but should never replace user diligence.
        </p>
      </div>

      {/* Detailed Technical Sections */}
      <div className="space-y-8">
        {sections.map((section) => {
          const Icon = section.icon;
          return (
            <div
              key={section.id}
              className="p-6 sm:p-8 rounded-2xl bg-white dark:bg-cyber-900 border border-slate-200 dark:border-cyber-800 shadow-sm space-y-4"
            >
              <div className="flex items-center gap-3 border-b border-slate-100 dark:border-cyber-800 pb-3">
                <div className={`p-2 rounded-xl bg-slate-100 dark:bg-cyber-800 ${section.color}`}>
                  <Icon className="w-5 h-5" />
                </div>
                <h2 className="text-lg sm:text-xl font-bold font-mono text-slate-900 dark:text-white">
                  {section.title}
                </h2>
              </div>
              <div className="text-sm text-slate-600 dark:text-cyber-200 leading-relaxed">
                {section.content}
              </div>
            </div>
          );
        })}
      </div>

      {/* CTA */}
      <div className="p-8 rounded-2xl bg-slate-100 dark:bg-cyber-900 border border-slate-200 dark:border-cyber-800 text-center space-y-4">
        <h3 className="text-lg font-bold font-mono text-slate-900 dark:text-white">
          Ready to verify a link?
        </h3>
        <Link
          href="/scanner"
          className="inline-flex items-center gap-2 px-6 py-2.5 rounded-xl bg-cyber-600 hover:bg-cyber-500 text-white font-semibold text-sm transition-colors shadow-md"
        >
          <span>Open URL Scanner</span>
        </Link>
      </div>
    </div>
  );
}
