# 🛡️ SENTINELX — Production-Quality Phishing URL Security Platform

> **Intelligent URL Threat Detection**

SENTINELX is a production-grade cybersecurity full-stack web application designed to answer: **"Can I trust this URL?"** with multi-factor, explainable threat intelligence. Instead of returning an opaque safe/unsafe boolean, SENTINELX evaluates over 20 distinct security signals across lexical structure, live DNS records, direct X.509 SSL/TLS socket handshakes, SSRF-shielded redirect chains, and modular threat reputation feeds—explaining exactly *why* a risk verdict was reached.

Designed from the ground up for zero-cost deployment on the **Vercel Free Tier**, SENTINELX requires no paid external APIs or mandatory databases for its complete MVP scanner experience, while providing full database readiness for PostgreSQL providers such as Supabase and Neon.

---

## 🌟 Key Features

- **Explainable Multi-Signal Risk Engine**:
  - Heuristic risk score from 0 to 100 with confidence estimation (65%–96%).
  - 5 transparent operational verdicts: `SAFE` (0–19), `LOW RISK` (20–39), `SUSPICIOUS` (40–59), `HIGH RISK` (60–79), and `CRITICAL / MALICIOUS` (80–100).
  - Granular detection signals with status (`pass`, `warning`, `fail`), severities, points impact, and source tags.
- **Strict SSRF Defense Guard**:
  - Rejection of non-HTTP(S) protocols (`file://`, `ftp://`, `javascript:`, `data:`, `gopher://`).
  - Pre-request DNS resolution & IP verification blocking all private, loopback, link-local, carrier-grade NAT, and cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`).
  - Per-hop SSRF re-validation for every followed HTTP redirect.
- **Live Infrastructure Inspection**:
  - **URL Structure**: Shannon entropy calculation, IDN homoglyphs & Cyrillic lookalikes, embedded userinfo (`@`), authentication/payment keywords, and shortener identification.
  - **Domain DNS**: Real-time queries for A (IPv4), AAAA (IPv6), MX (Mail Exchangers), and authoritative Nameservers (NS).
  - **SSL / TLS Handshake**: Direct Node socket inspection of peer certificates, issuer CAs, validity timestamps, and SAN/CN hostname matching. Includes educational warnings highlighting that HTTPS does not guarantee site trustworthiness.
  - **Redirect Chain**: Hop-by-hop resolution tracking status codes (301, 302, 307), cross-domain transfers, and loop detection.
- **Modular Threat Intelligence & ML-Ready Architecture**:
  - Adapters for **abuse.ch URLhaus** (free open threat queries), **Google Safe Browsing**, and **VirusTotal**.
  - Strict **No Fake Data Policy**: Unconfigured feeds honestly report `Not configured` with zero simulated statistics.
  - Normalized 12-dimensional feature vector extraction ready for ML inference pipelines.
- **Modern Cybersecurity SOC Design**:
  - Dark-first aesthetic with accessible high-contrast light mode toggle.
  - Animated circular SVG risk gauge (0 to 100).
  - Multi-stage scanning progress indicator.
  - Interactive Operations Dashboard with threat distribution and metrics.
  - LocalStorage-backed client history manager with search, verdict filters, JSON export, and record deletion.
  - Dedicated Methodology and About documentation pages.

---

## 🏗️ Architecture & Pipeline

```
                                [ User / Web Client ]
                                          │
                                 POST /api/scan
                                          ▼
                      [ Sliding-Window Rate Limiter (lib/security) ]
                                          │
                      [ Sanitizer & Normalizer (lib/security) ]
                                          │
                      [ SSRF Defense & DNS Re-check (lib/security) ]
                                          │
           ┌──────────────────────────────┼─────────────────────────────┐
           ▼                              ▼                             ▼
 [ URL Feature Extractor ]       [ Domain DNS Analyzer ]     [ SSL/TLS Handshake ]
  • Shannon entropy               • A & AAAA records          • Peer certificate
  • IDN Homoglyphs / Punycode     • MX mail routing           • CA issuer & expiry
  • Sensitive keywords            • Nameservers (NS)          • Hostname CN/SAN match
  • Risky TLDs & Shorteners       • Resolvability check       • Cipher & TLS version
           │                              │                             │
           └──────────────────────────────┼─────────────────────────────┘
                                          │
           ┌──────────────────────────────┴─────────────────────────────┐
           ▼                                                            ▼
 [ SSRF-Guarded Redirect Follower ]                        [ Modular Threat Feeds ]
  • Up to 5 hops with per-hop SSRF                          • URLhaus (abuse.ch)
  • Cross-domain shift alert                                • Google Safe Browsing
  • Status code inspection                                  • VirusTotal
           │                                                            │
           └──────────────────────────────┬─────────────────────────────┘
                                          │
                                          ▼
                         [ Heuristic Risk Scoring Engine ]
                                          │
                       • Multi-signal weighted deduction
                       • Confidence calculation (coverage-based)
                       • Categorical Verdict (Safe to Critical)
                       • Explainable reason generators
                                          │
                                          ▼
                             [ Structured JSON Report ]
                                          │
                        Persist to DB (Prisma/PostgreSQL) 
                        or Browser LocalStorage (Hybrid)
```

---

## 💻 Tech Stack

- **Framework**: Next.js 14 (App Router)
- **Language**: TypeScript (strict typing)
- **Styling**: Tailwind CSS, custom cybersecurity color tokens
- **3D Visualization**: React Three Fiber, Drei, Three.js (WebGL interactive hero)
- **Database (Optional)**: Prisma ORM with PostgreSQL (Supabase / Neon)
- **Rate Limiting (Optional)**: Upstash Redis (Serverless-ready distributed rate limiting)
- **Icons**: Lucide React
- **Testing**: Vitest
- **Deployment**: Vercel Serverless (Free Tier Compatible)

---

## 🚀 Local Development Setup

### 1. Prerequisites
- Node.js 18.x or higher (tested with Node 20 & 24)
- npm, pnpm, or yarn

### 2. Clone and Install
```bash
git clone https://github.com/yourusername/SENTINELX.git
cd SENTINELX
npm install
```

### 3. Configure Environment Variables
Copy the sample environment file:
```bash
cp .env.example .env.local
```

The application works out of the box with zero keys configured! Optional threat intelligence keys can be added:
```env
NEXT_PUBLIC_APP_URL=http://localhost:3000

# Optional: Google Safe Browsing API v4
# GOOGLE_SAFE_BROWSING_API_KEY=your_key_here

# Optional: VirusTotal API v3
# VIRUSTOTAL_API_KEY=your_key_here

# Optional: URLhaus API
# URLHAUS_API_KEY=your_key_here

# Optional: Persistent PostgreSQL (Supabase / Neon)
# DATABASE_URL="postgresql://..."
```

### 4. Run Development Server
```bash
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 🧪 Running Automated Tests

SENTINELX includes comprehensive unit and integration tests for SSRF protection, URL sanitization, keyword heuristics, punycode detection, risk scoring, and rate limiting:

```bash
npm test
```

Test coverage includes:
- `tests/ssrf.test.ts`: Rejection of loopback (127.0.0.1), private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), AWS/GCP cloud metadata (169.254.169.254), carrier-grade NAT, IPv6 loopback (::1), IPv4-mapped IPv6, and dangerous protocols (`file://`, `ftp://`, `javascript:`).
- `tests/sanitize.test.ts`: URL normalization, credential stripping, protocol prepending, and length limits.
- `tests/url-features.test.ts`: Shannon entropy, homoglyph lookalike detection, sensitive keyword classification, and shortener recognition.
- `tests/risk-engine.test.ts`: Scoring bounds, verdict thresholds, and explainable signal creation.
- `tests/rate-limiter.test.ts`: Sliding-window threshold enforcement.

---

## ☁️ Vercel Deployment Guide (Free Tier)

Deploying SENTINELX to Vercel requires under 3 minutes and zero paid infrastructure:

1. **Push to GitHub**:
   ```bash
   git init
   git add .
   git commit -m "Initial commit of SENTINELX"
   git branch -M main
   git remote add origin https://github.com/your-username/SENTINELX.git
   git push -u origin main
   ```

2. **Import into Vercel**:
   - Log in to your [Vercel Dashboard](https://vercel.com).
   - Click **Add New** &rarr; **Project**.
   - Select your `SENTINELX` GitHub repository and click **Import**.

3. **Configure Environment Variables (Optional)**:
   - Expand the **Environment Variables** section in the Vercel import modal.
   - If you have API keys (such as `GOOGLE_SAFE_BROWSING_API_KEY` or `VIRUSTOTAL_API_KEY`), paste them here.
   - If you do not have external API keys, leave them blank! The scanner will honestly report `Not configured` for external providers while running all local lexical, DNS, SSL, and redirect checks.

4. **Deploy**:
   - Click **Deploy**. Vercel will automatically build the Next.js App Router application.
   - Once deployment completes, test your live production URL!

---

## 🛡️ Security & Privacy Considerations

- **Strict SSRF Defense**: Privileged server execution prevents attackers from using the scanner as a proxy to probe internal services, intranet IPs, or cloud provider instance metadata.
- **Zero Credential Retention**: We never ask for passwords or session tokens for analyzed websites.
- **No Fake Data Policy**: Missing or unconfigured information is honestly labeled `Information unavailable` or `Not configured`—never simulated.
- **Rate Limiting**: Sliding-window rate limiter prevents abuse and denial-of-service against the serverless endpoints.

---

## ⚖️ Responsible Use & Limitations

SENTINELX provides automated heuristic risk assessment. **No automated scanner can guarantee that a website is 100% safe.** Attackers frequently deploy cloaking techniques, geofencing, and one-time verification links. Never enter sensitive passwords, financial information, or credentials solely based on a low-risk scan result. Always exercise standard cybersecurity hygiene.
