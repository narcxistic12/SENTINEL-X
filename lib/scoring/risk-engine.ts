import {
  RiskVerdict,
  SecuritySignal,
  UrlFeatures,
  DomainIntelligence,
  DomainRegistrationIntelligence,
  SslIntelligence,
  RedirectIntelligence,
  ThreatIntelResult,
  MlDetectionResult,
  PageContentAnalysisResult,
  EvidenceItem,
  SecurityEvidenceCategory,
  ExternalAnalysisResult,
} from '@/types/security';

export interface ScoreCalculationResult {
  riskScore: number;
  confidenceScore: number;
  verdict: RiskVerdict;
  riskCategory: string;
  summary: string;
  explanation: string;
  evidence: EvidenceItem[];
  signals: SecuritySignal[];
}

/**
 * Modular Evidence-Based Risk Scoring Engine.
 * Evaluates multiple independent security dimensions and generates explainable, URL-specific evidence.
 */
export function calculateRiskScore(params: {
  urlFeatures: UrlFeatures;
  domainIntel: DomainIntelligence;
  domainRegIntel?: DomainRegistrationIntelligence;
  sslIntel: SslIntelligence;
  redirectIntel: RedirectIntelligence;
  threatIntel: ThreatIntelResult[];
  mlResult?: MlDetectionResult;
  pageContentIntel?: PageContentAnalysisResult;
  urlscanResult?: ExternalAnalysisResult;
  anyrunResult?: ExternalAnalysisResult;
  cloudflareResult?: ExternalAnalysisResult;
  urlscansResult?: ExternalAnalysisResult;
  virustotalFreshResult?: ExternalAnalysisResult;
  externalIntel?: ExternalAnalysisResult[];
}): ScoreCalculationResult {
  const {
    urlFeatures,
    domainIntel,
    domainRegIntel,
    sslIntel,
    redirectIntel,
    threatIntel,
    pageContentIntel,
    urlscanResult,
    anyrunResult,
    cloudflareResult,
    urlscansResult,
    virustotalFreshResult,
    externalIntel,
  } = params;

  let totalRisk = 0;
  const signals: SecuritySignal[] = [];
  const evidence: EvidenceItem[] = [];

  // ==========================================
  // 1. URL Structure & Lexical Heuristics
  // ==========================================

  // Official Domain Guard: If official brand domain, do not penalize lexical keywords
  const isOfficialDomainMatch = urlFeatures.brandImpersonation?.isOfficialDomainMatch;

  if (urlFeatures.hasIpHost) {
    totalRisk += 25;
    signals.push({
      id: 'url-ip-host',
      title: 'Direct IP Address Used in Hostname',
      explanation:
        'Legitimate public web services virtually always use human-readable domain names. Direct IP addresses are frequently leveraged by phishing campaigns to bypass domain reputation blocklists.',
      severity: 'high',
      status: 'fail',
      source: 'LOCAL ANALYSIS',
      points: 25,
      technicalDetails: { hostname: urlFeatures.hostname },
    });
    evidence.push({
      source: 'URL Structure',
      finding: `URL uses a raw IP address host (${urlFeatures.hostname}) instead of a domain name.`,
      impact: 'HIGH_RISK',
      actual: true,
      category: 'URL_STRUCTURE',
    });
  }

  if (urlFeatures.hasPunycode || urlFeatures.hasHomoglyphs) {
    totalRisk += 30;
    const homoglyphDetails = (urlFeatures.homoglyphsFound || []).join(', ');
    signals.push({
      id: 'url-homoglyph-detected',
      title: 'Punycode / IDN Homograph Lookalike Detected',
      explanation:
        'The URL utilizes non-Latin lookalike characters or punycode encoding that visually mimics a well-known Latin domain name to deceive users.',
      severity: 'critical',
      status: 'fail',
      source: 'LOCAL ANALYSIS',
      points: 30,
      technicalDetails: {
        punycode: urlFeatures.punycodeDecoded,
        homoglyphs: homoglyphDetails,
      },
    });
    evidence.push({
      source: 'URL Structure',
      finding: `IDN homograph / punycode lookalike encoding detected (${urlFeatures.punycodeDecoded || urlFeatures.hostname}).`,
      impact: 'HIGH_RISK',
      actual: true,
      category: 'PUNYCODE',
    });
  }

  if (urlFeatures.hasAtSymbol) {
    totalRisk += 24;
    signals.push({
      id: 'url-at-symbol',
      title: 'Userinfo Delimiter (@) Present in URL',
      explanation:
        'The @ character in URLs treats preceding text as user credentials while routing the browser to whatever follows.',
      severity: 'high',
      status: 'fail',
      source: 'LOCAL ANALYSIS',
      points: 24,
    });
    evidence.push({
      source: 'URL Structure',
      finding: 'Userinfo delimiter (@) present in URL, which can disguise the true host destination.',
      impact: 'HIGH_RISK',
      actual: true,
      category: 'URL_STRUCTURE',
    });
  }

  if (urlFeatures.matchedKeywords && urlFeatures.matchedKeywords.length > 0) {
    const keywordList = urlFeatures.matchedKeywords.map((k) => k.keyword).join(', ');
    const hasAuth = urlFeatures.matchedKeywords.some((k) => k.category === 'authentication');
    const hasPayment = urlFeatures.matchedKeywords.some((k) => k.category === 'payment');

    const points = urlFeatures.matchedKeywords.length > 2 ? 22 : 12;
    totalRisk += points;

    signals.push({
      id: 'url-suspicious-keywords',
      title: 'Authentication / Financial Keywords in URL Path',
      explanation: `URL contains sensitive keywords (${keywordList}) associated with ${
        hasAuth && hasPayment ? 'login and payment' : hasAuth ? 'authentication credentials' : 'financial workflows'
      }.`,
      severity: urlFeatures.matchedKeywords.length > 2 ? 'high' : 'medium',
      status: 'warning',
      source: 'LOCAL ANALYSIS',
      points,
      technicalDetails: { keywords: urlFeatures.matchedKeywords },
    });
    evidence.push({
      source: 'URL Keywords',
      finding: `URL contains credential/financial keywords: ${keywordList}.`,
      impact: urlFeatures.matchedKeywords.length > 2 ? 'HIGH_RISK' : 'MEDIUM_RISK',
      actual: true,
      category: 'KEYWORD',
    });
  }

  if (urlFeatures.isRiskyTld) {
    totalRisk += 15;
    signals.push({
      id: 'url-risky-tld',
      title: `High-Abuse Top-Level Domain (.${urlFeatures.tld})`,
      explanation: `The .${urlFeatures.tld} extension has a statistically elevated frequency of phishing and malware registrations.`,
      severity: 'medium',
      status: 'warning',
      source: 'LOCAL ANALYSIS',
      points: 15,
      technicalDetails: { tld: urlFeatures.tld },
    });
    evidence.push({
      source: 'TLD Reputation',
      finding: `Top-level domain .${urlFeatures.tld} has an elevated security abuse rate.`,
      impact: 'MEDIUM_RISK',
      actual: true,
      category: 'URL_STRUCTURE',
    });
  }

  if (urlFeatures.isKnownShortener) {
    totalRisk += 10;
    signals.push({
      id: 'url-shortener',
      title: `URL Shortener Service Detected (${urlFeatures.shortenerName || 'Shortener'})`,
      explanation: 'URL shorteners conceal the true destination hostname and path from the user.',
      severity: 'medium',
      status: 'warning',
      source: 'LOCAL ANALYSIS',
      points: 10,
    });
    evidence.push({
      source: 'URL Shortener',
      finding: `URL uses shortener service (${urlFeatures.shortenerName || 'Shortener'}), masking final destination.`,
      impact: 'MEDIUM_RISK',
      actual: true,
      category: 'URL_STRUCTURE',
    });
  }

  if (urlFeatures.hasNestedUrl) {
    totalRisk += 15;
    signals.push({
      id: 'url-nested-redirect-target',
      title: 'Nested URL Parameter Observed in Path/Query',
      explanation: 'The URL path or query string embeds another external URL, a pattern commonly used in open-redirect phishing vectors.',
      severity: 'high',
      status: 'fail',
      source: 'LOCAL ANALYSIS',
      points: 15,
    });
    evidence.push({
      source: 'URL Structure',
      finding: 'Embedded nested URL structure detected in parameter/path payload.',
      impact: 'HIGH_RISK',
      actual: true,
      category: 'URL_STRUCTURE',
    });
  }

  if (urlFeatures.suspiciousFileExtension) {
    totalRisk += 10;
    signals.push({
      id: 'url-suspicious-extension',
      title: `Executable / Script Extension (.${urlFeatures.suspiciousFileExtension})`,
      explanation: `The URL target ends in an executable or script extension (.${urlFeatures.suspiciousFileExtension}).`,
      severity: 'medium',
      status: 'warning',
      source: 'LOCAL ANALYSIS',
      points: 10,
    });
    evidence.push({
      source: 'URL Structure',
      finding: `URL path targets script/executable extension (.${urlFeatures.suspiciousFileExtension}).`,
      impact: 'MEDIUM_RISK',
      actual: true,
      category: 'URL_STRUCTURE',
    });
  }

  if (urlFeatures.unusualPort) {
    totalRisk += 12;
    signals.push({
      id: 'url-unusual-port',
      title: `Non-Standard Port (${urlFeatures.port})`,
      explanation: `The connection specifies non-standard web port ${urlFeatures.port}.`,
      severity: 'medium',
      status: 'warning',
      source: 'LOCAL ANALYSIS',
      points: 12,
    });
    evidence.push({
      source: 'URL Structure',
      finding: `Non-standard service port ${urlFeatures.port} used in URL.`,
      impact: 'MEDIUM_RISK',
      actual: true,
      category: 'URL_STRUCTURE',
    });
  }

  if (urlFeatures.brandImpersonation?.detected) {
    totalRisk += 35;
    signals.push({
      id: 'url-brand-impersonation',
      title: `Brand Impersonation Detected (${urlFeatures.brandImpersonation.brandFound})`,
      explanation: urlFeatures.brandImpersonation.evidence,
      severity: 'critical',
      status: 'fail',
      source: 'LOCAL ANALYSIS',
      points: 35,
    });
    evidence.push({
      source: 'Brand Analysis',
      finding: urlFeatures.brandImpersonation.evidence,
      impact: 'HIGH_RISK',
      actual: true,
      category: 'BRAND_IMPERSONATION',
    });
  }

  // ==========================================
  // 2. Domain & DNS Intelligence
  // ==========================================

  if (!domainIntel.isResolvable) {
    totalRisk += 25;
    signals.push({
      id: 'domain-unresolvable',
      title: 'Domain Failed DNS Resolution',
      explanation: 'The domain name could not be resolved to any active IP address.',
      severity: 'high',
      status: 'fail',
      source: 'DOMAIN ANALYSIS',
      points: 25,
      technicalDetails: { error: domainIntel.lookupError },
    });
    evidence.push({
      source: 'DNS Analysis',
      finding: `Domain '${domainIntel.domain}' failed DNS resolution (Lookup error: ${domainIntel.lookupError || 'No A/AAAA records'}).`,
      impact: 'HIGH_RISK',
      actual: true,
      category: 'DNS',
    });
  } else {
    const ipCount = (domainIntel.ipAddresses || []).length;
    const v6Count = (domainIntel.ipv6Addresses || []).length;
    evidence.push({
      source: 'DNS Analysis',
      finding: `DNS resolution verified (${ipCount} IPv4, ${v6Count} IPv6 address(es)).`,
      impact: 'NEUTRAL',
      actual: true,
      category: 'DNS',
    });

    if (!domainIntel.hasMx && !urlFeatures.hasIpHost) {
      totalRisk += 6;
      signals.push({
        id: 'domain-no-mx',
        title: 'No Mail Exchanger (MX) Records Configured',
        explanation: 'The root domain has no configured MX records.',
        severity: 'low',
        status: 'info',
        source: 'DOMAIN ANALYSIS',
        points: 6,
      });
      evidence.push({
        source: 'DNS Analysis',
        finding: 'No MX mail server records are configured for this root domain.',
        impact: 'LOW_RISK',
        actual: true,
        category: 'DNS',
      });
    }
  }

  // ==========================================
  // 3. Domain Registration & Age Intelligence
  // ==========================================

  if (domainRegIntel && domainRegIntel.status === 'CHECKED') {
    if (domainRegIntel.isNewlyRegistered) {
      totalRisk += 15;
      signals.push({
        id: 'domain-newly-registered',
        title: `Newly Registered Domain (${domainRegIntel.domainAgeDays} Days Old)`,
        explanation: `Domain was created ${domainRegIntel.domainAgeDays} day(s) ago (${domainRegIntel.registrationDate || 'Recently'}). Newly created domains statistically account for a high percentage of zero-day phishing campaigns.`,
        severity: 'high',
        status: 'fail',
        source: 'DOMAIN ANALYSIS',
        points: 15,
        technicalDetails: { ageDays: domainRegIntel.domainAgeDays, date: domainRegIntel.registrationDate },
      });
      evidence.push({
        source: 'Domain Registration',
        finding: `Domain was registered recently (${domainRegIntel.domainAgeDays} days ago on ${domainRegIntel.registrationDate || 'recent date'}).`,
        impact: 'HIGH_RISK',
        actual: true,
        category: 'DOMAIN_AGE',
      });
    } else if (domainRegIntel.isYoungDomain) {
      totalRisk += 8;
      signals.push({
        id: 'domain-young-registered',
        title: `Young Domain Age (${domainRegIntel.domainAgeDays} Days)`,
        explanation: `Domain is under 90 days old (${domainRegIntel.domainAgeDays} days).`,
        severity: 'medium',
        status: 'warning',
        source: 'DOMAIN ANALYSIS',
        points: 8,
      });
      evidence.push({
        source: 'Domain Registration',
        finding: `Young domain registration age (${domainRegIntel.domainAgeDays} days).`,
        impact: 'MEDIUM_RISK',
        actual: true,
        category: 'DOMAIN_AGE',
      });
    } else if (domainRegIntel.domainAgeDays && domainRegIntel.domainAgeDays > 365) {
      evidence.push({
        source: 'Domain Registration',
        finding: `Established domain registration age (${Math.floor(domainRegIntel.domainAgeDays / 365)} year(s) old).`,
        impact: 'NEUTRAL',
        actual: true,
        category: 'DOMAIN_AGE',
      });
    }
  } else if (domainRegIntel && domainRegIntel.status !== 'CHECKED') {
    evidence.push({
      source: 'Domain Registration',
      finding: `Registration RDAP lookup: ${domainRegIntel.details || domainRegIntel.status}.`,
      impact: 'CONFIDENCE_REDUCTION',
      actual: true,
      category: 'REGISTRATION',
    });
  }

  // ==========================================
  // 4. SSL / TLS Security Signals
  // ==========================================

  if (!sslIntel.httpsEnabled) {
    totalRisk += 20;
    signals.push({
      id: 'ssl-unencrypted',
      title: 'Unencrypted HTTP Connection (No SSL/TLS)',
      explanation: 'Website communicates in cleartext HTTP without encryption.',
      severity: 'high',
      status: 'fail',
      source: 'SSL/TLS',
      points: 20,
    });
    evidence.push({
      source: 'TLS/HTTPS',
      finding: 'Unencrypted HTTP protocol used; data transmitted in cleartext.',
      impact: 'HIGH_RISK',
      actual: true,
      category: 'TLS',
    });
  } else {
    if (sslIntel.certificateValid && sslIntel.hostnameMatches) {
      evidence.push({
        source: 'TLS/HTTPS',
        finding: `Valid TLS certificate matching '${urlFeatures.hostname}', issued by '${sslIntel.issuer || 'Trusted CA'}'.`,
        impact: 'NEUTRAL',
        actual: true,
        category: 'TLS',
      });
    }

    if (sslIntel.isExpired) {
      totalRisk += 30;
      signals.push({
        id: 'ssl-cert-expired',
        title: 'SSL/TLS Certificate Has Expired',
        explanation: 'The security certificate presented by this server has expired.',
        severity: 'critical',
        status: 'fail',
        source: 'SSL/TLS',
        points: 30,
      });
      evidence.push({
        source: 'TLS/HTTPS',
        finding: 'TLS certificate presented by the server has expired.',
        impact: 'HIGH_RISK',
        actual: true,
        category: 'TLS',
      });
    }

    if (sslIntel.isSelfSigned) {
      totalRisk += 25;
      signals.push({
        id: 'ssl-self-signed',
        title: 'Untrusted Self-Signed Certificate',
        explanation: 'The certificate was signed by itself rather than a recognized public Certificate Authority.',
        severity: 'high',
        status: 'fail',
        source: 'SSL/TLS',
        points: 25,
      });
      evidence.push({
        source: 'TLS/HTTPS',
        finding: 'Untrusted self-signed TLS certificate.',
        impact: 'HIGH_RISK',
        actual: true,
        category: 'TLS',
      });
    }

    if (!sslIntel.hostnameMatches && sslIntel.certificateValid) {
      totalRisk += 25;
      signals.push({
        id: 'ssl-hostname-mismatch',
        title: 'Certificate Hostname Mismatch',
        explanation: 'The certificate CN/SAN names do not match the target hostname in the URL.',
        severity: 'high',
        status: 'fail',
        source: 'SSL/TLS',
        points: 25,
      });
      evidence.push({
        source: 'TLS/HTTPS',
        finding: `TLS certificate hostname mismatch (Issued to: '${sslIntel.subject || 'Unknown'}').`,
        impact: 'HIGH_RISK',
        actual: true,
        category: 'TLS',
      });
    }
  }

  // ==========================================
  // 5. Redirect Intelligence Signals
  // ==========================================

  if (redirectIntel.hopCount > 1) {
    const hopPoints = redirectIntel.hopCount >= 3 ? 14 : 8;
    totalRisk += hopPoints;
    signals.push({
      id: 'redirect-multiple-hops',
      title: `Multiple Redirect Hops (${redirectIntel.hopCount} Hops)`,
      explanation: `The initial URL undergoes ${redirectIntel.hopCount} redirect steps.`,
      severity: 'medium',
      status: 'warning',
      source: 'REDIRECT ANALYSIS',
      points: hopPoints,
      technicalDetails: { hops: redirectIntel.hops },
    });
    evidence.push({
      source: 'Redirect Inspection',
      finding: `URL undergoes ${redirectIntel.hopCount} redirect steps before reaching destination.`,
      impact: 'MEDIUM_RISK',
      actual: true,
      category: 'REDIRECT',
    });
  }

  if (redirectIntel.destinationChanged) {
    totalRisk += 12;
    signals.push({
      id: 'redirect-cross-domain',
      title: 'Cross-Domain Redirect Observed',
      explanation: `The URL shifts destination to a different root domain.`,
      severity: 'medium',
      status: 'warning',
      source: 'REDIRECT ANALYSIS',
      points: 12,
    });
    evidence.push({
      source: 'Redirect Inspection',
      finding: `Cross-domain redirect shifts destination to '${
        redirectIntel.finalUrl ? new URL(redirectIntel.finalUrl).hostname : 'external host'
      }'.`,
      impact: 'MEDIUM_RISK',
      actual: true,
      category: 'REDIRECT',
    });
  }

  // ==========================================
  // 6. Threat Intelligence & External Web Analysis Signals
  // ==========================================

  const unconfiguredProviders: string[] = [];
  const unavailableProviders: string[] = [];
  const cleanProviders: string[] = [];
  const flaggedIntel: ThreatIntelResult[] = [];

  for (const ti of threatIntel) {
    if (ti.isFlagged || ti.status === 'FLAGGED') {
      flaggedIntel.push(ti);
      const malCount = ti.stats?.maliciousEngineCount;
      const totalEng = ti.stats?.totalEngineCount;
      const detailText =
        malCount !== undefined && totalEng !== undefined
          ? `${ti.providerName} reported ${malCount} malicious detection(s) out of ${totalEng} engines.`
          : `${ti.providerName} explicitly flagged this URL as ${ti.threatType || 'malicious'}.`;

      evidence.push({
        source: ti.providerName,
        finding: detailText,
        impact: 'HIGH_RISK',
        actual: true,
        category: 'THREAT_INTELLIGENCE',
      });
    } else if (ti.status === 'CLEAN') {
      cleanProviders.push(ti.providerName);
      const malCount = ti.stats?.maliciousEngineCount;
      const totalEng = ti.stats?.totalEngineCount;
      const detailText =
        malCount === 0 && totalEng
          ? `${ti.providerName} returned 0 malicious detections out of ${totalEng} engines.`
          : `${ti.providerName} returned zero active threat listings.`;

      evidence.push({
        source: ti.providerName,
        finding: detailText,
        impact: 'NEUTRAL',
        actual: true,
        category: 'THREAT_INTELLIGENCE',
      });
    } else if (ti.status === 'NOT_CONFIGURED') {
      unconfiguredProviders.push(ti.providerName);
      evidence.push({
        source: ti.providerName,
        finding: `${ti.providerName} is not configured (Requires server API key).`,
        impact: 'CONFIDENCE_REDUCTION',
        actual: true,
        category: 'THREAT_INTELLIGENCE',
      });
    } else {
      unavailableProviders.push(ti.providerName);
      evidence.push({
        source: ti.providerName,
        finding: `${ti.providerName} was unavailable (${ti.details || ti.status}).`,
        impact: 'CONFIDENCE_REDUCTION',
        actual: true,
        category: 'THREAT_INTELLIGENCE',
      });
    }
  }

  // External Web Analysis Providers (URLscan, ANY.RUN, Cloudflare URL Scanner, URLScans, VirusTotal Fresh)
  const externalProviders = [
    params.urlscanResult,
    params.anyrunResult,
    params.cloudflareResult,
    params.urlscansResult,
    params.virustotalFreshResult,
    ...(params.externalIntel || []),
  ].filter(Boolean) as ExternalAnalysisResult[];
  for (const ext of externalProviders) {
    if (ext.evidence && ext.evidence.length > 0) {
      for (const evItem of ext.evidence) {
        if (!evidence.some((e) => e.source === evItem.source && e.finding === evItem.finding)) {
          evidence.push(evItem);
        }
      }
    }

    if (ext.isFlagged || ext.status === 'FLAGGED') {
      flaggedIntel.push({
        providerName: ext.providerName,
        status: 'FLAGGED',
        isFlagged: true,
        threatType: ext.threatType || 'Malicious / Web Threat',
        details: ext.details,
      });
    } else if (ext.status === 'CLEAN') {
      if (!cleanProviders.includes(ext.providerName)) cleanProviders.push(ext.providerName);
    } else if (ext.status === 'NOT_CONFIGURED') {
      if (!unconfiguredProviders.includes(ext.providerName)) unconfiguredProviders.push(ext.providerName);
    } else {
      if (!unavailableProviders.includes(ext.providerName)) unavailableProviders.push(ext.providerName);
    }
  }

  if (flaggedIntel.length > 0) {
    totalRisk = Math.max(totalRisk, 85);
    for (const item of flaggedIntel) {
      totalRisk += 15;
      signals.push({
        id: `threat-intel-${item.providerName.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`,
        title: `Blacklisted by ${item.providerName}`,
        explanation: `Confirmed active threat in reputation database: ${item.details || item.threatType || 'Malicious URL'}`,
        severity: 'critical',
        status: 'fail',
        source: 'THREAT INTELLIGENCE',
        points: 50,
        technicalDetails: { threatType: item.threatType, details: item.details },
      });
    }
  }

  // ==========================================
  // 7. MULTI-SIGNAL CORRELATION ENGINE (Zero-Day Detection)
  // ==========================================

  // Multi-signal rule 1: Cross-domain credential form submission
  const hasCrossDomainForm =
    params.urlscanResult?.metadata?.crossDomainFormSubmission ||
    evidence.some((e) => e.category === 'CROSS_DOMAIN_CREDENTIAL_SUBMISSION');

  if (hasCrossDomainForm) {
    totalRisk += 35;
    if (!evidence.some((e) => e.source === 'Correlation Engine' && e.category === 'CROSS_DOMAIN_CREDENTIAL_SUBMISSION')) {
      evidence.push({
        source: 'Correlation Engine',
        finding: 'Multi-signal correlation: Scanned page submits credential form data to a cross-domain external host.',
        impact: 'HIGH_RISK',
        actual: true,
        category: 'CROSS_DOMAIN_CREDENTIAL_SUBMISSION',
      });
    }
  }

  // Multi-signal rule 2: Brand Impersonation + Credential Form + (New Domain / Keywords / Risky TLD / Redirects)
  const brandDetected = urlFeatures.brandImpersonation?.detected || Boolean(params.urlscanResult?.metadata?.detectedBrand);
  const hasCredForm =
    Boolean(params.urlscanResult?.metadata?.hasPasswordField) ||
    Boolean(params.urlscanResult?.metadata?.hasLoginForm) ||
    Boolean(pageContentIntel?.hasPasswordField) ||
    urlFeatures.matchedKeywords.length > 0;

  if (brandDetected) {
    let correlationPoints = 0;

    if (hasCredForm) {
      correlationPoints += 25;
      evidence.push({
        source: 'Correlation Engine',
        finding: 'Multi-signal correlation: Brand impersonation combined with credential input form.',
        impact: 'HIGH_RISK',
        actual: true,
        category: 'BRAND_IMPERSONATION',
      });
    }

    if (domainRegIntel?.isNewlyRegistered || domainRegIntel?.isYoungDomain) {
      correlationPoints += 20;
      evidence.push({
        source: 'Correlation Engine',
        finding: 'Multi-signal correlation: Brand impersonation combined with newly registered domain.',
        impact: 'HIGH_RISK',
        actual: true,
        category: 'BRAND_IMPERSONATION',
      });
    }

    if (urlFeatures.matchedKeywords && urlFeatures.matchedKeywords.length > 0) {
      correlationPoints += 15;
    }

    if (urlFeatures.isRiskyTld) {
      correlationPoints += 10;
    }

    if (redirectIntel.destinationChanged || redirectIntel.hopCount > 1) {
      correlationPoints += 10;
    }

    totalRisk += correlationPoints;
  }

  // Clamp total risk score between 0 and 100
  const finalRiskScore = Math.min(100, Math.max(0, Math.round(totalRisk)));

  // ==========================================
  // 8. DYNAMIC CONFIDENCE SCORE CALCULATION
  // ==========================================

  let confidence = 0;

  // 1. Local URL & Brand Analysis (+15 to +20)
  confidence += 15;
  if (!urlFeatures.hasIpHost && !urlFeatures.hasPunycode && !urlFeatures.hasAtSymbol) {
    confidence += 5;
  }

  // 2. Domain Registration Intel Coverage (+10)
  if (domainRegIntel && domainRegIntel.status === 'CHECKED') {
    confidence += 10;
  }

  // 3. DNS Analysis Coverage (+15% if resolved, +5% for IP diversity / MX / NS records)
  if (domainIntel.isResolvable) {
    confidence += 15;
    const ipCount = (domainIntel.ipAddresses || []).length + (domainIntel.ipv6Addresses || []).length;
    if (ipCount > 1) {
      confidence += 5;
    } else if (domainIntel.hasMx || (domainIntel.nsRecords && domainIntel.nsRecords.length > 0)) {
      confidence += 5;
    }
  }

  // 4. SSL/TLS Analysis Coverage (+10 to +15)
  if (sslIntel.protocol || !sslIntel.httpsEnabled) {
    confidence += 10;
    if (sslIntel.certificateValid && sslIntel.issuer) {
      confidence += 5;
    }
  }

  // 5. Redirect Analysis Coverage (+10%)
  if (!redirectIntel.error) {
    confidence += 10;
  }

  // 6. Threat Intelligence Provider Responses (+10% per provider that returned CLEAN or FLAGGED)
  const activeCleanOrFlaggedCount = cleanProviders.length + flaggedIntel.length;
  confidence += activeCleanOrFlaggedCount * 10;

  // Bonus for verified threat evidence or multi-signal strong correlation
  if (flaggedIntel.length > 0 || (urlFeatures.brandImpersonation?.detected && (domainRegIntel?.isNewlyRegistered || urlFeatures.matchedKeywords.length > 0))) {
    confidence += 5;
  }

  const finalConfidenceScore = Math.min(100, Math.max(0, Math.round(confidence)));

  // ==========================================
  // 9. VERDICT DETERMINATION
  // ==========================================

  let verdict: RiskVerdict = 'SAFE';
  let riskCategory = 'SAFE / VERY LOW RISK';

  if (finalRiskScore >= 80) {
    verdict = 'CRITICAL';
    riskCategory = 'CRITICAL / MALICIOUS';
  } else if (finalRiskScore >= 60) {
    verdict = 'HIGH_RISK';
    riskCategory = 'HIGH RISK';
  } else if (finalRiskScore >= 35) {
    verdict = 'SUSPICIOUS';
    riskCategory = 'SUSPICIOUS';
  } else if (finalRiskScore >= 15) {
    verdict = 'LOW_RISK';
    riskCategory = 'LOW RISK';
  } else {
    verdict = 'SAFE';
    riskCategory = 'SAFE / VERY LOW RISK';
  }

  // ==========================================
  // 10. FAIL-CLOSED GUARD RAILS & UNKNOWN RULES
  // ==========================================

  if (flaggedIntel.length > 0) {
    if (verdict !== 'CRITICAL' && verdict !== 'HIGH_RISK') {
      verdict = 'CRITICAL';
      riskCategory = 'CRITICAL / MALICIOUS';
    }
  }

  if (urlFeatures.brandImpersonation?.detected || urlFeatures.hasHomoglyphs) {
    if (verdict === 'SAFE' || verdict === 'LOW_RISK') {
      verdict = 'SUSPICIOUS';
      riskCategory = 'SUSPICIOUS (LOOKALIKE BRAND)';
    }
  }

  // If domain is unresolvable or redirect failed (SSRF block) and no active threat features found, return UNKNOWN / SUSPICIOUS
  if (verdict === 'SAFE' || verdict === 'LOW_RISK' || verdict === 'SUSPICIOUS') {
    const isUnresolvable = !domainIntel.isResolvable;
    const isRedirectFailed = Boolean(redirectIntel.error && redirectIntel.error.includes('SSRF'));

    if (isUnresolvable || isRedirectFailed) {
      if (finalRiskScore >= 35) {
        verdict = 'SUSPICIOUS';
        riskCategory = 'SUSPICIOUS (INCOMPLETE EVIDENCE)';
      } else {
        verdict = 'UNKNOWN';
        riskCategory = 'UNKNOWN (INSUFFICIENT EVIDENCE)';
      }
    }
  }

  // ==========================================
  // 11. DYNAMIC URL-SPECIFIC EXPLANATION GENERATOR
  // ==========================================

  const explanationParts: string[] = [];

  // Part 1: Primary Threat Intelligence Findings (if any provider flagged)
  if (flaggedIntel.length > 0) {
    const providerDetails = flaggedIntel.map((ti) => {
      if (ti.stats?.maliciousEngineCount) {
        return `${ti.providerName} (${ti.stats.maliciousEngineCount}/${ti.stats.totalEngineCount} engines flagged)`;
      }
      if (ti.details && ti.details.includes('PhishTank database verified')) {
        return `blacklisted by ${ti.providerName} (${ti.details})`;
      }
      return `blacklisted by ${ti.providerName} (${ti.threatType || 'malicious'})`;
    });

    explanationParts.push(`Confirmed threat detection: This URL was explicitly ${providerDetails.join(', ')}.`);
  }

  // Part 2: Local Heuristic Reasons (Evidence / Risk Contributors)
  const localHeuristicReasons: string[] = [];
  if (urlFeatures.brandImpersonation?.detected) {
    localHeuristicReasons.push(urlFeatures.brandImpersonation.evidence);
  }
  if (params.urlscanResult?.metadata?.detectedBrand && !urlFeatures.brandImpersonation?.detected) {
    localHeuristicReasons.push(`URLscan detected brand impersonation in page title ('${params.urlscanResult.metadata.pageTitle}').`);
  }
  if (params.urlscanResult?.metadata?.crossDomainFormSubmission) {
    localHeuristicReasons.push(`Scanned page submits credential form data to a cross-domain external host ('${params.urlscanResult.metadata.formTargetDomain || 'external'}').`);
  }
  if (params.urlscanResult?.metadata?.hasPasswordField) {
    localHeuristicReasons.push('URLscan DOM analysis detected a credential / password collection form.');
  }
  if (urlFeatures.hasIpHost) {
    localHeuristicReasons.push(`The URL uses a raw IP address (${urlFeatures.hostname}) instead of a domain name.`);
  }
  if (urlFeatures.hasPunycode || urlFeatures.hasHomoglyphs) {
    localHeuristicReasons.push(`Non-Latin lookalike / punycode characters (${urlFeatures.punycodeDecoded || urlFeatures.hostname}) were detected.`);
  }
  if (urlFeatures.hasAtSymbol) {
    localHeuristicReasons.push('Userinfo delimiter (@) present in URL, which can disguise the true host destination.');
  }
  if (urlFeatures.matchedKeywords && urlFeatures.matchedKeywords.length > 0) {
    const kw = urlFeatures.matchedKeywords.map((k) => k.keyword).join(', ');
    localHeuristicReasons.push(`The URL path/query contains credential-related keywords (${kw}).`);
  }
  if (domainRegIntel?.isNewlyRegistered) {
    localHeuristicReasons.push(`Domain is newly registered (${domainRegIntel.domainAgeDays} days old).`);
  } else if (domainRegIntel?.isYoungDomain) {
    localHeuristicReasons.push(`Domain registration age is under 90 days (${domainRegIntel.domainAgeDays} days old).`);
  }
  if (urlFeatures.isRiskyTld) {
    localHeuristicReasons.push(`Top-level domain .${urlFeatures.tld} has an elevated security abuse rate.`);
  }
  if (urlFeatures.isKnownShortener) {
    localHeuristicReasons.push(`URL uses shortener service (${urlFeatures.shortenerName || 'Shortener'}).`);
  }
  if (urlFeatures.hasNestedUrl) {
    localHeuristicReasons.push('Embedded nested URL structure detected in parameter/path payload.');
  }
  if (urlFeatures.suspiciousFileExtension) {
    localHeuristicReasons.push(`URL path targets script/executable extension (.${urlFeatures.suspiciousFileExtension}).`);
  }
  if (urlFeatures.unusualPort) {
    localHeuristicReasons.push(`Non-standard service port ${urlFeatures.port} used in URL.`);
  }
  if (!domainIntel.isResolvable) {
    localHeuristicReasons.push(`DNS resolution failed for hostname '${urlFeatures.hostname}'.`);
  }
  if (!sslIntel.httpsEnabled) {
    localHeuristicReasons.push('Connection uses unencrypted HTTP.');
  } else {
    if (sslIntel.isExpired) {
      localHeuristicReasons.push('TLS certificate presented by the server has expired.');
    }
    if (sslIntel.isSelfSigned) {
      localHeuristicReasons.push('Untrusted self-signed TLS certificate.');
    }
    if (!sslIntel.hostnameMatches && sslIntel.certificateValid) {
      localHeuristicReasons.push(`TLS certificate hostname mismatch (Issued to: '${sslIntel.subject || 'Unknown'}').`);
    }
  }
  if (redirectIntel.hopCount > 1) {
    localHeuristicReasons.push(`URL undergoes ${redirectIntel.hopCount} redirect steps before reaching destination.`);
  }
  if (redirectIntel.destinationChanged) {
    localHeuristicReasons.push('Cross-domain redirect shifts destination.');
  }

  // Push local heuristic reasons to explanationParts
  explanationParts.push(...localHeuristicReasons);

  // Part 3: Positive Infrastructure Verification (if resolvable or valid TLS)
  if (domainIntel.isResolvable) {
    explanationParts.push(`DNS resolution succeeded (${(domainIntel.ipAddresses || []).join(', ') || 'verified'}).`);
  }
  if (sslIntel.httpsEnabled && sslIntel.certificateValid && sslIntel.hostnameMatches) {
    explanationParts.push(`TLS certificate is valid and issued to '${urlFeatures.hostname}'.`);
  }

  // Part 4: Threat Intelligence Coverage Summary
  if (flaggedIntel.length === 0) {
    if (verdict === 'CRITICAL' || verdict === 'HIGH_RISK' || verdict === 'SUSPICIOUS' || localHeuristicReasons.length > 0) {
      if (cleanProviders.length > 0) {
        explanationParts.push('Threat intelligence coverage was limited because configured providers did not return a confirmed match.');
      } else {
        explanationParts.push('Threat intelligence coverage was limited because configured providers were not configured or unavailable.');
      }
    } else if (cleanProviders.length > 0) {
      explanationParts.push(`No threat intelligence matches were reported by ${cleanProviders.join(', ')}.`);
    }
  }

  // Part 4: Coverage & Missing Providers
  const missingProviders = [...unconfiguredProviders, ...unavailableProviders];
  if (missingProviders.length > 0) {
    explanationParts.push(
      `Note: ${missingProviders.join(', ')} ${
        unconfiguredProviders.length > 0 ? 'were not configured for this server deployment' : 'were unavailable'
      }, resulting in an evidence confidence score of ${finalConfidenceScore}%.`
    );
  }

  const explanation = explanationParts.join(' ');

  // Summary mapping
  let summary = '';
  if (verdict === 'CRITICAL' || verdict === 'HIGH_RISK') {
    summary = `CRITICAL THREAT: ${explanationParts[0] || 'Severe malicious indicators detected.'}`;
  } else if (verdict === 'SUSPICIOUS') {
    summary = `SUSPICIOUS URL: ${explanationParts[0] || explanationParts[1] || 'Exhibits lookalike or suspicious indicators.'}`;
  } else if (verdict === 'UNKNOWN') {
    summary = `UNKNOWN / INSUFFICIENT EVIDENCE: Evidence confidence is ${finalConfidenceScore}%. Critical reputation providers were not configured or unreachable.`;
  } else if (verdict === 'LOW_RISK') {
    summary = `LOW RISK: Minimal risk indicators detected. Confidence is ${finalConfidenceScore}%.`;
  } else {
    summary = `SAFE: DNS and TLS infrastructure verified with no threat detections. Confidence is ${finalConfidenceScore}%.`;
  }

  return {
    riskScore: finalRiskScore,
    confidenceScore: finalConfidenceScore,
    verdict,
    riskCategory,
    summary,
    explanation,
    evidence,
    signals,
  };
}

