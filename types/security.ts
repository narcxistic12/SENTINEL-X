export type RiskVerdict =
  | 'SAFE'
  | 'LOW_RISK'
  | 'SUSPICIOUS'
  | 'HIGH_RISK'
  | 'CRITICAL'
  | 'UNKNOWN';

export type SignalSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type SignalStatus = 'pass' | 'warning' | 'fail' | 'info';

export type SignalSource =
  | 'LOCAL ANALYSIS'
  | 'DOMAIN ANALYSIS'
  | 'THREAT INTELLIGENCE'
  | 'SSL/TLS'
  | 'REDIRECT ANALYSIS'
  | 'ML MODEL'
  | 'UNAVAILABLE';

export interface SecuritySignal {
  id: string;
  title: string;
  explanation: string;
  severity: SignalSeverity;
  status: SignalStatus;
  source: SignalSource;
  points: number; // impact contributed to risk calculation
  technicalDetails?: Record<string, unknown>;
}

export interface MatchedKeyword {
  category: 'authentication' | 'payment' | 'urgency' | 'impersonation';
  keyword: string;
  location: 'host' | 'path' | 'query';
}

export interface UrlFeatures {
  rawUrl: string;
  normalizedUrl: string;
  protocol: string;
  hostname: string;
  port: number | null;
  path: string;
  queryString: string;
  fragment: string;
  length: number;
  paramCount: number;
  subdomainCount: number;
  subdomains: string[];
  tld: string;
  hasIpHost: boolean;
  isIpv6: boolean;
  hasAtSymbol: boolean;
  hasPunycode: boolean;
  punycodeDecoded?: string;
  hasHomoglyphs: boolean;
  homoglyphsFound: string[];
  hyphenCount: number;
  dotCount: number;
  percentEncodedCount: number;
  entropy: number;
  matchedKeywords: MatchedKeyword[];
  isKnownShortener: boolean;
  shortenerName?: string;
  isRiskyTld: boolean;
  brandImpersonation?: {
    detected: boolean;
    brandFound?: string;
    evidence: string;
    similarityType?: 'subdomain_spoof' | 'affix_spoof' | 'typosquatting';
    officialDomain?: string;
    isOfficialDomainMatch?: boolean;
  };
  pathSegmentCount?: number;
  hasNestedUrl?: boolean;
  suspiciousQueryParams?: string[];
  suspiciousFileExtension?: string | null;
  unusualPort?: boolean;
}

export interface DomainIntelligence {
  domain: string;
  tld: string;
  isResolvable: boolean;
  ipAddresses: string[];
  ipv6Addresses: string[];
  mxRecords: { exchange: string; priority: number }[];
  txtRecords: string[][];
  nsRecords: string[];
  hasMx: boolean;
  domainAgeEstimateDays: number | null;
  registrationDate: string | null;
  expirationDate: string | null;
  registrar: string | null;
  isAvailable: boolean;
  lookupError?: string;
}

export interface SslIntelligence {
  httpsEnabled: boolean;
  certificateValid: boolean;
  hostnameMatches: boolean;
  issuer: string | null;
  subject: string | null;
  validFrom: string | null;
  validTo: string | null;
  daysUntilExpiration: number | null;
  protocol: string | null;
  cipher: string | null;
  isSelfSigned: boolean;
  isExpired: boolean;
  error?: string;
  disclaimer: string;
}

export interface RedirectHop {
  hopNumber: number;
  url: string;
  statusCode: number;
  targetUrl: string;
  crossDomain: boolean;
  durationMs: number;
}

export interface RedirectIntelligence {
  originalUrl: string;
  finalUrl: string;
  hopCount: number;
  hops: RedirectHop[];
  destinationChanged: boolean;
  loopDetected: boolean;
  ssrfBlocked: boolean;
  error?: string;
}

export type ThreatIntelStatus =
  | 'CHECKED'
  | 'NOT_CONFIGURED'
  | 'UNAVAILABLE'
  | 'FLAGGED'
  | 'CLEAN'
  | 'TIMEOUT'
  | 'ERROR'
  | 'RATE_LIMITED';

export interface ThreatIntelResult {
  providerName: string;
  status: ThreatIntelStatus;
  isFlagged: boolean;
  threatType?: string;
  details?: string;
  lastChecked?: string;
  stats?: {
    maliciousEngineCount?: number;
    suspiciousEngineCount?: number;
    harmlessEngineCount?: number;
    undetectedEngineCount?: number;
    totalEngineCount?: number;
  };
}

export interface FeatureVectorItem {
  name: string;
  value: number;
  normalized: number;
  weight: number;
}

export interface MlDetectionResult {
  status: 'AVAILABLE' | 'NOT_CONFIGURED' | 'UNAVAILABLE';
  prediction?: 'SAFE' | 'PHISHING' | 'SUSPICIOUS';
  confidencePercentage?: number;
  modelVersion?: string;
  extractedFeatureVector: FeatureVectorItem[];
  note: string;
}

export type ExternalAnalysisStatus =
  | 'CLEAN'
  | 'FLAGGED'
  | 'NOT_CONFIGURED'
  | 'SUBMITTED'
  | 'PENDING'
  | 'TIMEOUT'
  | 'ERROR'
  | 'UNAVAILABLE'
  | 'RATE_LIMITED';

export interface ExternalAnalysisResult {
  providerName: string;
  status: ExternalAnalysisStatus;
  isFlagged: boolean;
  threatType?: string;
  details?: string;
  scanUuid?: string;
  resultUrl?: string;
  evidence: EvidenceItem[];
  metadata?: {
    screenshotUrl?: string;
    pageTitle?: string;
    pageDomain?: string;
    contactedDomainsCount?: number;
    contactedIpsCount?: number;
    hasLoginForm?: boolean;
    hasPasswordField?: boolean;
    crossDomainFormSubmission?: boolean;
    formTargetDomain?: string;
    detectedBrand?: string;
    verdictScore?: number;
    tags?: string[];
    [key: string]: unknown;
  };
}

export interface ExternalAnalysisProvider {
  name: string;
  isConfigured(): boolean;
  analyze(url: string): Promise<ExternalAnalysisResult>;
}

export interface AnalysisCoverage {
  urlStructure: 'CHECKED' | 'FAILED';
  domainIntelligence: 'CHECKED' | 'UNAVAILABLE' | 'FAILED';
  sslTls: 'CHECKED' | 'NOT_APPLICABLE' | 'UNAVAILABLE' | 'FAILED';
  redirects: 'CHECKED' | 'UNAVAILABLE' | 'FAILED';
  threatIntelligence: 'CHECKED' | 'NOT_CONFIGURED' | 'UNAVAILABLE';
  mlDetection: 'CHECKED' | 'NOT_CONFIGURED' | 'UNAVAILABLE';
  externalAnalysis?: 'CHECKED' | 'NOT_CONFIGURED' | 'UNAVAILABLE' | 'PENDING' | 'TIMEOUT';
}

export type SecurityEvidenceCategory =
  | 'URL_STRUCTURE'
  | 'DOMAIN'
  | 'BRAND_IMPERSONATION'
  | 'DOMAIN_AGE'
  | 'DNS'
  | 'TLS'
  | 'REDIRECT'
  | 'THREAT_INTELLIGENCE'
  | 'IP_REPUTATION'
  | 'PUNYCODE'
  | 'KEYWORD'
  | 'SSRF'
  | 'REGISTRATION'
  | 'PAGE_CONTENT'
  | 'CROSS_DOMAIN_CREDENTIAL_SUBMISSION'
  | 'BEHAVIOR'
  | 'EXTERNAL_ANALYSIS';

export interface SecurityEvidence {
  category: SecurityEvidenceCategory;
  source: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  details?: Record<string, unknown>;
}

export interface DomainRegistrationIntelligence {
  status: 'CHECKED' | 'NOT_CONFIGURED' | 'UNAVAILABLE' | 'TIMEOUT' | 'ERROR';
  domainAgeDays: number | null;
  registrationDate: string | null;
  expirationDate: string | null;
  registrar: string | null;
  isNewlyRegistered: boolean; // < 30 days
  isYoungDomain: boolean; // < 90 days
  nameservers: string[];
  details?: string;
}

export interface PageContentAnalysisResult {
  status: 'AVAILABLE' | 'DISABLED' | 'UNAVAILABLE' | 'SKIPPED_SSRF_PROTECTION';
  hasLoginForm?: boolean;
  hasPasswordField?: boolean;
  hasPaymentForm?: boolean;
  externalFormSubmission?: boolean;
  suspiciousScripts?: boolean;
  pageTitleMatchBrand?: boolean;
  note: string;
}

export interface EvidenceItem {
  source: string;
  finding: string;
  impact: 'HIGH_RISK' | 'MEDIUM_RISK' | 'LOW_RISK' | 'NEUTRAL' | 'CONFIDENCE_REDUCTION' | 'POSITIVE_BENIGN';
  actual: boolean;
  category?: SecurityEvidenceCategory;
}

export interface ProviderStatusSummary {
  provider: string;
  status: ExternalAnalysisStatus | ThreatIntelStatus;
  available: boolean;
  scanId?: string;
  reportUrl?: string;
  findingsCount?: number;
  details?: string;
}

export interface DynamicAnalysisReport {
  available: boolean;
  providers: ProviderStatusSummary[];
  findings: EvidenceItem[];
}

export interface ScanReport {
  id: string;
  url: string;
  normalizedUrl: string;
  scanTimestamp: string;
  durationMs: number;
  verdict: RiskVerdict;
  riskScore: number; // 0 to 100
  confidenceScore: number; // 0 to 100
  riskCategory: string;
  summary: string;
  explanation?: string;
  evidence?: EvidenceItem[];
  signals: SecuritySignal[];
  urlFeatures: UrlFeatures;
  domainIntel: DomainIntelligence;
  domainRegIntel?: DomainRegistrationIntelligence;
  sslIntel: SslIntelligence;
  redirectIntel: RedirectIntelligence;
  threatIntel: ThreatIntelResult[];
  mlDetection: MlDetectionResult;
  pageContentIntel?: PageContentAnalysisResult;
  urlscanResult?: ExternalAnalysisResult;
  anyrunResult?: ExternalAnalysisResult;
  cloudflareResult?: ExternalAnalysisResult;
  urlscansResult?: ExternalAnalysisResult;
  virustotalFreshResult?: ExternalAnalysisResult;
  externalIntel?: ExternalAnalysisResult[];
  providers?: Record<string, ProviderStatusSummary>;
  dynamicAnalysis?: DynamicAnalysisReport;
  recommendations?: string[];
  coverage: AnalysisCoverage;
}

export interface ScanHistoryItem {
  id: string;
  url: string;
  hostname: string;
  verdict: RiskVerdict;
  riskScore: number;
  confidenceScore: number;
  scanTimestamp: string;
  threatCount: number;
  warningCount: number;
}
