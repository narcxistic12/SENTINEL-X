import { ScanReport, RiskVerdict } from '@/types/security';

const STORAGE_KEY = 'phishguard_scans_v1';

export interface DashboardMetrics {
  totalScans: number;
  safeCount: number;
  lowRiskCount: number;
  suspiciousCount: number;
  threatCount: number;
  averageRiskScore: number;
  verdictDistribution: Record<RiskVerdict, number>;
  recentScans: ScanReport[];
}

export function saveScanReport(report: ScanReport): void {
  if (typeof window === 'undefined') return;

  try {
    const existing = getStoredScans();
    // Prepend new scan, remove duplicate id if present
    const updated = [report, ...existing.filter((item) => item.id !== report.id)].slice(0, 50);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
  } catch (err) {
    console.error('Failed to save scan report to localStorage:', err);
  }
}

export function getStoredScans(): ScanReport[] {
  if (typeof window === 'undefined') return [];

  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    return JSON.parse(raw) as ScanReport[];
  } catch (err) {
    console.error('Failed to read scans from localStorage:', err);
    return [];
  }
}

export async function fetchStoredScans(): Promise<ScanReport[]> {
  if (typeof window === 'undefined') return [];
  try {
    const res = await fetch('/api/history');
    if (res.ok) {
      const data = await res.json();
      return data as ScanReport[];
    }
    // Fallback to local storage if API fails (e.g. 503)
  } catch (err) {
    console.error('Failed to fetch from API, falling back to local storage', err);
  }
  return getStoredScans();
}

export function getScanById(id: string): ScanReport | null {
  const scans = getStoredScans();
  return scans.find((s) => s.id === id) || null;
}

export function deleteScanById(id: string): void {
  if (typeof window === 'undefined') return;

  const scans = getStoredScans().filter((s) => s.id !== id);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(scans));
}

export function clearAllScans(): void {
  if (typeof window === 'undefined') return;
  localStorage.removeItem(STORAGE_KEY);
}

export function computeDashboardMetrics(scans: ScanReport[]): DashboardMetrics {
  const total = scans.length;

  if (total === 0) {
    return {
      totalScans: 0,
      safeCount: 0,
      lowRiskCount: 0,
      suspiciousCount: 0,
      threatCount: 0,
      averageRiskScore: 0,
      verdictDistribution: {
        SAFE: 0,
        LOW_RISK: 0,
        SUSPICIOUS: 0,
        HIGH_RISK: 0,
        CRITICAL: 0,
        UNKNOWN: 0,
      },
      recentScans: [],
    };
  }

  let totalScore = 0;
  let safeCount = 0;
  let lowRiskCount = 0;
  let suspiciousCount = 0;
  let threatCount = 0;

  const verdictDistribution: Record<RiskVerdict, number> = {
    SAFE: 0,
    LOW_RISK: 0,
    SUSPICIOUS: 0,
    HIGH_RISK: 0,
    CRITICAL: 0,
    UNKNOWN: 0,
  };

  for (const scan of scans) {
    totalScore += scan.riskScore;
    verdictDistribution[scan.verdict] = (verdictDistribution[scan.verdict] || 0) + 1;

    if (scan.verdict === 'SAFE') safeCount++;
    else if (scan.verdict === 'LOW_RISK') lowRiskCount++;
    else if (scan.verdict === 'SUSPICIOUS') suspiciousCount++;
    else if (scan.verdict === 'HIGH_RISK' || scan.verdict === 'CRITICAL') threatCount++;
  }

  return {
    totalScans: total,
    safeCount,
    lowRiskCount,
    suspiciousCount,
    threatCount,
    averageRiskScore: Math.round(totalScore / total),
    verdictDistribution,
    recentScans: scans.slice(0, 10),
  };
}
