import { EvidenceItem } from '@/types/security';

export class EvidenceAggregator {
  private evidenceMap = new Map<string, EvidenceItem>();

  public addEvidence(items: EvidenceItem | EvidenceItem[]): void {
    const list = Array.isArray(items) ? items : [items];

    for (const item of list) {
      if (!item || !item.finding) continue;

      // Construct unique deduplication key per provider & finding category
      const normalizedFinding = item.finding.toLowerCase().trim();
      const dedupeKey = `${item.source.toLowerCase()}:${item.category || 'general'}:${normalizedFinding}`;

      if (!this.evidenceMap.has(dedupeKey)) {
        this.evidenceMap.set(dedupeKey, {
          ...item,
          finding: item.finding.trim(),
        });
      }
    }
  }

  public getEvidence(): EvidenceItem[] {
    return Array.from(this.evidenceMap.values());
  }

  public getHighRiskEvidence(): EvidenceItem[] {
    return this.getEvidence().filter((e) => e.impact === 'HIGH_RISK');
  }

  public getMediumRiskEvidence(): EvidenceItem[] {
    return this.getEvidence().filter((e) => e.impact === 'MEDIUM_RISK');
  }
}
