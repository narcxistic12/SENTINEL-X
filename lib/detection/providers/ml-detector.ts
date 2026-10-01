import { UrlFeatures, MlDetectionResult, FeatureVectorItem } from '@/types/security';

export interface DetectionProvider {
  name: string;
  detect(features: UrlFeatures): Promise<MlDetectionResult>;
}

/**
 * Extracts normalized numeric feature vector (0.0 to 1.0) from raw URL features.
 * Prepares input for Random Forest, XGBoost, or Neural Network classification.
 */
export function extractMlFeatureVector(features: UrlFeatures): FeatureVectorItem[] {
  return [
    {
      name: 'url_length',
      value: features.length,
      normalized: Math.min(1.0, features.length / 200),
      weight: 0.15,
    },
    {
      name: 'shannon_entropy',
      value: features.entropy,
      normalized: Math.min(1.0, features.entropy / 6.0),
      weight: 0.2,
    },
    {
      name: 'subdomain_depth',
      value: features.subdomainCount,
      normalized: Math.min(1.0, features.subdomainCount / 4),
      weight: 0.15,
    },
    {
      name: 'has_ip_host',
      value: features.hasIpHost ? 1 : 0,
      normalized: features.hasIpHost ? 1.0 : 0.0,
      weight: 0.35,
    },
    {
      name: 'has_at_symbol',
      value: features.hasAtSymbol ? 1 : 0,
      normalized: features.hasAtSymbol ? 1.0 : 0.0,
      weight: 0.3,
    },
    {
      name: 'has_punycode_or_homoglyph',
      value: features.hasPunycode || features.hasHomoglyphs ? 1 : 0,
      normalized: features.hasPunycode || features.hasHomoglyphs ? 1.0 : 0.0,
      weight: 0.4,
    },
    {
      name: 'suspicious_keywords_count',
      value: features.matchedKeywords.length,
      normalized: Math.min(1.0, features.matchedKeywords.length / 3),
      weight: 0.3,
    },
    {
      name: 'hyphen_count',
      value: features.hyphenCount,
      normalized: Math.min(1.0, features.hyphenCount / 5),
      weight: 0.1,
    },
    {
      name: 'dot_count',
      value: features.dotCount,
      normalized: Math.min(1.0, features.dotCount / 6),
      weight: 0.1,
    },
    {
      name: 'is_known_shortener',
      value: features.isKnownShortener ? 1 : 0,
      normalized: features.isKnownShortener ? 1.0 : 0.0,
      weight: 0.15,
    },
    {
      name: 'is_risky_tld',
      value: features.isRiskyTld ? 1 : 0,
      normalized: features.isRiskyTld ? 1.0 : 0.0,
      weight: 0.25,
    },
    {
      name: 'query_param_count',
      value: features.paramCount,
      normalized: Math.min(1.0, features.paramCount / 5),
      weight: 0.1,
    },
  ];
}

export class MLDetector implements DetectionProvider {
  public name = 'SentinelX ML Classification Engine';

  public async detect(features: UrlFeatures): Promise<MlDetectionResult> {
    const vector = extractMlFeatureVector(features);
    const endpoint = process.env.ML_MODEL_ENDPOINT;

    // Honest handling: do not fabricate ML predictions without an actual model configured
    if (!endpoint) {
      return {
        status: 'NOT_CONFIGURED',
        modelVersion: 'SentinelX-URL-v1 (Pending Model Deployment)',
        extractedFeatureVector: vector,
        note: 'ML model server not configured. Extracted 12-point URL vector is ready for inference deployment.',
      };
    }

    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ features: vector }),
      });

      if (!res.ok) {
        return {
          status: 'UNAVAILABLE',
          extractedFeatureVector: vector,
          note: `ML Inference server error: HTTP ${res.status}`,
        };
      }

      const data = await res.json();
      return {
        status: 'AVAILABLE',
        prediction: data.prediction,
        confidencePercentage: data.confidence,
        modelVersion: data.model_version || 'SentinelX-ML-Production',
        extractedFeatureVector: vector,
        note: 'ML prediction generated from real inference endpoint.',
      };
    } catch {
      return {
        status: 'UNAVAILABLE',
        extractedFeatureVector: vector,
        note: 'Could not connect to ML inference server.',
      };
    }
  }
}
