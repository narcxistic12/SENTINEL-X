import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

export async function GET() {
  return NextResponse.json({
    status: 'healthy',
    service: 'SENTINELX Threat Intelligence & Phishing Scanner',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    providers: {
      urlhaus: true,
      googleSafeBrowsing: Boolean(process.env.GOOGLE_SAFE_BROWSING_API_KEY),
      virusTotal: Boolean(process.env.VIRUSTOTAL_API_KEY),
      phishTank: Boolean(process.env.PHISHTANK_API_KEY),
      mlModelEndpoint: Boolean(process.env.ML_MODEL_ENDPOINT),
      database: Boolean(process.env.DATABASE_URL),
    },
  });
}
