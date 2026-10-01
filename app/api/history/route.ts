import { NextRequest, NextResponse } from 'next/server';
import prisma from '@/lib/prisma';
import { ScanReport } from '@/types/security';
import { authenticateRequest } from '@/lib/security/auth';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  if (!process.env.DATABASE_URL) {
    return NextResponse.json(
      { error: 'Database not configured' },
      { status: 503 }
    );
  }

  try {
    const user = await authenticateRequest(req);
    
    // Ownership / Scope Check:
    // If authenticated as normal user, show only user's scans or public unassigned scans.
    // If authenticated as ADMIN, allow all.
    // If unauthenticated, return public unassigned scans.
    const whereCondition = user
      ? user.role === 'ADMIN'
        ? {}
        : { OR: [{ userId: user.id }, { userId: null }] }
      : { userId: null };

    const scans = await prisma.scan.findMany({
      where: whereCondition,
      take: 100,
      orderBy: { createdAt: 'desc' },
    });

    const parsedScans: ScanReport[] = scans
      .filter((s) => s.fullReport)
      .map((s) => s.fullReport as unknown as ScanReport);

    return NextResponse.json(parsedScans, { status: 200 });
  } catch (err) {
    console.error('Failed to fetch scan history:', err);
    return NextResponse.json(
      { error: 'Failed to fetch scan history' },
      { status: 500 }
    );
  }
}
