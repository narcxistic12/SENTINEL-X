import { NextRequest, NextResponse } from 'next/server';
import prisma from '@/lib/prisma';
import { authenticateRequest, logSecurityEvent } from '@/lib/security/auth';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  try {
    const user = await authenticateRequest(req);

    if (!user || user.role !== 'ADMIN') {
      await logSecurityEvent({
        actor: user ? user.id : 'UNAUTHENTICATED',
        action: 'ACCESS_ADMIN_STATS',
        target: '/api/admin/stats',
        status: 'BLOCKED',
        details: 'Non-admin attempted to access admin stats route',
      });
      return NextResponse.json({ error: 'Forbidden: Admin access required' }, { status: 403 });
    }

    if (!process.env.DATABASE_URL) {
      return NextResponse.json({
        systemStatus: 'ONLINE_SERVERLESS_NO_DB',
        totalUsers: 0,
        totalScansRecorded: 0,
      });
    }

    const [userCount, scanCount] = await Promise.all([
      prisma.user.count(),
      prisma.scan.count(),
    ]);

    await logSecurityEvent({
      actor: user.id,
      action: 'ACCESS_ADMIN_STATS',
      target: '/api/admin/stats',
      status: 'SUCCESS',
    });

    return NextResponse.json({
      systemStatus: 'OPERATIONAL',
      totalUsers: userCount,
      totalScansRecorded: scanCount,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error('Admin API error:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
