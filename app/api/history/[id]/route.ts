import { NextRequest, NextResponse } from 'next/server';
import prisma from '@/lib/prisma';
import { ScanReport } from '@/types/security';
import { authenticateRequest, logSecurityEvent } from '@/lib/security/auth';

export const dynamic = 'force-dynamic';

export async function GET(
  req: NextRequest,
  { params }: { params: { id: string } }
) {
  const scanId = params.id;

  if (!scanId || typeof scanId !== 'string') {
    return NextResponse.json({ error: 'Invalid scan ID format' }, { status: 400 });
  }

  if (!process.env.DATABASE_URL) {
    return NextResponse.json({ error: 'Database not configured' }, { status: 503 });
  }

  try {
    const user = await authenticateRequest(req);

    const scan = await prisma.scan.findUnique({
      where: { id: scanId },
    });

    if (!scan) {
      return NextResponse.json({ error: 'Scan record not found' }, { status: 404 });
    }

    // SERVER-SIDE AUTHORIZATION & OWNERSHIP CHECK (IDOR Prevention)
    // If scan is assigned to a user, caller must be owner OR an admin
    if (scan.userId) {
      if (!user) {
        await logSecurityEvent({
          actor: 'UNAUTHENTICATED',
          action: 'GET_SCAN_BY_ID',
          target: scanId,
          status: 'BLOCKED',
          details: 'Unauthenticated attempt to access private scan',
        });
        return NextResponse.json({ error: 'Unauthorized access to scan report' }, { status: 401 });
      }

      if (user.role !== 'ADMIN' && scan.userId !== user.id) {
        await logSecurityEvent({
          actor: user.id,
          action: 'GET_SCAN_BY_ID',
          target: scanId,
          status: 'BLOCKED',
          details: `User ${user.id} attempted IDOR access to scan owned by ${scan.userId}`,
        });
        return NextResponse.json({ error: 'Forbidden: You do not own this scan report' }, { status: 403 });
      }
    }

    const report = scan.fullReport as unknown as ScanReport;
    return NextResponse.json(report, { status: 200 });
  } catch (err) {
    console.error(`Failed to fetch scan ID ${scanId}:`, err);
    return NextResponse.json({ error: 'Failed to retrieve scan record' }, { status: 500 });
  }
}

export async function DELETE(
  req: NextRequest,
  { params }: { params: { id: string } }
) {
  const scanId = params.id;

  if (!scanId || typeof scanId !== 'string') {
    return NextResponse.json({ error: 'Invalid scan ID format' }, { status: 400 });
  }

  if (!process.env.DATABASE_URL) {
    return NextResponse.json({ error: 'Database not configured' }, { status: 503 });
  }

  try {
    const user = await authenticateRequest(req);

    if (!user) {
      return NextResponse.json({ error: 'Authentication required for scan deletion' }, { status: 401 });
    }

    const scan = await prisma.scan.findUnique({
      where: { id: scanId },
    });

    if (!scan) {
      return NextResponse.json({ error: 'Scan record not found' }, { status: 404 });
    }

    // Ownership check for deletion
    if (user.role !== 'ADMIN' && scan.userId !== user.id) {
      await logSecurityEvent({
        actor: user.id,
        action: 'DELETE_SCAN_BY_ID',
        target: scanId,
        status: 'BLOCKED',
        details: `User ${user.id} attempted unauthorized deletion of scan owned by ${scan.userId}`,
      });
      return NextResponse.json({ error: 'Forbidden: You do not have permission to delete this scan' }, { status: 403 });
    }

    await prisma.scan.delete({
      where: { id: scanId },
    });

    await logSecurityEvent({
      actor: user.id,
      action: 'DELETE_SCAN_BY_ID',
      target: scanId,
      status: 'SUCCESS',
    });

    return NextResponse.json({ message: 'Scan deleted successfully', id: scanId }, { status: 200 });
  } catch (err) {
    console.error(`Failed to delete scan ID ${scanId}:`, err);
    return NextResponse.json({ error: 'Failed to delete scan record' }, { status: 500 });
  }
}
