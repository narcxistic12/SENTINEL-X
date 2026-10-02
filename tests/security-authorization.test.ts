import { describe, it, expect } from 'vitest';
import { authenticateRequest } from '../lib/security/auth';
import { NextRequest } from 'next/server';

describe('SENTINELX Authorization & Security Tests', () => {
  it('Authentication returns null for unauthenticated requests', async () => {
    const req = new NextRequest('http://localhost:3000/api/history');
    const user = await authenticateRequest(req);
    expect(user).toBeNull();
  });

  it('Authentication identifies user role from valid user token', async () => {
    const req = new NextRequest('http://localhost:3000/api/history', {
      headers: { Authorization: 'Bearer sess_user_alice123' },
    });
    const user = await authenticateRequest(req);
    expect(user).not.toBeNull();
    expect(user?.id).toBe('alice123');
    expect(user?.role).toBe('USER');
  });

  it('Authentication identifies admin role from valid admin token', async () => {
    const req = new NextRequest('http://localhost:3000/api/admin/stats', {
      headers: { Authorization: 'Bearer sess_admin_bob99' },
    });
    const user = await authenticateRequest(req);
    expect(user).not.toBeNull();
    expect(user?.role).toBe('ADMIN');
  });

  it('/api/admin/stats blocks unauthenticated requests with 403', async () => {
    const { GET } = await import('../app/api/admin/stats/route');
    const req = new NextRequest('http://localhost:3000/api/admin/stats');
    const res = await GET(req);
    expect(res.status).toBe(403);
  });

  it('/api/admin/stats blocks USER role requests with 403', async () => {
    const { GET } = await import('../app/api/admin/stats/route');
    const req = new NextRequest('http://localhost:3000/api/admin/stats', {
      headers: { Authorization: 'Bearer sess_user_charlie' },
    });
    const res = await GET(req);
    expect(res.status).toBe(403);
  });

  it('/api/admin/stats allows ADMIN role requests', async () => {
    const { GET } = await import('../app/api/admin/stats/route');
    const req = new NextRequest('http://localhost:3000/api/admin/stats', {
      headers: { Authorization: 'Bearer sess_admin_root' },
    });
    const res = await GET(req);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.systemStatus).toBeDefined();
  });
});

