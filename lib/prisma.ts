import { PrismaClient } from '@prisma/client';

declare global {
  var prismaGlobal: PrismaClient | undefined;
}

function getPrismaClient(): PrismaClient {
  if (!globalThis.prismaGlobal) {
    globalThis.prismaGlobal = new PrismaClient();
  }
  return globalThis.prismaGlobal;
}

// Proxy wrapper so PrismaClient is ONLY instantiated when a query property is actually accessed at runtime
const prisma = new Proxy({} as PrismaClient, {
  get(_target, prop: keyof PrismaClient) {
    const client = getPrismaClient();
    const value = client[prop];
    if (typeof value === 'function') {
      return value.bind(client);
    }
    return value;
  },
});

export default prisma;

