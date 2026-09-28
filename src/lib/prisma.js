import { PrismaClient } from '@prisma/client';
import path from 'path';

if (!process.env.DATABASE_URL) {
  // Resolve absolute path to prisma/dev.db to avoid working directory issues across environments
  process.env.DATABASE_URL = `file:${path.resolve(process.cwd(), 'prisma/dev.db')}`;
}

const globalForPrisma = global;

export const prisma =
  globalForPrisma.prisma ||
  new PrismaClient({
    log: ['query'],
  });

if (process.env.NODE_ENV !== 'production') globalForPrisma.prisma = prisma;
