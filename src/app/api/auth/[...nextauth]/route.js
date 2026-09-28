import NextAuth from "next-auth"
import CredentialsProvider from "next-auth/providers/credentials"
import { prisma } from "@/lib/prisma"
import bcrypt from "bcryptjs"
import { logSecurityEvent } from "@/lib/siem"

// Auto-detect production URL for NextAuth when deployed on Netlify/Vercel
if (!process.env.NEXTAUTH_URL) {
  if (process.env.URL) {
    process.env.NEXTAUTH_URL = process.env.URL;
  } else if (process.env.DEPLOY_PRIME_URL) {
    process.env.NEXTAUTH_URL = process.env.DEPLOY_PRIME_URL;
  } else if (process.env.DEPLOY_URL) {
    process.env.NEXTAUTH_URL = process.env.DEPLOY_URL;
  }
}

const DEFAULT_AUTH_SECRET = 'umakonekta-secure-session-auth-key-production-ph-2026';

const rateLimitMap = new Map();
const ipRateLimitMap = new Map();
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000; // 15 minutes

export const authOptions = {
  providers: [
    CredentialsProvider({
      name: 'Credentials',
      credentials: {
        registryId: { label: "Registry ID", type: "text" },
        password: { label: "Password", type: "password" }
      },
      async authorize(credentials, req) {
        const cleanRegistryId = (credentials?.registryId || '').trim();
        const rawPassword = credentials?.password || '';

        if (!cleanRegistryId || !rawPassword) {
          return null;
        }

        const realIp = req.headers?.['cf-connecting-ip'] || req.headers?.['x-real-ip'] || req.headers?.['x-forwarded-for']?.split(',')[0].trim();
        const ip = realIp || 'unknown';

        // 0. IP Rate Limiting Check (DDoS Protection)
        const now = Date.now();
        const rateData = ipRateLimitMap.get(ip) || { count: 0, lastReset: now };
        if (now - rateData.lastReset > 60000) {
          rateData.count = 1;
          rateData.lastReset = now;
        } else {
          rateData.count++;
        }
        ipRateLimitMap.set(ip, rateData);

        if (rateData.count > 20) {
          throw new Error("Rate limit exceeded. Too many login attempts from your IP.");
        }

        // 1. Check IP Blacklist Firewall
        const blacklistedIp = await prisma.ipBlacklist.findUnique({
          where: { ipAddress: ip }
        });
        if (blacklistedIp) {
          await logSecurityEvent({
            eventType: 'IP_BLOCKED_LOGIN_ATTEMPT',
            ipAddress: ip,
            registryId: cleanRegistryId,
            details: `Blacklisted IP attempted to authenticate. Reason: ${blacklistedIp.reason}`,
            severity: 'CRITICAL'
          });
          throw new Error("Connection refused by firewall.");
        }

        // 1.5. Check Geo-Fencing & VPN/Tor Ban (Bypass for local development and private networks)
        const isLocalIp = !ip || ip === 'unknown' || ip === '::1' || ip === '127.0.0.1' || ip.includes('127.0.0.1') || ip === 'localhost' || ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.') || ip.startsWith('fe80:') || ip.startsWith('::ffff:');
        if (!isLocalIp) {
          let geoBlocked = false;
          let geoData = null;
          try {
            const geoRes = await fetch(`http://ip-api.com/json/${ip}?fields=status,countryCode,proxy,hosting`, { 
              next: { revalidate: 3600 },
              signal: AbortSignal.timeout(2000)
            });
            const geo = await geoRes.json();
            if (geo.status === 'success') {
              geoData = geo;
              if (geo.proxy || geo.hosting || (geo.countryCode && geo.countryCode !== 'PH')) {
                geoBlocked = true;
              }
            }
          } catch (e) {
            // Silently fail open on network errors to external API
          }

          if (geoBlocked && geoData) {
            await logSecurityEvent({
              eventType: 'VPN_TOR_BLOCKED',
              ipAddress: ip,
              registryId: cleanRegistryId,
              details: `Foreign or proxy connection blocked. Country: ${geoData.countryCode}, Proxy: ${geoData.proxy}, Hosting: ${geoData.hosting}`,
              severity: 'HIGH'
            });
            
            // CyGuard Auto-Mitigation
            const cyguardConfig = await prisma.systemConfig.findUnique({ where: { key: 'CYGUARD_ACTIVE' } });
            if (cyguardConfig?.value === 'true') {
              await prisma.ipBlacklist.upsert({
                where: { ipAddress: ip },
                update: {},
                create: { ipAddress: ip, reason: 'CyGuard: Auto-firewalled due to VPN/Geo anomaly during login.' }
              });
              await logSecurityEvent({ eventType: 'CYGUARD_INTERVENTION', ipAddress: ip, registryId: cleanRegistryId, details: `Autonomously firewalled malicious IP.`, severity: 'CRITICAL' });
            }
            
            throw new Error("Access Denied: Connections must originate from a residential Philippine network.");
          }
        }

        // 2. Check Global Lockdown
        const lockdownConfig = await prisma.systemConfig.findUnique({
          where: { key: 'GLOBAL_LOCKDOWN' }
        });
        const isLockdownActive = lockdownConfig?.value === 'true';

        const rateKey = cleanRegistryId.toLowerCase();
        const attempts = rateLimitMap.get(rateKey) || { count: 0, lockoutUntil: 0 };
        
        if (Date.now() < attempts.lockoutUntil) {
          await logSecurityEvent({
            eventType: 'BRUTE_FORCE_LOCKOUT',
            ipAddress: req.headers?.['x-forwarded-for'] || 'unknown',
            registryId: cleanRegistryId,
            details: 'Blocked authentication attempt during lockout period.',
            severity: 'HIGH'
          });
          throw new Error("Account temporarily locked due to too many failed login attempts. Please try again in 15 minutes.");
        }

        // Legitimate legacy institutional aliases (DA RSBSA / CDA registration numbers)
        const LEGACY_INSTITUTIONAL_ALIASES = {
          '03-49-12-00841': 'farmer-1-23-A001',
          'cda-fca-2024-9140': 'provider-1-23-A001',
          'cda-fca-2024-9141': 'provider-1-23-A002',
          'cda-fca-2024-9142': 'provider-1-23-A003',
          'cda-fca-2024-9143': 'provider-1-23-A004',
          'cda-fca-2024-9144': 'provider-1-23-A005',
          'cda-fca-2024-9145': 'provider-1-23-A006',
          'cda-fca-2024-9146': 'provider-1-23-A007',
          'cda-fca-2024-9147': 'provider-1-23-A008',
          'cda-fca-2024-9148': 'provider-1-23-A009',
          'cda-fca-2024-9149': 'provider-1-23-A010',
          'mech-tesda-889': 'mechanic-1-23-A001',
          'gov-mao-r11-0042': 'admin-1-23-A001',
          'secops-alpha-01': 'secops-1-23-A001',
        };

        const lowerRegistryId = cleanRegistryId.toLowerCase();

        // Query user: strictly lookup by registryId
        let user = await prisma.user.findUnique({
          where: { registryId: cleanRegistryId }
        });

        // Case-insensitive fallback for SQLite where findUnique is strictly case-sensitive
        if (!user) {
          try {
            const rawUsers = await prisma.$queryRaw`SELECT * FROM User WHERE LOWER(registryId) = LOWER(${cleanRegistryId}) LIMIT 1`;
            if (rawUsers && rawUsers.length > 0) {
              user = rawUsers[0];
            }
          } catch (_) {}
        }

        // If not found directly, check exact legacy institutional alias
        if (!user && LEGACY_INSTITUTIONAL_ALIASES[lowerRegistryId]) {
          const aliasTarget = LEGACY_INSTITUTIONAL_ALIASES[lowerRegistryId];
          user = await prisma.user.findUnique({
            where: { registryId: aliasTarget }
          });
          if (!user) {
            try {
              const rawAliasUsers = await prisma.$queryRaw`SELECT * FROM User WHERE LOWER(registryId) = LOWER(${aliasTarget}) LIMIT 1`;
              if (rawAliasUsers && rawAliasUsers.length > 0) {
                user = rawAliasUsers[0];
              }
            } catch (_) {}
          }
        }

        if (!user) {
          await logSecurityEvent({
            eventType: 'FAILED_LOGIN_UNKNOWN_USER',
            ipAddress: ip,
            registryId: cleanRegistryId,
            details: 'Authentication attempt for unregistered Registry ID.',
            severity: 'LOW'
          });
          return null;
        }

        // 3. Enforce Global Lockdown
        if (isLockdownActive && user.role !== 'secops') {
          await logSecurityEvent({
            eventType: 'LOCKDOWN_LOGIN_ATTEMPT',
            ipAddress: ip,
            registryId: cleanRegistryId,
            details: 'Standard user attempted login during active DEFCON 1 lockdown.',
            severity: 'HIGH'
          });
          throw new Error("SYSTEM LOCKDOWN ACTIVE: All non-SecOps authentications are suspended.");
        }

        if (user.isBanned) {
          await logSecurityEvent({
            eventType: 'BANNED_USER_LOGIN_ATTEMPT',
            ipAddress: ip,
            registryId: cleanRegistryId,
            details: 'A banned user attempted to authenticate.',
            severity: 'HIGH'
          });
          throw new Error("Account has been permanently locked by Security Operations.");
        }

        // Cryptographically verify password against bcrypt hash - ZERO HARDCODED CREDENTIAL BYPASSES
        const isValid = await bcrypt.compare(
          rawPassword,
          user.passwordHash
        );

        if (!isValid) {
          attempts.count += 1;
          if (attempts.count >= MAX_ATTEMPTS) {
            attempts.lockoutUntil = Date.now() + LOCKOUT_MS;
            await logSecurityEvent({
              eventType: 'BRUTE_FORCE_DETECTED',
              ipAddress: ip,
              registryId: cleanRegistryId,
              details: `Account locked for 15 minutes due to ${MAX_ATTEMPTS} consecutive failed attempts.`,
              severity: 'CRITICAL'
            });

            // CyGuard Auto-Mitigation
            const cyguardConfig = await prisma.systemConfig.findUnique({ where: { key: 'CYGUARD_ACTIVE' } });
            if (cyguardConfig?.value === 'true' && user.role !== 'secops') {
              await prisma.user.update({
                where: { registryId: user.registryId },
                data: { isBanned: true }
              });
              await prisma.ipBlacklist.upsert({
                where: { ipAddress: ip },
                update: {},
                create: { ipAddress: ip, reason: 'CyGuard: Auto-firewalled due to brute-force attack.' }
              });
              await logSecurityEvent({
                eventType: 'CYGUARD_INTERVENTION',
                ipAddress: ip,
                registryId: cleanRegistryId,
                details: `Autonomously firewalled IP and locked account due to brute-force attack.`,
                severity: 'CRITICAL'
              });
            }

          } else {
            await logSecurityEvent({
              eventType: 'FAILED_LOGIN',
              ipAddress: ip,
              registryId: cleanRegistryId,
              details: `Failed attempt ${attempts.count}/${MAX_ATTEMPTS}`,
              severity: 'LOW'
            });
          }
          rateLimitMap.set(rateKey, attempts);
          return null;
        }

        // Clear failed attempt tracking on verified login
        rateLimitMap.delete(rateKey);

        // Standardize registryId format (user role-month-day register-A000)
        let standardRegistryId = user.registryId;
        const legacyToStandard = {
          '03-49-12-00841': 'farmer-1-23-A001',
          'CDA-FCA-2024-9140': 'provider-1-23-A001',
          'CDA-FCA-2024-9141': 'provider-1-23-A002',
          'CDA-FCA-2024-9142': 'provider-1-23-A003',
          'CDA-FCA-2024-9143': 'provider-1-23-A004',
          'CDA-FCA-2024-9144': 'provider-1-23-A005',
          'CDA-FCA-2024-9145': 'provider-1-23-A006',
          'CDA-FCA-2024-9146': 'provider-1-23-A007',
          'CDA-FCA-2024-9147': 'provider-1-23-A008',
          'CDA-FCA-2024-9148': 'provider-1-23-A009',
          'CDA-FCA-2024-9149': 'provider-1-23-A010',
          'MECH-TESDA-889': 'mechanic-1-23-A001',
          'GOV-MAO-R11-0042': 'admin-1-23-A001',
          'SECOPS-ALPHA-01': 'secops-1-23-A001',
        };
        if (legacyToStandard[standardRegistryId]) {
          standardRegistryId = legacyToStandard[standardRegistryId];
        }

        return {
          id: user.id,
          name: user.name,
          role: user.role,
          registryId: standardRegistryId,
        };
      }
    })
  ],
  secret: process.env.NEXTAUTH_SECRET || process.env.AUTH_SECRET || DEFAULT_AUTH_SECRET,
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.role = user.role;
        token.registryId = user.registryId;
      }
      return token;
    },
    async session({ session, token }) {
      if (session?.user) {
        session.user.id = token.sub;
        session.user.role = token.role;
        session.user.registryId = token.registryId;
      }
      return session;
    }
  },
  session: {
    strategy: "jwt",
    maxAge: 24 * 60 * 60, // 24 hours
  },
  pages: {
    signIn: '/login',
    error: '/login',
  }
};

const handler = NextAuth(authOptions);
export { handler as GET, handler as POST };
