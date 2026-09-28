import { getToken } from "next-auth/jwt";
import { NextResponse } from "next/server";

const rolePortalMap = {
  farmer: "/farmer-dashboard",
  provider: "/provider-dashboard",
  mechanic: "/mechanic-dashboard",
  admin: "/admin",
  secops: "/x9f-telemetry-vault-8812",
};

const AUTH_SECRET = process.env.NEXTAUTH_SECRET || process.env.AUTH_SECRET || 'umakonekta-secure-session-auth-key-production-ph-2026';

// Global Edge WAF and Authentication Guard
export async function middleware(req) {
  const userAgent = req.headers.get('user-agent')?.toLowerCase() || '';
  const country = req.headers.get('x-vercel-ip-country');

  // 1. GLOBAL ANTI-SCRAPER
  const blockedScrapers = ['curl', 'wget', 'python', 'scrapy', 'bot', 'headlesschrome', 'puppeteer'];
  if (blockedScrapers.some(scraper => userAgent.includes(scraper))) {
    return new NextResponse("Forbidden", { status: 403 });
  }

  // 2. GLOBAL GEO-FENCE (Vercel Edge Production Only)
  if (country && country !== 'PH') {
    return new NextResponse("Access Denied: UmaKonekta is exclusively available within the Philippines.", { status: 403 });
  }

  const { pathname } = req.nextUrl;

  // 3. API Route Guard for SecOps Internal Endpoints (Except public POST /api/x9f-ops/track)
  if (pathname.startsWith('/api/x9f-ops') && !(pathname === '/api/x9f-ops/track' && req.method === 'POST')) {
    const token = await getToken({ 
      req, 
      secret: AUTH_SECRET 
    });

    if (!token || token.role !== 'secops') {
      return NextResponse.json({ error: 'Unauthorized: SecOps clearance required' }, { status: 403 });
    }
    return NextResponse.next();
  }

  // 4. Route Guard for Private Portals
  const privateRoutes = [
    '/farmer-dashboard',
    '/provider-dashboard',
    '/admin',
    '/mechanics',
    '/mechanic-dashboard',
    '/daily-roster',
    '/dispatch-slip',
    '/sacco-receipt',
    '/x9f-telemetry-vault-8812'
  ];
  
  if (privateRoutes.some(route => pathname.startsWith(route))) {
    const token = await getToken({ 
      req, 
      secret: AUTH_SECRET 
    });

    if (!token) {
      const loginUrl = new URL("/login", req.url);
      loginUrl.searchParams.set("callbackUrl", pathname);
      return NextResponse.redirect(loginUrl);
    }

    const role = token.role;
    const redirectToHomePortal = () => {
      const targetUrl = rolePortalMap[role] || "/login";
      return NextResponse.redirect(new URL(targetUrl, req.url));
    };

    if (pathname.startsWith("/mechanics")) {
      return NextResponse.redirect(new URL("/mechanic-dashboard", req.url));
    }
    if (pathname.startsWith("/admin") && role !== "admin") return redirectToHomePortal();
    if (pathname.startsWith("/farmer-dashboard") && role !== "farmer" && role !== "admin") return redirectToHomePortal();
    if (pathname.startsWith("/provider-dashboard") && role !== "provider" && role !== "admin") return redirectToHomePortal();
    if (pathname.startsWith("/daily-roster") && role !== "provider" && role !== "admin") return redirectToHomePortal();
    if (pathname.startsWith("/mechanic-dashboard") && role !== "mechanic" && role !== "admin") return redirectToHomePortal();
    if (pathname.startsWith("/x9f-telemetry-vault-8812") && role !== "secops" && role !== "admin") return redirectToHomePortal();
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    // Match all request paths except for static files and next internals
    '/((?!_next/static|_next/image|favicon.ico|background|logo).*)',
  ],
};
