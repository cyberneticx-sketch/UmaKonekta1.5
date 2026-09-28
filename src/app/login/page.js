'use client';

import { useState, useEffect, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { signIn, useSession } from 'next-auth/react';
import Link from 'next/link';
import FarmerLoadingScreen from '@/components/FarmerLoadingScreen';
import { formatRegistryId, getRoleTemplate, getRoleInitial } from '@/lib/formatters';
import {
  User,
  Building2,
  Wrench,
  Shield,
  ShieldCheck,
  Lock,
  Eye,
  EyeOff,
  Sparkles,
  CheckCircle2,
  AlertCircle,
  Info,
  ArrowRight,
  LogIn,
  Loader2,
  Radio,
  Headphones,
  Zap
} from 'lucide-react';

const demoAccounts = {
  farmer: {
    id: 'farmer-1-23-A001',
    pwd: 'Farmer@2026!',
    name: 'Farmer Member #00001',
    badge: 'RSBSA Farmer'
  },
  provider: {
    id: 'provider-1-23-A001',
    pwd: 'TagumAdmin2024!',
    name: 'Tagum FCA Machinery Depot',
    badge: 'FCA Depot'
  },
  mechanic: {
    id: 'mechanic-1-23-A001',
    pwd: 'Mech@2026!',
    name: 'TESDA Field Mechanic #889',
    badge: 'Field Tech'
  },
  admin: {
    id: 'admin-1-23-A001',
    pwd: 'MAO-Command-9912',
    name: 'LGU Admin Officer',
    badge: 'Gov Admin'
  },
  secops: {
    id: 'secops-1-23-A001',
    pwd: 'SecOps@2026!',
    name: 'SecOps Threat Analyst',
    badge: 'SIEM SecOps'
  }
};

const roleConfigs = {
  farmer: {
    heading: 'Farmer & Requestor Login',
    subtext: 'Enter your Farmer Member ID to search directory resources and submit equipment requests.',
    idLabel: 'Farmer Registry ID',
    idPlaceholder: 'e.g., farmer-0-0-F0000',
    idHelp: 'Format: (farmer-0-0-F0000), e.g., farmer-0-0-F0000.',
    idIcon: User,
    pwdLabel: 'Password',
    btnText: 'Verify Identity & Enter Farmer Dashboard',
    targetUrl: '/farmer-dashboard'
  },
  provider: {
    heading: 'Resource Provider Depot Login',
    badge: 'FCA Depot Auth',
    subtext: 'Sign in with your Provider ID to manually create and manage resource listings, and review incoming requests.',
    idLabel: 'Provider Registry ID',
    idPlaceholder: 'e.g., provider-0-0-P0000',
    idHelp: 'Format: (provider-0-0-P0000), e.g., provider-0-0-P0000.',
    idIcon: Building2,
    pwdLabel: 'Password',
    btnText: 'Authenticate & Access Provider Hub',
    targetUrl: '/provider-dashboard'
  },
  admin: {
    heading: 'LGU & Municipal Admin Directory',
    badge: 'Gov Admin',
    subtext: 'Municipal Agriculture Office (MAO) administration for user registrations, role management, and farmer directory audits.',
    idLabel: 'Admin Registry ID',
    idPlaceholder: 'e.g., admin-0-0-A0000',
    idHelp: 'Format: (admin-0-0-A0000), e.g., admin-0-0-A0000.',
    idIcon: ShieldCheck,
    pwdLabel: 'Admin Password',
    btnText: 'Enter Admin Moderation Command',
    targetUrl: '/admin'
  },
  mechanic: {
    heading: 'Field Mechanic & Mobile Repair Unit',
    badge: 'TESDA NC-II Unit',
    subtext: 'Field technicians and mobile repair vans responding to harvest breakdowns, parts replacement, and emergency SOS logs.',
    idLabel: 'Mechanic Registry ID',
    idPlaceholder: 'e.g., mechanic-0-0-M0000',
    idHelp: 'Format: (mechanic-0-0-M0000), e.g., mechanic-0-0-M0000.',
    idIcon: Wrench,
    pwdLabel: 'Technician Password',
    btnText: 'Authenticate & Enter Mechanic Portal',
    targetUrl: '/mechanic-dashboard'
  },
  secops: {
    heading: 'Security Operations Center',
    badge: 'SecOps Command',
    subtext: 'Classified terminal for real-time SIEM monitoring, threat neutralization, and platform defense.',
    idLabel: 'SecOps Authorization Clearance',
    idPlaceholder: 'e.g., secops-0-0-S0000',
    idHelp: 'Format: (secops-0-0-S0000), e.g., secops-0-0-S0000.',
    idIcon: Radio,
    pwdLabel: 'Biometric / Token Security Code',
    btnText: 'Initialize SecOps Terminal',
    targetUrl: '/x9f-telemetry-vault-8812'
  }
};

export default function Login() {
  return (
    <Suspense fallback={<FarmerLoadingScreen message="Initializing Login Portal..." subtext="DA-LGU RSBSA Directory Verification" />}>
      <LoginContent />
    </Suspense>
  );
}

function LoginContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { data: session, status: authStatus } = useSession();

  const roleFromUrl = searchParams.get('role');
  const callbackUrlParam = searchParams.get('callbackUrl') || '';

  // Infer role: explicit ?role= param, or inferred from ?callbackUrl=
  const initialRole = (roleFromUrl && roleConfigs[roleFromUrl])
    ? roleFromUrl
    : (callbackUrlParam.includes('x9f') || callbackUrlParam.includes('secops'))
      ? 'secops'
      : callbackUrlParam.includes('mechanic')
        ? 'mechanic'
        : (callbackUrlParam.includes('provider') || callbackUrlParam.includes('daily-roster'))
          ? 'provider'
          : callbackUrlParam.includes('admin')
            ? 'admin'
            : 'farmer';

  const [activeRole, setActiveRole] = useState(initialRole);
  const [idValue, setIdValue] = useState(() => getRoleTemplate(initialRole));
  const [pwdValue, setPwdValue] = useState('');
  const [pwdVisible, setPwdVisible] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');

  const config = roleConfigs[activeRole] || roleConfigs.farmer;
  const RoleIcon = config.idIcon || User;
  const intent = searchParams.get('intent');
  const asset = searchParams.get('asset');

  // If already authenticated, redirect to appropriate portal immediately
  useEffect(() => {
    if (authStatus === 'authenticated' && session?.user?.role) {
      const userRole = session.user.role;
      const target = (intent === 'request' && userRole === 'farmer')
        ? `/farmer-dashboard?${searchParams.toString()}`
        : ({
          farmer: '/farmer-dashboard',
          provider: '/provider-dashboard',
          mechanic: '/mechanic-dashboard',
          admin: '/admin',
          secops: '/x9f-telemetry-vault-8812'
        }[userRole] || '/farmer-dashboard');

      window.location.href = target;
    }
  }, [authStatus, session, intent, searchParams]);

  useEffect(() => {
    const roleParam = searchParams.get('role');
    if (roleParam && roleConfigs[roleParam] && roleParam !== activeRole) {
      setActiveRole(roleParam);
      setIdValue(getRoleTemplate(roleParam));
    }
  }, [searchParams, activeRole]);

  // Handle NextAuth redirect error parameters
  const authErrorParam = searchParams.get('error');
  useEffect(() => {
    if (authErrorParam) {
      if (authErrorParam === 'Configuration') {
        setErrorMessage('Server configuration issue detected. Please verify NEXTAUTH_SECRET and DATABASE_URL in your environment settings.');
      } else if (authErrorParam === 'AccessDenied') {
        setErrorMessage('Access denied: You do not have permission to view this resource.');
      } else if (authErrorParam === 'CredentialsSignin') {
        setErrorMessage('Invalid credentials. Please verify your Registry ID and Password/PIN.');
      } else {
        setErrorMessage(`Authentication error: ${authErrorParam}`);
      }
    }
  }, [authErrorParam]);

  const handleRoleChange = (role) => {
    setActiveRole(role);
    setIdValue(getRoleTemplate(role));
    setPwdValue('');
    setErrorMessage('');
    router.replace(`/login?role=${role}`, { scroll: false });
  };

  const handleIdChange = (e) => {
    const nextVal = e.target.value;
    const isDeleting = nextVal.length < idValue.length;
    if (isDeleting) {
      setIdValue(nextVal);
    } else {
      setIdValue(formatRegistryId(nextVal, activeRole));
    }
  };

  const handleApplyTemplate = () => {
    const template = getRoleTemplate(activeRole);
    setIdValue(template);
    if (errorMessage) setErrorMessage('');
  };

  const handleFillDemo = (roleKey = activeRole) => {
    const targetRole = roleConfigs[roleKey] ? roleKey : 'farmer';
    const demo = demoAccounts[targetRole] || demoAccounts.farmer;
    if (targetRole !== activeRole) {
      setActiveRole(targetRole);
      router.replace(`/login?role=${targetRole}`, { scroll: false });
    }
    setIdValue(demo.id);
    setPwdValue(demo.pwd);
    if (errorMessage) setErrorMessage('');
  };

  const handleLoginSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);
    setErrorMessage('');

    const cleanId = idValue.trim();
    if (!cleanId || !pwdValue) {
      setErrorMessage('Please enter both your Registry ID and Password/PIN.');
      setIsSubmitting(false);
      return;
    }

    try {
      const res = await signIn('credentials', {
        redirect: false,
        registryId: cleanId,
        password: pwdValue,
      });

      if (!res?.ok || res?.error) {
        setIsSubmitting(false);
        setErrorMessage(res?.error || 'Authentication failed. Please verify your credentials or use the embedded template format.');
        return;
      }

      setIsSuccess(true);

      const target = (intent === 'request' && activeRole === 'farmer')
        ? `/farmer-dashboard?${searchParams.toString()}`
        : (callbackUrlParam && !callbackUrlParam.includes('/login'))
          ? callbackUrlParam
          : config.targetUrl;

      setTimeout(() => {
        window.location.href = target;
      }, 500);

    } catch (err) {
      setIsSubmitting(false);
      setErrorMessage('An unexpected authentication error occurred. Please try again.');
    }
  };

  return (
    <div className="flex flex-col relative w-full min-h-[calc(100vh-80px)] lg:flex-row bg-cream-surface">
      {/* LEFT SIDE: Brand Showcase & Institutional Trust Section */}
      <div className="relative lg:w-5/12 xl:w-1/2 flex flex-col justify-between p-6 sm:p-10 lg:p-14 bg-gradient-to-br from-[#003618] via-[#005426] to-[#01505e] text-white overflow-hidden min-h-[420px] lg:min-h-full">
        {/* Ambient Visual Elements & Terraces Backdrop */}
        <div
          className="absolute inset-0 bg-cover bg-center mix-blend-overlay opacity-30 pointer-events-none"
          style={{ backgroundImage: "url('/umakonekta-bg-4.png')" }}
        />
        <div className="absolute -top-32 -left-32 w-80 h-80 bg-[#a3f5b2]/20 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute -bottom-20 -right-20 w-96 h-96 bg-[#F4A228]/15 rounded-full blur-3xl pointer-events-none" />

        {/* Center Hero Message & Scope Pillars */}
        <div className="relative z-10 my-auto py-8 lg:py-12 max-w-xl">
          <h1 className="text-3xl sm:text-4xl lg:text-5xl font-extrabold text-white tracking-tight leading-[1.15] mb-4">
            Connecting Every Farmer, <br /><span className="text-[#a3f5b2]">Empowering Every Community.</span>
          </h1>
          <p className="text-white/85 text-sm sm:text-base leading-relaxed mb-6">
            Sign in to discover machinery resources, manually manage equipment listings, or moderate municipal farmer and cooperative directory records.
          </p>
        </div>

        <div className="relative z-10 pt-4 border-t border-white/15 text-xs text-white/70 flex items-center justify-between">
          <span>Republic of the Philippines • Department of Agriculture</span>

        </div>
      </div>

      {/* RIGHT SIDE: Multi-Role Interactive Login Portal */}
      <div className="flex-1 relative z-10 flex items-center justify-center p-4 sm:p-8 lg:p-12 xl:p-16">
        <div className="w-full max-w-lg bg-white/95 backdrop-blur-md rounded-2xl p-6 sm:p-8 lg:p-10 shadow-[0_8px_32px_rgba(0,84,38,0.08)] border border-[#DDE3DA] flex flex-col gap-6">

          {/* Portal Role Selector Tabs (4 In-Scope Roles: Farmer, Provider, Mechanic, Admin) */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-bold uppercase tracking-wider text-primary">Select Account Portal</span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-1.5 p-1 bg-[#e5f0eb] rounded-xl border border-[#DDE3DA]/80">
              {[
                { key: 'farmer', label: 'Farmer', Icon: User },
                { key: 'provider', label: 'Provider', Icon: Building2 },
                { key: 'mechanic', label: 'Mechanic', Icon: Wrench },
                { key: 'admin', label: 'Admin', Icon: ShieldCheck }
              ].map(({ key, label, Icon }) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => handleRoleChange(key)}
                  className={`py-2 px-1 rounded-lg text-xs flex flex-col items-center gap-1 transition-all cursor-pointer ${activeRole === key ? 'bg-primary text-white font-bold shadow-md' : 'text-[#475953] font-medium hover:text-on-surface'
                    }`}
                >
                  <Icon className="w-4 h-4" />
                  <span>{label}</span>
                </button>
              ))}
            </div>

            {activeRole === 'secops' && (
              <div className="mt-2 p-2.5 bg-slate-900 text-emerald-400 rounded-xl text-xs flex items-center justify-between border border-emerald-500/30">
                <div className="flex items-center gap-2">
                  <Radio className="w-4 h-4 text-emerald-400" />
                  <span className="font-mono font-bold tracking-wide">SecOps Telemetry Mode Active</span>
                </div>
                <button
                  type="button"
                  onClick={() => handleRoleChange('farmer')}
                  className="text-[11px] text-slate-300 hover:text-white underline font-sans cursor-pointer"
                >
                  Standard Roles
                </button>
              </div>
            )}
          </div>

          {/* Dynamic Context Header */}
          <div className="border-b border-[#DDE3DA]/80 pb-4">
            <div className="flex items-center justify-between">
              <h2 className="text-xl sm:text-2xl font-extrabold text-on-surface tracking-tight">
                {config.heading}
              </h2>
            </div>
            <p className="text-xs sm:text-sm text-[#404940] mt-1">
              {config.subtext}
            </p>
          </div>

          {/* Registration Success Banner */}
          {searchParams.get('registered') === 'true' && !errorMessage && (
            <div className="p-3.5 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs font-semibold flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
              <span>Registration completed successfully! Please sign in with your credentials.</span>
            </div>
          )}

          {/* Inline Error Banner */}
          {errorMessage && (
            <div className="p-3.5 rounded-xl bg-red-50 border border-red-200 text-red-700 text-xs font-semibold flex items-center gap-2">
              <AlertCircle className="w-4 h-4 text-red-600 shrink-0" />
              <span>{errorMessage}</span>
            </div>
          )}

          {intent === 'request' && asset && (
            <div className="p-3 rounded-xl bg-[#EAF5EE] text-[#1B6E39] text-xs font-semibold flex items-center gap-2 border border-[#1B6E39]/20">
              <Info className="w-4 h-4 text-[#1B6E39] shrink-0" />
              <span>Log in to finalize request for {asset}.</span>
            </div>
          )}

          {/* Interactive Form */}
          <form className="space-y-4" onSubmit={handleLoginSubmit}>
            <div className="space-y-1.5">
              <div className="flex items-center justify-between gap-2">
                <label className="block text-xs font-bold uppercase tracking-wider text-on-surface">
                  {config.idLabel}
                </label>
                <div className="flex items-center gap-1.5">

                  {activeRole !== 'secops' && (
                    <button
                      type="button"
                      onClick={handleApplyTemplate}
                      className="inline-flex items-center gap-1 px-2 py-0.5 rounded-lg bg-emerald-50 hover:bg-emerald-100 text-primary text-[11px] font-mono font-bold transition-all border border-emerald-200 cursor-pointer"
                      title={`Auto-apply ${activeRole} template format`}
                    >
                      <Sparkles className="w-3.5 h-3.5 text-primary" />
                      <span>Format</span>
                    </button>
                  )}
                </div>
              </div>

              <div className="relative">
                <span className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-soil-slate">
                  <RoleIcon className="w-4 h-4 text-soil-slate" />
                </span>
                <input
                  type="text"
                  required
                  value={idValue}
                  onChange={handleIdChange}
                  placeholder={getRoleTemplate(activeRole)}
                  className="w-full pl-10 pr-4 py-3 bg-white text-on-surface text-sm rounded-xl border border-border-soft focus:border-primary focus:ring-2 focus:ring-primary/20 focus:outline-none font-mono font-bold transition-all placeholder:text-soil-slate/50"
                />
              </div>

              <p className="text-[11px] text-soil-slate leading-tight">
                {config.idHelp}
              </p>
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="block text-xs font-bold uppercase tracking-wider text-on-surface">
                  {config.pwdLabel}
                </label>
              </div>

              <div className="relative">
                <span className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-[#475953]">
                  <Lock className="w-5 h-5 text-[#475953]" />
                </span>
                <input
                  type={pwdVisible ? "text" : "password"}
                  required
                  value={pwdValue}
                  onChange={(e) => setPwdValue(e.target.value)}
                  placeholder= "enter your password"
                  className="w-full pl-11 pr-11 py-3 bg-white text-on-surface text-sm rounded-xl border border-[#DDE3DA] focus:border-primary focus:ring-2 focus:ring-primary/20 focus:outline-none font-mono transition-all"
                />
                <button
                  type="button"
                  onClick={() => setPwdVisible(!pwdVisible)}
                  className="absolute inset-y-0 right-0 pr-3.5 flex items-center text-[#475953] hover:text-on-surface cursor-pointer"
                  aria-label={pwdVisible ? "Hide password" : "Show password"}
                >
                  {pwdVisible ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={isSubmitting || isSuccess}
              className="w-full mt-2 py-3.5 px-4 bg-primary text-white text-sm font-extrabold rounded-xl shadow-md hover:bg-primary-container focus:ring-4 focus:ring-primary/20 transition-all active:scale-[0.99] flex items-center justify-center gap-2 cursor-pointer disabled:opacity-75"
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Verifying Credentials...</span>
                </>
              ) : isSuccess ? (
                <>
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Identity Verified! Redirecting...</span>
                </>
              ) : (
                <>
                  <LogIn className="w-4 h-4" />
                  <span>{config.btnText}</span>
                </>
              )}
            </button>
          </form>



          {/* Direct Link to Registration */}
          <div className="text-center pt-2 border-t border-[#DDE3DA]/80 text-xs text-soil-slate">
            <span>Don&apos;t have an enrolled account yet? </span>
            <Link href={`/register?role=${activeRole}`} className="font-extrabold text-primary hover:underline ml-1 inline-flex items-center gap-1">
              <span>Register / Sign Up here</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          <div className="bg-[#F3F4EE] p-3 rounded-xl flex items-center justify-between text-xs text-[#475953]">
            <span className="flex items-center gap-1.5 font-bold">
              <Headphones className="w-4 h-4 text-[#C26D1A]" />
              Barangay Desk Assistance
            </span>
            <span className="text-soil-slate/70 font-medium">Available during LGU office hours</span>
          </div>

        </div>
      </div>
    </div>
  );
}
