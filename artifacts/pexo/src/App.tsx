import { Switch, Route, useLocation, Redirect, Router as WouterRouter } from "wouter";
import { lazy, Suspense, useEffect, useState } from "react";
import { supabase } from "@/lib/supabase";
import i18n from "@/lib/i18n";
import { isValidLang } from "@/lib/detect-language";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ThemeProvider } from "@/components/theme-provider";
import { AuthProvider, useAuth } from "@/lib/auth-context";
import { CartProvider } from "@/hooks/use-shopify-cart";

// Deferred — invisible until triggered, no need to block initial paint
const Toaster = lazy(() => import("@/components/ui/toaster").then(m => ({ default: m.Toaster })));
const SonnerToaster = lazy(() => import("sonner").then(m => ({ default: m.Toaster })));
import { AppHeader } from "@/components/app-header";
import { PexlyFooter } from "@/components/pexly-footer";
const CookieConsent = lazy(() => import("@/components/cookie-consent").then(m => ({ default: m.CookieConsent })));
const WalletSetupDialog = lazy(() => import("@/components/wallet/WalletSetupDialog").then(m => ({ default: m.WalletSetupDialog })));
import { PageSkeleton, WalletPageSkeleton } from "@/components/page-skeleton";
const PexlyHomepage = lazy(() => import("@/pages/current-html/home").then(m => ({ default: m.PexlyHomepage })));
const PhysicalProductsExport = lazy(() => import("@/pages/current-html/physical-products").then(m => ({ default: m.PhysicalProductsExport })));
const GiftCardsExport = lazy(() => import("@/pages/current-html/gift-cards").then(m => ({ default: m.GiftCardsExport })));
const AboutUsExport = lazy(() => import("@/pages/current-html/about-us").then(m => ({ default: m.AboutUsExport })));
const TeamsExport = lazy(() => import("@/pages/current-html/teams").then(m => ({ default: m.TeamsExport })));
const CareerExport = lazy(() => import("@/pages/current-html/career").then(m => ({ default: m.CareerExport })));
const BlogsExport = lazy(() => import("@/pages/current-html/blogs").then(m => ({ default: m.BlogsExport })));
const VerifyEmail = lazy(() => import("@/pages/verify-email").then(m => ({ default: m.VerifyEmail })));

const SignIn = lazy(() => import("@/pages/signin").then(m => ({ default: m.SignIn })));
const SignUp = lazy(() => import("@/pages/signup").then(m => ({ default: m.SignUp })));
const Wallet = lazy(() => import("@/pages/wallet"));
const MobileTopup = lazy(() => import("@/pages/mobile-topup"));
const UtilityBill = lazy(() => import("@/pages/utility-bill"));
const Support = lazy(() => import("@/pages/support"));
const SupportArticle = lazy(() => import("@/pages/support-article"));
const SupportCategory = lazy(() => import("@/pages/support-category"));
const Contact = lazy(() => import("@/pages/contact"));
const Checkout = lazy(() => import("@/pages/checkout").then(m => ({ default: m.Checkout })));
const CheckoutPayCrypto = lazy(() => import("@/pages/checkout-pay-crypto").then(m => ({ default: m.CheckoutPayCrypto })));
const GiftCardBrowse = lazy(() => import("@/pages/gift-card-browse").then(m => ({ default: m.GiftCardBrowse })));
const GiftCardDetail = lazy(() => import("@/pages/gift-card-detail").then(m => ({ default: m.GiftCardDetail })));
const ProductDetail = lazy(() => import("@/pages/product-detail").then(m => ({ default: m.ProductDetail })));
import { GiftCardCartProvider } from "@/hooks/use-gift-card-cart";

// ─── Route guard helpers ──────────────────────────────────────────────────────

type LazyComponent = React.LazyExoticComponent<React.ComponentType<any>>;

/** Renders a lazy component with a skeleton fallback — no auth check. */
function LazyRoute({
  component: Component,
  skeleton = <PageSkeleton />,
}: {
  component: LazyComponent;
  skeleton?: React.ReactNode;
}) {
  return (
    <Suspense fallback={skeleton}>
      <Component />
    </Suspense>
  );
}

/**
 * Checks the user's presence AND their Authenticator Assurance Level.
 *
 * Returns:
 *   'pending'   — still resolving (show skeleton)
 *   'authed'    — fully authenticated (AAL2, or no 2FA enrolled)
 *   'needs-mfa' — AAL1 session exists but a verified TOTP factor is enrolled;
 *                 the user must complete the second factor before proceeding
 *   'unauthed'  — no session at all
 *
 * Per Supabase docs (supabase.com/docs/guides/auth/auth-mfa), the recommended
 * gate check is getAuthenticatorAssuranceLevel() — "very fast (microseconds),
 * rarely uses the network" — not listFactors() + status check.
 */
function useAuthGuard() {
  const { user, loading } = useAuth();
  const [state, setState] = useState<'pending' | 'authed' | 'needs-mfa' | 'unauthed'>('pending');

  useEffect(() => {
    if (loading) { setState('pending'); return; }
    if (!user)   { setState('unauthed'); return; }

    let cancelled = false;
    supabase.auth.mfa.getAuthenticatorAssuranceLevel().then(({ data, error }) => {
      if (cancelled) return;
      if (error || !data?.currentLevel) {
        // Unknown/malformed assurance-level response — do not default to
        // "authed". Treat exactly like a failed check (see .catch below).
        setState('unauthed');
        return;
      }
      if (data.currentLevel === 'aal1' && data.nextLevel === 'aal2') {
        setState('needs-mfa');
      } else if (data.currentLevel === 'aal2' && data.nextLevel === 'aal2') {
        setState('authed'); // fully assured
      } else if (data.currentLevel === 'aal1' && data.nextLevel === 'aal1') {
        setState('authed'); // no 2FA enrolled — AAL1 is the max for this account
      } else {
        // Any other combination is an assurance state we don't recognize —
        // fail closed rather than assume it's safe.
        setState('unauthed');
      }
    }).catch(() => {
      // Fail CLOSED: if the AAL check itself errors (network blip, stale
      // client, Supabase outage), never treat that as "authenticated". An
      // unknown assurance level must not grant access to protected routes.
      if (!cancelled) setState('unauthed');
    });
    return () => { cancelled = true; };
  }, [user, loading]);

  return state;
}

/**
 * Requires an authenticated session with sufficient AAL.
 * - While auth is resolving → shows skeleton.
 * - Unauthenticated or needs-mfa → redirects to /signin (preserving return URL).
 * - Authenticated (AAL2 or no 2FA enrolled) → renders the page.
 */
function ProtectedRoute({
  component: Component,
  skeleton = <PageSkeleton />,
}: {
  component: LazyComponent;
  skeleton?: React.ReactNode;
}) {
  const guard = useAuthGuard();
  const [location] = useLocation();

  if (guard === 'pending') return <>{skeleton}</>;

  if (guard !== 'authed') {
    const returnTo = encodeURIComponent(location);
    return <Redirect to={`/signin?redirect=${returnTo}`} />;
  }

  return (
    <Suspense fallback={skeleton}>
      <Component />
    </Suspense>
  );
}

/**
 * Redirects already-authenticated users away from auth pages (signin / signup).
 * - While loading → shows skeleton so there's no flash of the auth form.
 * - Authenticated (AAL2) → redirects to /wallet (or the ?redirect param).
 * - Unauthenticated or needs-mfa → renders the auth page (user must complete TOTP).
 */
function AuthRoute({
  component: LazyComponent,
  skeleton = <PageSkeleton />,
}: {
  component: LazyComponent;
  skeleton?: React.ReactNode;
}) {
  const guard = useAuthGuard();
  const [location] = useLocation();
  const oauthProvider = new URLSearchParams(location.split("?")[1] ?? "").get("oauth");
  const isOAuthCallback = oauthProvider === "google" || oauthProvider === "wallet";
  const isSignInInProgress = (() => {
    try {
      return sessionStorage.getItem("pexly.oauth.intent") === "signin";
    } catch {
      return false;
    }
  })();

  if (guard === 'pending') return <>{skeleton}</>;

  // OAuth callbacks must render the auth page long enough to validate the
  // provider account and complete MFA. Redirecting immediately here would
  // bypass the callback page before it can reject an account that has not
  // completed Pexly registration.
  if (guard === 'authed' && !isOAuthCallback && !isSignInInProgress) {
    const params = new URLSearchParams(location.split("?")[1] ?? "");
    const raw = params.get("redirect") ?? "/wallet";
    const redirect = raw.startsWith("/") && !raw.startsWith("//") ? raw : "/wallet";
    return <Redirect to={redirect} />;
  }

  return (
    <Suspense fallback={skeleton}>
      <LazyComponent />
    </Suspense>
  );
}

// ─────────────────────────────────────────────────────────────────────────────

function AppRoutes() {
  return (
    <Switch>
      <Route path="/">{() => <LazyRoute component={PexlyHomepage} />}</Route>
      <Route path="/gift-cards/browse">{() => <LazyRoute component={GiftCardBrowse} />}</Route>
      <Route path="/gift-cards/:id">{() => <LazyRoute component={GiftCardDetail} />}</Route>
      <Route path="/gift-cards">{() => <LazyRoute component={GiftCardsExport} />}</Route>
      <Route path="/shop/product/:id">{() => <LazyRoute component={ProductDetail} />}</Route>
      <Route path="/shop">{() => <LazyRoute component={PhysicalProductsExport} />}</Route>
      <Route path="/about-us">{() => <LazyRoute component={AboutUsExport} />}</Route>
      <Route path="/about">{() => <LazyRoute component={AboutUsExport} />}</Route>
      <Route path="/teams">{() => <LazyRoute component={TeamsExport} />}</Route>
      <Route path="/team">{() => <LazyRoute component={TeamsExport} />}</Route>
      <Route path="/career">{() => <LazyRoute component={CareerExport} />}</Route>
      <Route path="/careers">{() => <LazyRoute component={CareerExport} />}</Route>
      <Route path="/blogs">{() => <LazyRoute component={BlogsExport} />}</Route>
      <Route path="/blog">{() => <LazyRoute component={BlogsExport} />}</Route>
      <Route path="/support">{() => <LazyRoute component={Support} />}</Route>
      <Route path="/support/article/:slug">{() => <LazyRoute component={SupportArticle} />}</Route>
      <Route path="/support/:category">{() => <LazyRoute component={SupportCategory} />}</Route>
      <Route path="/contact">{() => <LazyRoute component={Contact} />}</Route>
      <Route path="/verify-email">{() => <LazyRoute component={VerifyEmail} />}</Route>

      <Route path="/signin">{() => <AuthRoute component={SignIn} />}</Route>
      <Route path="/signup">{() => <AuthRoute component={SignUp} />}</Route>

      <Route path="/dashboard">{() => <Redirect to="/wallet" />}</Route>
      <Route path="/wallet">{() => <ProtectedRoute component={Wallet} skeleton={<WalletPageSkeleton />} />}</Route>
      <Route path="/wallet/mobile-topup">{() => <LazyRoute component={MobileTopup} />}</Route>
      <Route path="/mobile-topup">{() => <Redirect to="/wallet/mobile-topup" />}</Route>
      <Route path="/mobile-top-up">{() => <Redirect to="/wallet/mobile-topup" />}</Route>
      <Route path="/utility">{() => <LazyRoute component={UtilityBill} />}</Route>
      <Route path="/wallet/utility-bill">{() => <LazyRoute component={UtilityBill} />}</Route>
      <Route path="/wallet/utility">{() => <Redirect to="/utility" />}</Route>
      <Route path="/utility-bill">{() => <Redirect to="/utility" />}</Route>
      <Route path="/checkout">{() => <LazyRoute component={Checkout} />}</Route>
      <Route path="/checkout/pay/crypto">{() => <LazyRoute component={CheckoutPayCrypto} />}</Route>
      <Route><Redirect to="/" /></Route>
    </Switch>
  );
}

function AppContent() {
  const { user, walletImportState, setWalletImportState } = useAuth();
  const [location] = useLocation();
  // A Google OAuth callback briefly commits an AAL1 (pre-2FA) session to
  // `user` before signin.tsx's callback effect has a chance to call
  // pauseSessionForTOTP() and hide it again. Without this check, that
  // window is enough for WalletSetupDialog to mount, kick off its own wallet
  // check, and (for accounts with MFA) get abruptly unmounted a moment
  // later when the session is hidden — then mount again once 2FA
  // completes. That mount → unmount → mount is the "glitching" MFA
  // accounts see and non-MFA accounts don't (they never hit the pause).
  // This only gates what's rendered here — it intentionally doesn't touch
  // the Google callback's own logic in signin.tsx.
  const isAuthSignInSettling = (() => {
    try {
      const intent = sessionStorage.getItem("pexly.oauth.intent");
      const provider = sessionStorage.getItem("pexly.oauth.provider");
      return intent === "signin" || (intent === "signup" && provider === "walletconnect");
    } catch {
      return false;
    }
  })();
  const isHomepage = location === "/";
  const isPhysicalProductsPage = location === "/shop";
  const isGiftCardsTemplatePage = location === "/gift-cards";
  const isStandaloneCompanyPage = ["/about", "/about-us", "/blogs", "/blog", "/career", "/careers", "/teams", "/team"].includes(location);
  const hideShell = isHomepage || isStandaloneCompanyPage || isPhysicalProductsPage || isGiftCardsTemplatePage;
  const isAuthPage = /(?:^|\/)(?:signin|signup)\/?$/.test(location);
  const hideGlobalHeader = hideShell;

  return (
    <div className={`flex min-h-[100dvh] w-full flex-col ${!hideGlobalHeader ? "pt-[58px] max-[991px]:pt-[44px]" : ""}`}>
      {!hideGlobalHeader && <AppHeader />}
      <main className="flex-1 flex flex-col">
        <AppRoutes />
      </main>
      {!hideShell && !isAuthPage && <PexlyFooter />}

      {user && !isAuthSignInSettling && (
        <Suspense fallback={null}>
          <WalletSetupDialog
            open={walletImportState.required}
            onOpenChange={(open) => setWalletImportState({ ...walletImportState, required: open })}
            userId={user.id}
            onSuccess={() => setWalletImportState({ required: false, expectedAddress: null })}
            expectedAddress={walletImportState.expectedAddress}
          />
        </Suspense>
      )}

      <Suspense fallback={null}><Toaster /></Suspense>
      <Suspense fallback={null}><SonnerToaster position="top-center" richColors /></Suspense>
      {!hideShell && !isAuthPage && <Suspense fallback={null}><CookieConsent /></Suspense>}
    </div>
  );
}

function getInitialLangBase(): string | null {
  const seg = window.location.pathname.split("/").filter(Boolean)[0];
  if (seg === "jp") return "/jp";
  return isValidLang(seg) ? `/${seg}` : null;
}

function App() {
  const [langBase, setLangBase] = useState<string>(() => getInitialLangBase() ?? "/en");

  useEffect(() => {
    const initial = getInitialLangBase();
    if (initial) {
      i18n.changeLanguage(initial === "/jp" ? "ja" : initial.slice(1));
    } else {
      const rest = window.location.pathname;
      const search = window.location.search;
      const hash = window.location.hash;
      window.history.replaceState(
        null,
        "",
        `/en${rest === "/" ? "" : rest}${search}${hash}`,
      );
      i18n.changeLanguage("en");
      setLangBase("/en");
    }
  }, []);

  const isHelp = window.location.hostname === "help.pexly.app";

  return (
    <WouterRouter base={langBase}>
      <QueryClientProvider client={queryClient}>
          <ThemeProvider>
            <AuthProvider>
              <GiftCardCartProvider>
                <CartProvider>
                  <TooltipProvider>
                    {isHelp ? (
                      <div className="flex min-h-[100dvh] w-full flex-col pt-[58px] max-[991px]:pt-[44px]">
                        <AppHeader />
                        <main className="flex flex-1 flex-col">
                          <Suspense fallback={<PageSkeleton />}><Support /></Suspense>
                        </main>
                        <PexlyFooter />
                      </div>
                    ) : (
                      <>
                        <AppContent />
                      </>
                    )}
                  </TooltipProvider>
                </CartProvider>
              </GiftCardCartProvider>
            </AuthProvider>
          </ThemeProvider>
      </QueryClientProvider>
    </WouterRouter>
  );
}

export default App;
