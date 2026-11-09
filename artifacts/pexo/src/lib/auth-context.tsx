import { createContext, useContext, useEffect, useState, useCallback, useRef } from "react";
import type { User, Session } from "@supabase/supabase-js";
import { useLocation } from "wouter";
import { getSupabase } from "./supabase";
import { getClientLocation } from "./get-client-ip";
import { devLog } from "./dev-logger";
import { sendLoginNotificationIfEnabled, fetchAndCreateMarketMoversNotifications } from "./notifications-api";
import { deviceFingerprint } from "./security/device-fingerprint";
import { setAccessTokenProvider } from "@/hooks/use-signing-worker";

interface PendingAuth {
  userId: string;
  email: string;
  deviceInfo: {
    deviceName: string;
    browser: string;
    os: string;
  };
}

interface WalletImportState {
  required: boolean;
  expectedAddress: string | null;
}

export interface AuthContextType {
  user: User | null;
  session: Session | null;
  signUp: (email: string, password: string, captchaToken?: string) => Promise<{ error: any }>;
  signIn: (email: string, password: string, captchaToken?: string) => Promise<{ 
    error: any; 
    data: any;
    requiresOTP?: boolean;
    pendingAuth?: PendingAuth;
    requiresTOTP?: boolean;
    totpFactorId?: string;
    totpChallengeId?: string;
  }>;
  signOut: () => Promise<void>;
  completeOTPVerification: () => Promise<void>;
  cancelOTPVerification: () => Promise<void>;
  /**
   * Call after a successful mfa.verify() to lift the TOTP-pending gate and
   * commit the AAL2 session as the active user in auth context.
   */
  completeTOTPSignIn: () => Promise<void>;
  /**
   * Call when the user cancels the TOTP form ("Back to Login").
   * Lifts the gate and signs the AAL1 session out so no partial session lingers.
   */
  cancelTOTPSignIn: () => Promise<void>;
  /**
   * Call immediately after passkey auth succeeds and before showing the TOTP
   * challenge form. Sets totpPendingRef and clears user/session from React
   * state so that route guards treat the user as unauthenticated until the
   * second factor is verified. completeTOTPSignIn() re-commits the AAL2 session.
   */
  pauseSessionForTOTP: () => void;
  /**
   * Call just before starting the passkey WebAuthn ceremony (both the explicit
   * button and the conditional/autofill path). Sets signInInProgressRef so the
   * SIGNED_IN event emitted by Supabase is parked in deferredSignedInRef instead
   * of immediately updating user state — preventing AuthRoute from redirecting
   * to /dashboard before the AAL check completes.
   */
  beginPasskeyAuth: () => void;
  /**
   * Call when the passkey flow succeeds and no 2FA is required.
   * Clears signInInProgressRef and applies the deferred SIGNED_IN session
   * (including device tracking and wallet check side-effects).
   * For the 2FA path use pauseSessionForTOTP() instead.
   */
  releasePasskeyAuth: () => void;
  loading: boolean;
  isLoading: boolean;
  pendingOTPVerification: PendingAuth | null;
  walletImportState: WalletImportState;
  setWalletImportState: (state: WalletImportState) => void;
  isWalletUnlocked: boolean;
  unlockWallet: (password: string) => void;
  lockWallet: () => void;
  /**
   * Returns the current vault password from module scope — NOT stored in
   * the context value object so React DevTools cannot passively read it.
   * Call this only inside event handlers / async functions, never during
   * render so the return value never enters the component tree.
   */
  getSessionPassword: () => string | null;
  setSessionPassword: (password: string | null) => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

function getDeviceInfo() {
  const ua = navigator.userAgent;
  let browser = 'Unknown Browser';
  let browserVersion = '';
  let os = 'Unknown OS';
  let osVersion = '';
  let deviceName = 'Desktop';
  let deviceModel = '';

  const hasTouchScreen = navigator.maxTouchPoints > 0 || 'ontouchstart' in window;
  const screenWidth = window.screen.width;
  const screenHeight = window.screen.height;
  const minDimension = Math.min(screenWidth, screenHeight);

  // Detect browser and version
  if (ua.includes('CriOS')) {
    browser = 'Chrome';
    const match = ua.match(/CriOS\/(\d+)/);
    if (match) browserVersion = match[1];
  } else if (ua.includes('FxiOS')) {
    browser = 'Firefox';
    const match = ua.match(/FxiOS\/(\d+)/);
    if (match) browserVersion = match[1];
  } else if (ua.includes('EdgiOS')) {
    browser = 'Edge';
    const match = ua.match(/EdgiOS\/(\d+)/);
    if (match) browserVersion = match[1];
  } else if (ua.includes('Chrome') && !ua.includes('Edg') && !ua.includes('OPR')) {
    browser = 'Chrome';
    const match = ua.match(/Chrome\/(\d+)/);
    if (match) browserVersion = match[1];
  } else if (ua.includes('Safari') && !ua.includes('Chrome')) {
    browser = 'Safari';
    const match = ua.match(/Version\/(\d+)/);
    if (match) browserVersion = match[1];
  } else if (ua.includes('Firefox')) {
    browser = 'Firefox';
    const match = ua.match(/Firefox\/(\d+)/);
    if (match) browserVersion = match[1];
  } else if (ua.includes('Edg')) {
    browser = 'Edge';
    const match = ua.match(/Edg\/(\d+)/);
    if (match) browserVersion = match[1];
  } else if (ua.includes('OPR') || ua.includes('Opera')) {
    browser = 'Opera';
  } else if (ua.includes('SamsungBrowser')) {
    browser = 'Samsung Internet';
    const match = ua.match(/SamsungBrowser\/(\d+)/);
    if (match) browserVersion = match[1];
  }

  // Detect OS and device
  if (ua.includes('iPhone')) {
    os = 'iOS';
    deviceName = 'iPhone';
    const match = ua.match(/iPhone OS (\d+[._]\d+)/);
    if (match) osVersion = match[1].replace('_', '.');
  } else if (ua.includes('iPad')) {
    os = 'iPadOS';
    deviceName = 'iPad';
    const match = ua.match(/CPU OS (\d+[._]\d+)/);
    if (match) osVersion = match[1].replace('_', '.');
  } else if (ua.includes('Android')) {
    os = 'Android';
    const match = ua.match(/Android (\d+\.?\d*)/);
    if (match) osVersion = match[1];
    
    const modelMatch = ua.match(/;\s*([^;)]+)\s*Build\//);
    if (modelMatch) {
      deviceModel = modelMatch[1].trim();
      deviceModel = deviceModel.replace(/^(SM-|LG-|SAMSUNG|Xiaomi|HUAWEI|OPPO|vivo|OnePlus|Pixel)\s*/i, '');
    }
    
    const isTablet = minDimension >= 600 || 
      (deviceModel && (
        deviceModel.toLowerCase().includes('tablet') || 
        deviceModel.toLowerCase().includes('tab') ||
        deviceModel.toLowerCase().includes('pad')
      ));
    
    deviceName = isTablet ? 'Android Tablet' : 'Android Phone';
  } else if (ua.includes('Windows Phone') || ua.includes('Windows Mobile')) {
    os = 'Windows Phone';
    deviceName = 'Windows Phone';
  } else if (ua.includes('Windows NT 10.0')) {
    os = 'Windows';
    osVersion = ua.includes('Windows NT 10.0; Win64') ? '10/11' : '10';
  } else if (ua.includes('Windows NT 6.3')) {
    os = 'Windows';
    osVersion = '8.1';
  } else if (ua.includes('Windows NT 6.1')) {
    os = 'Windows';
    osVersion = '7';
  } else if (ua.includes('Windows')) {
    os = 'Windows';
  } else if (ua.includes('Mac OS X') || ua.includes('Macintosh')) {
    const isLikelyIPad = hasTouchScreen && 
      ua.includes('Safari') && 
      !ua.includes('Chrome') &&
      navigator.maxTouchPoints >= 2 &&
      (navigator.platform === 'MacIntel' || navigator.platform === 'iPad');
    
    if (isLikelyIPad && minDimension <= 1024) {
      os = 'iPadOS';
      deviceName = 'iPad';
      const match = ua.match(/Mac OS X (\d+[._]\d+)/);
      if (match) osVersion = match[1].replace('_', '.');
    } else {
      os = 'macOS';
      const match = ua.match(/Mac OS X (\d+[._]\d+)/);
      if (match) osVersion = match[1].replace('_', '.');
    }
  } else if (ua.includes('CrOS')) {
    os = 'Chrome OS';
    deviceName = 'Chromebook';
  } else if (ua.includes('Linux')) {
    os = 'Linux';
    if (ua.includes('Ubuntu')) os = 'Ubuntu';
    
    if (hasTouchScreen && minDimension < 800) {
      os = 'Android';
      deviceName = 'Android Phone';
    }
  }

  let fullDeviceName = deviceName;
  
  if (deviceModel && deviceModel.length > 0 && deviceModel.length < 30) {
    fullDeviceName = deviceModel;
  } else if (deviceName === 'Desktop') {
    if (os === 'macOS') {
      fullDeviceName = 'Mac';
    } else if (os === 'Windows') {
      fullDeviceName = 'Windows PC';
    } else if (os === 'Linux' || os === 'Ubuntu') {
      fullDeviceName = 'Linux PC';
    } else if (os === 'Chrome OS') {
      fullDeviceName = 'Chromebook';
    }
  }

  const fullOs = osVersion ? `${os} ${osVersion}` : os;
  const fullBrowser = browserVersion ? `${browser} ${browserVersion}` : browser;

  return { 
    browser: fullBrowser, 
    os: fullOs, 
    deviceName: fullDeviceName, 
    userAgent: ua 
  };
}

// Module-level lock — prevents two concurrent trackDevice calls from both
// seeing "no existing row" and both inserting (race condition).
let _trackDeviceInflight: Promise<{ isNewDevice: boolean; ipAddress: string; country: string; isp: string }> | null = null;

async function trackDevice(userId: string): Promise<{ isNewDevice: boolean; ipAddress: string; country: string; isp: string }> {
  if (_trackDeviceInflight) {
    // Another call is already running — wait for it, then signal "not new"
    // so only the first caller can ever send a notification.
    await _trackDeviceInflight.catch(() => {});
    return { isNewDevice: false, ipAddress: '', country: '', isp: '' };
  }
  _trackDeviceInflight = _doTrackDevice(userId);
  try {
    return await _trackDeviceInflight;
  } finally {
    _trackDeviceInflight = null;
  }
}

async function _doTrackDevice(userId: string): Promise<{ isNewDevice: boolean; ipAddress: string; country: string; isp: string }> {
  const STALE_THRESHOLD_DAYS = 30;
  try {
    const supabase = await getSupabase();
    const deviceInfo = getDeviceInfo();
    // Single fetch for IP + country + ISP — no duplicate requests
    const location = await getClientLocation().catch(() => ({ ip: '', country: '', isp: '' }));
    const ipAddress = location.ip;
    const country   = location.country;
    const isp       = location.isp;
    // Use browser fingerprint hash as stable dedup key — survives IP/network changes
    const fingerprintHash = await deviceFingerprint.getCurrentFingerprint();
    const now = new Date().toISOString();

    const { data: existing } = await supabase
      .from('user_devices')
      .select('id, last_active')
      .eq('user_id', userId)
      .eq('fingerprint_hash', fingerprintHash)
      .maybeSingle();

    if (existing) {
      const daysSince = (Date.now() - new Date(existing.last_active).getTime()) / 86_400_000;
      const isStale = daysSince > STALE_THRESHOLD_DAYS;
      await supabase.from('user_devices').update({ is_current: false }).eq('user_id', userId);
      await supabase.from('user_devices')
        .update({ is_current: true, last_active: now, ip_address: ipAddress })
        .eq('id', existing.id);
      return { isNewDevice: isStale, ipAddress, country, isp };
    }

    // Genuinely new device — insert a record and signal caller to fire notification
    await supabase.from('user_devices').update({ is_current: false }).eq('user_id', userId);
    await supabase.from('user_devices').insert({
      user_id: userId,
      fingerprint_hash: fingerprintHash,
      device_name: deviceInfo.deviceName,
      browser: deviceInfo.browser,
      os: deviceInfo.os,
      ip_address: ipAddress,
      user_agent: deviceInfo.userAgent,
      is_current: true,
      last_active: now,
    });
    return { isNewDevice: true, ipAddress, country, isp };
  } catch {
    return { isNewDevice: false, ipAddress: '', country: '', isp: '' };
  }
}

// Helper to check pending OTP from sessionStorage (avoids stale closure)
function hasPendingOTP(): boolean {
  try {
    return !!sessionStorage.getItem('pendingOTP_data');
  } catch {
    return false;
  }
}

// Returns true only if there is a non-expired pending OTP challenge for this
// specific user. If the stored OTP belongs to a different user (stale from a
// previous flow), it is cleared and false is returned so the new session can
// proceed normally. This prevents a stale OTP from blocking a valid login.
function isOTPBlockingUser(userId: string): boolean {
  try {
    const raw = sessionStorage.getItem('pendingOTP_data');
    if (!raw) return false;
    const parsed = JSON.parse(raw);
    // Expired — always discard
    if (Date.now() - (parsed.createdAt || 0) > 10 * 60 * 1000) {
      sessionStorage.removeItem('pendingOTP_data');
      sessionStorage.removeItem('pendingOTP_session');
      return false;
    }
    // Different user's OTP — discard; let this user's session through
    if (parsed.userId && parsed.userId !== userId) {
      sessionStorage.removeItem('pendingOTP_data');
      sessionStorage.removeItem('pendingOTP_session');
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

// ─── Vault password — module-level store, intentionally outside React state ──
// Keeping the wallet decryption password in useState exposes it in React
// DevTools (browser extensions can read all component state). Storing it at
// module scope instead means it is never visible in the component tree while
// still being accessible through the AuthContext API. The boolean
// isWalletUnlocked (useState) continues to drive re-renders when the lock
// state changes, so all consumers stay correctly in sync.
let _vaultPassword: string | null = null;
// ────────────────────────────────────────────────────────────────────────────

// ─── Custom inactivity-based session expiry (no Supabase premium required) ──
// Supabase silently refreshes the access token, so the JWT timeout setting
// alone never logs users out. Instead we track the last moment the user was
// active and expire the session if they've been idle too long. The check runs
// every time Supabase refreshes the token — no polling needed.
const SESSION_INACTIVITY_MS = 30 * 60 * 1000; // 30 minutes of inactivity
const ACTIVITY_THROTTLE_MS  = 60 * 1000;       // write to localStorage at most once per minute

let _lastActivityWrite = 0; // module-level throttle — no React state needed

function getLastActivity(userId: string): number {
  try {
    const val = localStorage.getItem(`pexly_last_activity_${userId}`);
    return val ? parseInt(val, 10) : 0;
  } catch { return 0; }
}

function touchLastActivity(userId: string, force = false): void {
  const now = Date.now();
  if (!force && now - _lastActivityWrite < ACTIVITY_THROTTLE_MS) return;
  _lastActivityWrite = now;
  try {
    localStorage.setItem(`pexly_last_activity_${userId}`, String(now));
  } catch { /* silent */ }
}

function clearLastActivity(userId: string): void {
  try {
    localStorage.removeItem(`pexly_last_activity_${userId}`);
  } catch { /* silent */ }
}

function isSessionExpired(userId: string): boolean {
  const last = getLastActivity(userId);
  if (!last) return false; // no recorded activity → don't expire (backwards-compat)
  return Date.now() - last > SESSION_INACTIVITY_MS;
}
// ────────────────────────────────────────────────────────────────────────────

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [, navigate] = useLocation();
  const [user, setUser] = useState<User | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);
  
  const [pendingOTPVerification, setPendingOTPVerification] = useState<PendingAuth | null>(() => {
    try {
      const saved = sessionStorage.getItem('pendingOTP_data');
      if (!saved) return null;
      const parsed = JSON.parse(saved);
      const createdAt = parsed.createdAt || 0;
      if (Date.now() - createdAt > 10 * 60 * 1000) {
        sessionStorage.removeItem('pendingOTP_data');
        sessionStorage.removeItem('pendingOTP_session');
        return null;
      }
      return parsed;
    } catch { return null; }
  });

  const setPendingOTPWithTimestamp = useCallback((data: PendingAuth | null) => {
    setPendingOTPVerification(data);
    try {
      if (data) {
        const dataWithTimestamp = { ...data, createdAt: Date.now() };
        sessionStorage.setItem('pendingOTP_data', JSON.stringify(dataWithTimestamp));
      } else {
        sessionStorage.removeItem('pendingOTP_data');
      }
    } catch { /* silent */ }
  }, []);
  
  const [pendingSession, setPendingSession] = useState<{ user: User; session: Session } | null>(() => {
    try {
      const saved = sessionStorage.getItem('pendingOTP_session');
      return saved ? JSON.parse(saved) : null;
    } catch { return null; }
  });

  const [walletImportState, setWalletImportState] = useState<WalletImportState>({ 
    required: false, 
    expectedAddress: null 
  });

  // sessionPassword is stored in _vaultPassword (module scope), not useState.
  const [isWalletUnlocked, setIsWalletUnlocked] = useState(false);
  const inactivityTimerRef = useRef<NodeJS.Timeout | null>(null);

  const lockWallet = useCallback(() => {
    _vaultPassword = null;
    setIsWalletUnlocked(false);
    if (inactivityTimerRef.current) {
      clearTimeout(inactivityTimerRef.current);
    }
  }, []);

  // Wire the signing worker's chain-gateway calls (BTC/SOL/TRON/EVM prepare
  // + sign, SPL/TRC-20 transfers) to this app's real Supabase session.
  //
  // Deliberately pull-based rather than capturing `session` from closure: it
  // calls getSupabase().auth.getSession() fresh on every gateway request,
  // the same pattern completeTOTPSignIn/cancelTOTPSignIn above use for the
  // same reason — a token captured once via closure over `session` state
  // could go stale between a user unlocking their wallet and confirming a
  // send, especially across the multi-second scrypt KDF delay on first use.
  // Registered once per AuthProvider mount; setAccessTokenProvider just
  // swaps a module-level function reference, so re-registering on every
  // render isn't needed and would just add noise.
  useEffect(() => {
    setAccessTokenProvider(async () => {
      const supabase = await getSupabase();
      const { data } = await supabase.auth.getSession();
      return data.session?.access_token ?? null;
    });
  }, []);

  const lockWalletDueToInactivity = useCallback(() => {
    _vaultPassword = null;
    setIsWalletUnlocked(false);
    if (inactivityTimerRef.current) {
      clearTimeout(inactivityTimerRef.current);
    }
    navigate('/signin?reason=timeout');
  }, [navigate]);

  const resetInactivityTimer = useCallback(() => {
    if (inactivityTimerRef.current) {
      clearTimeout(inactivityTimerRef.current);
    }
    // 15 minutes of inactivity triggers auto-lock
    inactivityTimerRef.current = setTimeout(lockWalletDueToInactivity, 15 * 60 * 1000);
  }, [lockWalletDueToInactivity]);

  const unlockWallet = useCallback((password: string) => {
    _vaultPassword = password;
    setIsWalletUnlocked(true);
    resetInactivityTimer();
  }, [resetInactivityTimer]);

  const hiddenAtRef = useRef<number | null>(null);
  const BACKGROUND_LOCK_MS = 5 * 60 * 1000; // lock wallet if tab is hidden for 5+ minutes

  useEffect(() => {
    const activityEvents = ['mousedown', 'keydown', 'touchstart', 'mousemove'];
    const handleActivity = () => {
      if (isWalletUnlocked) resetInactivityTimer();
      if (activeUserIdRef.current) touchLastActivity(activeUserIdRef.current);
    };

    const handleVisibilityChange = () => {
      if (document.hidden) {
        hiddenAtRef.current = Date.now();
      } else {
        const hiddenAt = hiddenAtRef.current;
        hiddenAtRef.current = null;
        if (hiddenAt && isWalletUnlockedRef.current && Date.now() - hiddenAt >= BACKGROUND_LOCK_MS) {
          lockWalletDueToInactivity();
        } else if (!document.hidden && isWalletUnlockedRef.current) {
          resetInactivityTimer();
        }
        if (activeUserIdRef.current) touchLastActivity(activeUserIdRef.current);
      }
    };

    activityEvents.forEach(event => window.addEventListener(event, handleActivity));
    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => {
      activityEvents.forEach(event => window.removeEventListener(event, handleActivity));
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      if (inactivityTimerRef.current) clearTimeout(inactivityTimerRef.current);
    };
  }, [isWalletUnlocked, resetInactivityTimer, lockWalletDueToInactivity]);
  
  const checkedUsersRef = useRef<Set<string>>(new Set());
  const lastForceCheckRef = useRef<number>(0);
  const mmFiredRef = useRef(false); // market movers: run once per app load regardless of event type
  const sessionTokenRef = useRef<string | null>(null);
  const isSigningOutRef = useRef(false);
  const activeUserIdRef = useRef<string | null>(null);
  // Ref mirrors for values used inside long-lived callbacks to avoid stale closures
  const isWalletUnlockedRef = useRef(false);

  // ── TOTP-safe sign-in ───────────────────────────────────────────────────
  // signInInProgressRef: true while signIn() is running its TOTP check.
  //   The onAuthStateChange SIGNED_IN handler defers its payload here.
  // totpPendingRef: true from when requiresTOTP is returned until the user
  //   either successfully verifies (completeTOTPSignIn) or cancels
  //   (cancelTOTPSignIn).  Gates TOKEN_REFRESHED, health-check, and
  //   initial-session so no path can call setUser while a TOTP challenge
  //   is active — including the AuthRoute redirect in App.tsx.
  const signInInProgressRef = useRef(false);
  const deferredSignedInRef = useRef<{ user: User; session: Session } | null>(null);
  const totpPendingRef = useRef(false);
  // Tracks the last access_token for which we ran trackDevice.
  // Supabase re-emits SIGNED_IN on tab refocus — this guard ensures we only
  // run the post-login side-effects once per unique session token.
  const lastTrackedTokenRef = useRef<string | null>(null);

  // Keep refs in sync with state so callbacks always see current values
  useEffect(() => {
    activeUserIdRef.current = user?.id ?? null;
  }, [user?.id]);

  // Account isolation: when the signed-in user changes (or disappears), drop
  // every wallet cache and in-flight wallet operation that belonged to the
  // previous user. React Query wallet rows/balances/data and any volatile
  // secrets must not survive a switch.
  const prevWalletUserIdRef = useRef<string | null>(null);
  useEffect(() => {
    const prev = prevWalletUserIdRef.current;
    const next = user?.id ?? null;
    prevWalletUserIdRef.current = next;
    if (prev && prev !== next) {
      void import("./wallet-query-cache").then(({ clearWalletQueryCaches }) => clearWalletQueryCaches());
      void import("./non-custodial-wallet").then(({ clearWalletStateFromMemory }) => clearWalletStateFromMemory(prev));
    }
  }, [user?.id]);

  useEffect(() => {
    isWalletUnlockedRef.current = isWalletUnlocked;
  }, [isWalletUnlocked]);

  const checkWalletOnAuth = useCallback(async (userId: string, force: boolean = false) => {
    if (!userId) return;

    if (!force && checkedUsersRef.current.has(userId)) {
      return;
    }

    // Guard: don't attempt any Supabase calls when the project credentials
    // are not configured (dev environment without .env) or the client failed
    // to initialise. Without this the client silently returns null for every
    // query and we'd land on "CREATE REQUIRED" every time.
    const supabaseUrl = import.meta.env.VITE_SUPABASE_URL as string | undefined;
    if (!supabaseUrl) {
      devLog.warn("Wallet check skipped — VITE_SUPABASE_URL not configured");
      return;
    }

    try {
      const supabase = await getSupabase();

      // A previous logout may have failed to wipe IndexedDB. Finish that first
      // and refuse to load wallet data while stale data may still be present.
      const { completePendingWipeIfNeeded } = await import("./secure-storage-wiper");
      if (!(await completePendingWipeIfNeeded())) {
        devLog.error("Wallet check aborted — previous session storage could not be wiped");
        checkedUsersRef.current.delete(userId);
        return;
      }

      // DECISION FLOW:
      // 1. Fetch authoritative encrypted blobs from Supabase (source of truth).
      //    Nothing is cached in the browser. Never store decrypted keys.
      // 2. If wallet is already unlocked in memory -> Wallet Ready
      // 3. If encrypted blobs exist (Supabase or IDB cache) -> Password Required
      // 4. If wallet address exists in profile but no blob -> Import Required
      // 5. No address at all AND Supabase confirmed it -> Create Required
      //
      // Critical: only open the dialog when we have a CONFIRMED server response.
      // If Supabase is unreachable (bad network, cold start, missing creds) we
      // must stay silent — showing "create wallet" over real funds would be
      // catastrophic. We track `supabaseReachable` for exactly this gate.

      // 1. Always sync encrypted blobs from Supabase first.
      let wallets: any[] = [];
      let supabaseReachable = false;
      try {
        const { nonCustodialWalletManager } = await import("./non-custodial-wallet");
        const supabaseWallets = await nonCustodialWalletManager.loadWalletsFromSupabase(supabase, userId);
        supabaseReachable = true; // request completed without throwing
        if (supabaseWallets && supabaseWallets.length > 0) {
          wallets = supabaseWallets;
        }
      } catch (walletSyncError: any) {
        // Keep the actual RPC failure visible in development diagnostics.
        // Only safe PostgREST error metadata is logged; wallet row contents
        // and encrypted fields are never logged.
        devLog.error("Supabase wallet sync failed", {
          code: walletSyncError?.code ?? null,
          message: walletSyncError?.message ?? String(walletSyncError),
          details: walletSyncError?.details ?? null,
          hint: walletSyncError?.hint ?? null,
        });
        // supabaseReachable stays false — the server is the only wallet
        // source, so there is nothing to fall back to. The gate below keeps
        // the create dialog closed until the server can confirm the state.
      }

      // 2. If wallet is already unlocked in memory -> Wallet Ready
      if (wallets.length > 0 && isWalletUnlockedRef.current) {
        checkedUsersRef.current.add(userId);
        setWalletImportState({ required: false, expectedAddress: null });
        return;
      }

      // 3. Wallets exist → no dialog needed. Encrypted blobs are already in IDB
      //    (loadWalletsFromSupabase saves them). Password is only required when
      //    the user signs a transaction, not just to load the wallet page.
      if (wallets.length > 0) {
        checkedUsersRef.current.add(userId);
        setWalletImportState({ required: false, expectedAddress: null });
        return;
      }

      // If the wallet RPC was unavailable, refuse to open the dialog.
      // Do not use user_profiles as a wallet-detection fallback: its
      // permissions are intentionally independent from wallet RPC access,
      // and a profile permission error must not hide wallet setup.
      if (!supabaseReachable) {
        devLog.warn("Wallet check aborted — Supabase unreachable, will retry on wallet page");
        checkedUsersRef.current.delete(userId); // allow retry next navigation
        return;
      }

      // CREATE REQUIRED: the wallet RPC confirmed no wallet exists.
      // Re-query through the same RPC as an authoritative double-check before
      // prompting. Direct user_wallets access and user_profiles fallback reads
      // are intentionally unavailable.
      const { nonCustodialWalletManager } = await import("./non-custodial-wallet");
      let confirmedWallets: any[];
      try {
        confirmedWallets = await nonCustodialWalletManager.loadWalletsFromSupabase(supabase, userId);
      } catch (walletCheckError: any) {
        devLog.warn("Wallet RPC check failed, aborting dialog:", walletCheckError?.message);
        checkedUsersRef.current.delete(userId);
        return;
      }

      if (confirmedWallets.length > 0) {
        checkedUsersRef.current.add(userId);
        setWalletImportState({ required: false, expectedAddress: null });
        return;
      }

      checkedUsersRef.current.add(userId);
      setWalletImportState({
        required: true,
        expectedAddress: null,
      });

    } catch {
      devLog.error("Wallet detection error");
      checkedUsersRef.current.delete(userId);
    }
  }, []);

  const checkWalletOnAuthRef = useRef<(userId: string, force?: boolean) => Promise<void>>(
    async () => {} // dummy function, will be updated by useEffect
  );

  useEffect(() => {
    checkWalletOnAuthRef.current = checkWalletOnAuth;
  }, [checkWalletOnAuth]);

  // Clear checkedUsersRef when user logs out
  useEffect(() => {
    if (!user?.id) {
      checkedUsersRef.current.clear();
    }
  }, [user?.id]);

  // Check wallet whenever user becomes available after loading. Call the
  // callback directly here instead of going through the ref-backed placeholder
  // so the first authenticated render cannot silently skip the check.
  // Use the user-aware OTP guard so stale OTP data for another user cannot
  // block this wallet lookup.
  useEffect(() => {
    if (user?.id && !loading && !isOTPBlockingUser(user.id)) {
      void checkWalletOnAuth(user.id);
    }
  }, [user?.id, loading, checkWalletOnAuth]);

  // Update sessionTokenRef when session changes
  useEffect(() => {
    sessionTokenRef.current = session?.access_token ?? null;
  }, [session?.access_token]);

  // Sync OTP state to sessionStorage
  useEffect(() => {
    try {
      if (pendingOTPVerification) {
        sessionStorage.setItem('pendingOTP_data', JSON.stringify(pendingOTPVerification));
      } else {
        sessionStorage.removeItem('pendingOTP_data');
      }
      
      if (pendingSession) {
        sessionStorage.setItem('pendingOTP_session', JSON.stringify(pendingSession));
      } else {
        sessionStorage.removeItem('pendingOTP_session');
      }
    } catch { /* silent */ }
  }, [pendingOTPVerification, pendingSession]);

  const setSessionPassword = useCallback((password: string | null) => {
    _vaultPassword = password;
    if (password) {
      setIsWalletUnlocked(true);
      resetInactivityTimer();
    } else {
      setIsWalletUnlocked(false);
      if (inactivityTimerRef.current) clearTimeout(inactivityTimerRef.current);
    }
  }, [resetInactivityTimer]);

  // Main auth effect
  useEffect(() => {
    // Guard against the effect running after the component unmounts. Because
    // getSupabase() is async, the cleanup function below may fire before the
    // Promise resolves. Without this flag, the async callback would continue
    // running (setting up subscriptions, updating state) on an unmounted tree.
    let aborted = false;

    // Helper: clear stale OTP React state when sessionStorage was wiped
    const clearOTPState = () => {
      setPendingOTPVerification(null);
      setPendingSession(null);
    };

    // Clean up stale OTP data older than 10 minutes
    try {
      const otpData = sessionStorage.getItem('pendingOTP_data');
      if (otpData) {
        const parsed = JSON.parse(otpData);
        const createdAt = parsed.createdAt || 0;
        if (Date.now() - createdAt > 10 * 60 * 1000) {
          sessionStorage.removeItem('pendingOTP_data');
          sessionStorage.removeItem('pendingOTP_session');
          clearOTPState();
        }
      }
    } catch { /* silent */ }

    if (window.location.pathname === '/verify-email') {
      setSession(null);
      setUser(null);
      setLoading(false);
      return;
    }

    // Refs so the cleanup function can reach these even though they are
    // assigned asynchronously inside the getSupabase().then() callback.
    let subscription: { unsubscribe(): void } | undefined;
    let healthCheckInterval: ReturnType<typeof setInterval> | undefined;

    // Load Supabase asynchronously — vendor-db chunk is NOT part of the
    // initial bundle; it downloads in the background after first render.
    getSupabase().then((supabase) => {
      if (aborted) return; // component unmounted before client resolved

      // Set up auth state listener FIRST
      const { data: { subscription: sub } } = supabase.auth.onAuthStateChange((event, currentSession) => {
        if (aborted) return;
        if (window.location.pathname === '/verify-email') {
          setSession(null);
          setUser(null);
          return;
        }

        // ALWAYS update session for token refresh — but check custom expiry first
        if (event === 'TOKEN_REFRESHED' || event === 'INITIAL_SESSION') {
          if (
            currentSession?.user &&
            !isSigningOutRef.current &&
            isSessionExpired(currentSession.user.id)
          ) {
            // Session exceeded our custom max age — force sign out once
            isSigningOutRef.current = true;
            supabase.auth.signOut().finally(() => { isSigningOutRef.current = false; });
            return;
          }
          // Don't surface the AAL1 session while a TOTP challenge is active.
          // completeTOTPSignIn() will explicitly commit the AAL2 session once
          // mfa.verify() succeeds.
          if (totpPendingRef.current) return;
          setSession(currentSession);
          setUser(currentSession?.user ?? null);
          return;
        }

        // Handle logout/session clear
        if (event === 'SIGNED_OUT' || !currentSession) {
          setSession(null);
          setUser(null);
          setWalletImportState({ required: false, expectedAddress: null });
          void import("./non-custodial-wallet").then(({ clearWalletStateFromMemory }) => {
            clearWalletStateFromMemory();
          });
          void import("./wallet-query-cache").then(({ clearWalletQueryCaches }) => clearWalletQueryCaches());
          checkedUsersRef.current.clear();
          lastTrackedTokenRef.current = null; // reset so next sign-in always runs trackDevice
          return;
        }

        // If signIn() is mid-flight, defer this SIGNED_IN event.
        // signIn() will apply user/session state itself after the TOTP check.
        if (event === 'SIGNED_IN' && signInInProgressRef.current) {
          deferredSignedInRef.current = { user: currentSession.user, session: currentSession };
          return;
        }

        // If the user left the tab and came back while a TOTP challenge is
        // active, Supabase re-emits SIGNED_IN for the existing AAL1 session.
        // Block it here — completeTOTPSignIn() is the only path allowed to
        // commit a user while totpPendingRef is true.
        if (totpPendingRef.current) return;

        // Use user-aware OTP check: stale OTP for a different user is cleared
        // automatically inside isOTPBlockingUser so the real session gets through.
        if (!isOTPBlockingUser(currentSession.user.id)) {
          setSession(currentSession);
          setUser(currentSession.user);

          if (event === 'SIGNED_IN') {
            // Guard: Supabase re-emits SIGNED_IN on tab refocus / token refresh.
            // Only run device tracking + wallet check once per unique access token.
            if (lastTrackedTokenRef.current === currentSession.access_token) return;
            lastTrackedTokenRef.current = currentSession.access_token;

            // Stamp activity at login so the 30-min inactivity clock starts now
            touchLastActivity(currentSession.user.id, true);
            // Defer async work to avoid blocking the callback.
            // The 1500ms delay gives Supabase time to stabilise its connection
            // after sign-in so the wallet check doesn't run against a
            // not-yet-ready client and falsely trigger the setup dialog.
            setTimeout(async () => {
              if (aborted) return;
              const userId = currentSession.user.id;
              const deviceInfo = getDeviceInfo();
              const { isNewDevice, ipAddress, country, isp } = await trackDevice(userId);
              checkWalletOnAuthRef.current(userId);
              if (isNewDevice) sendLoginNotificationIfEnabled(userId, deviceInfo, ipAddress, country, isp);
            }, 1500);
          }

          // Market movers: run once per app load for ANY session event
          // (INITIAL_SESSION, SIGNED_IN, TOKEN_REFRESHED).
          // The function itself deduplicates via localStorage + Supabase,
          // so firing it here on every auth state change is safe and cheap.
          if (!mmFiredRef.current) {
            mmFiredRef.current = true;
            setTimeout(() => {
              if (aborted) return;
              fetchAndCreateMarketMoversNotifications(currentSession.user.id);
            }, 2000);
          }
        }

      });
      subscription = sub;

      // Add periodic session health check
      healthCheckInterval = setInterval(async () => {
        if (aborted) return;
        // Skip entirely while a TOTP challenge is active — the health check
        // would surface the AAL1 session and trigger the AuthRoute redirect.
        if (totpPendingRef.current) return;
        const { data: { session: currentSession } } = await supabase.auth.getSession();
        if (currentSession && sessionTokenRef.current !== currentSession.access_token && !isOTPBlockingUser(currentSession.user.id)) {
          setSession(currentSession);
          setUser(currentSession.user);
        }
      }, 60000);

      // Then get initial session
      supabase.auth.getSession().then(async ({ data: { session: initialSession } }) => {
        if (aborted) return;
        // isOTPBlockingUser is user-aware: if pendingOTP_data belongs to a
        // different user (stale from a prior flow), it clears it and returns
        // false so this session is allowed through. Also sync React state.
        const blocked = initialSession?.user
          ? isOTPBlockingUser(initialSession.user.id)
          : hasPendingOTP();
        // Also skip while a TOTP challenge is active — the initial-session
        // path would surface the AAL1 session the same way the health check
        // would.
        if (!blocked && !totpPendingRef.current) {
          setSession(initialSession);
          setUser(initialSession?.user ?? null);
        }
        setLoading(false);
      }).catch(() => {
        if (!aborted) setLoading(false);
      });
    }).catch(() => {
      if (!aborted) setLoading(false);
    });

    // Force wallet check handler (no supabase needed — delegates to ref)
    const handleForceCheck = (e: CustomEvent<{ userId: string }>) => {
      if (e.detail?.userId) {
        const userId = e.detail.userId;
        const now = Date.now();
        if (now - lastForceCheckRef.current < 2000) return;
        lastForceCheckRef.current = now;
        checkWalletOnAuthRef.current(userId, true);
      }
    };
    
    window.addEventListener('force-wallet-check', handleForceCheck as EventListener);

    return () => {
      aborted = true;
      subscription?.unsubscribe();
      if (healthCheckInterval !== undefined) clearInterval(healthCheckInterval);
      window.removeEventListener('force-wallet-check', handleForceCheck as EventListener);
    };
  }, []);

  const signUp = useCallback(async (email: string, password: string, captchaToken?: string) => {
    const supabase = await getSupabase();
    const baseUrl = window.location.hostname.includes('pexly.app') 
      ? 'https://pexly.app' 
      : window.location.origin;
    const redirectUrl = `${baseUrl}/verify-email`;
    
    const { error, data } = await supabase.auth.signUp({
      email,
      password,
      options: { 
        emailRedirectTo: redirectUrl,
        captchaToken,
      },
    });

    if (!error && data.user) {
      await trackDevice(data.user.id);
    }

    return { error };
  }, []);

  const signIn = useCallback(async (email: string, password: string, captchaToken?: string) => {
    const supabase = await getSupabase();

    // ── TOTP interception ───────────────────────────────────────────────
    // Keep the flag TRUE for the entire duration of the sign-in + TOTP
    // check.  The onAuthStateChange SIGNED_IN handler will park any
    // incoming event in deferredSignedInRef and return immediately.
    // signIn() explicitly releases the flag at every exit path *after*
    // the TOTP decision is final, then manually applies or discards the
    // deferred payload as appropriate.
    signInInProgressRef.current = true;
    deferredSignedInRef.current = null;

    const { error, data } = await supabase.auth.signInWithPassword({ 
      email, 
      password,
      options: { captchaToken },
    });

    if (error) {
      // Auth failed — release interception and discard any deferred payload.
      signInInProgressRef.current = false;
      deferredSignedInRef.current = null;
      return { error, data };
    }

    if (data.user && data.session) {
      // NOTE: trackDevice is NOT called here.
      // The deferred SIGNED_IN path (below) always runs after signIn() resolves
      // and is the single authoritative place that calls trackDevice for a fresh
      // sign-in.  Calling it here too causes a race: both calls find "no row",
      // both insert, both send a new-device notification.

      // ── Fail-closed TOTP check ─────────────────────────────────────────
      // Official Supabase pattern (docs: supabase.com/docs/guides/auth/auth-mfa):
      //   1. getAuthenticatorAssuranceLevel() — fast, tells us whether the
      //      current session needs a second factor (currentLevel=aal1,
      //      nextLevel=aal2).  This is the recommended gate check.
      //   2. listFactors() — only called when aal2 is required, to obtain
      //      the factorId needed for the challenge call.
      //
      // SECURITY: any error is treated as a hard failure (fail closed).
      // We sign the user out so no unauthenticated session state leaks.
      let mfaErr: Error | null = null;
      let totpFactorId: string | null = null;
      let totpChallengeId: string | null = null;

      try {
        const { data: aalData, error: aalErr } = await supabase.auth.mfa.getAuthenticatorAssuranceLevel();
        if (aalErr) throw aalErr;

        if (aalData.currentLevel === 'aal1' && aalData.nextLevel === 'aal2') {
          const { data: factorsData, error: listErr } = await supabase.auth.mfa.listFactors();
          if (listErr) throw listErr;

          const totpFactor = factorsData?.totp?.find((f: any) => f.status === 'verified');
          if (totpFactor) {
            const { data: challengeData, error: challengeErr } = await supabase.auth.mfa.challenge({
              factorId: totpFactor.id,
            });
            if (challengeErr || !challengeData) {
              throw challengeErr ?? new Error('Failed to start MFA challenge');
            }
            totpFactorId = totpFactor.id;
            totpChallengeId = challengeData.id;
          }
        }
      } catch (e: any) {
        mfaErr = e instanceof Error ? e : new Error(String(e));
        console.error('[MFA] TOTP check failed (fail-closed):', e);
      }

      // ── Exit: MFA check errored — sign out and return error ────────────
      if (mfaErr) {
        signInInProgressRef.current = false;
        deferredSignedInRef.current = null;
        // Fire-and-forget — SIGNED_OUT handler will clear user/session state
        supabase.auth.signOut().catch(() => {});
        return { error: mfaErr, data };
      }

      // ── Exit: TOTP required ─────────────────────────────────────────────
      // Set totpPendingRef BEFORE clearing signInInProgressRef to ensure
      // there is zero window where neither guard is active.  This ref stays
      // true until completeTOTPSignIn() or cancelTOTPSignIn() is called —
      // it gates TOKEN_REFRESHED, the health-check, and the initial-session
      // path so nothing can call setUser while the challenge is live.
      if (totpFactorId && totpChallengeId) {
        totpPendingRef.current = true;
        signInInProgressRef.current = false;
        deferredSignedInRef.current = null;
        return {
          error: null,
          data,
          requiresTOTP: true,
          totpFactorId,
          totpChallengeId,
        };
      }

      // ── Exit: No TOTP — apply the deferred SIGNED_IN ───────────────────
      // Snapshot into a local const BEFORE clearing the ref so TypeScript
      // can narrow on an immutable binding rather than a mutable ref property.
      signInInProgressRef.current = false;
      // TypeScript's control-flow analysis collapses User/Session to `never`
      // inside this large callback, making any annotation that references those
      // types produce an all-`never` object that TypeScript treats as impossible.
      // Asserting through `{ user: any; session: any }` breaks the inference
      // chain; downstream calls (setUser, setSession) still receive the correct
      // runtime values — the ref type guarantees that.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const deferred = deferredSignedInRef.current as { user: any; session: any } | null;
      deferredSignedInRef.current = null;
      if (deferred) {
        const dUser = deferred.user;
        const dSession = deferred.session;
        touchLastActivity(dUser.id, true);
        setSession(dSession);
        setUser(dUser);
        // Replicate the async post-login tasks normally run in the SIGNED_IN handler
        setTimeout(async () => {
          const deviceInfo = getDeviceInfo();
          const { isNewDevice, ipAddress, country, isp } = await trackDevice(dUser.id);
          checkWalletOnAuthRef.current(dUser.id);
          if (isNewDevice) sendLoginNotificationIfEnabled(dUser.id, deviceInfo, ipAddress, country, isp);
        }, 1500);
      }
    } else {
      signInInProgressRef.current = false;
      deferredSignedInRef.current = null;
    }

    return { error, data };
  }, []);

  const completeOTPVerification = useCallback(async () => {
    if (!pendingSession) return;
    
    const { user: pendingUser, session: pendingSessionData } = pendingSession;
    
    // Stamp activity at login so the 30-min inactivity clock starts now
    touchLastActivity(pendingUser.id, true);

    // Actually set the session and user state now
    setSession(pendingSessionData);
    setUser(pendingUser);
    
    const { isNewDevice, ipAddress, country, isp } = await trackDevice(pendingUser.id);
    const deviceInfo = getDeviceInfo();
    if (isNewDevice) sendLoginNotificationIfEnabled(pendingUser.id, deviceInfo, ipAddress, country, isp);
    
    // Clear pending state
    setPendingOTPWithTimestamp(null);
    setPendingSession(null);
    
    try {
      sessionStorage.removeItem('pendingOTP_data');
      sessionStorage.removeItem('pendingOTP_session');
    } catch { /* silent */ }
  }, [pendingSession, setPendingOTPWithTimestamp]);

  const cancelOTPVerification = useCallback(async () => {
    // Sign out from Supabase to clear the pending session
    const supabase = await getSupabase();
    await supabase.auth.signOut();
    
    setPendingOTPWithTimestamp(null);
    setPendingSession(null);
    
    try {
      sessionStorage.removeItem('pendingOTP_data');
      sessionStorage.removeItem('pendingOTP_session');
    } catch { /* silent */ }
  }, [setPendingOTPWithTimestamp]);

  // ── TOTP completion / cancellation ─────────────────────────────────────

  // beginPasskeyAuth: called by signin.tsx just before starting the WebAuthn
  //   ceremony (both button and conditional/autofill paths).  Parks the SIGNED_IN
  //   event in deferredSignedInRef so user state is never set while the AAL check
  //   is in flight — same interception pattern used by signIn() for passwords.
  const beginPasskeyAuth = useCallback(() => {
    signInInProgressRef.current = true;
    deferredSignedInRef.current = null;
  }, []);

  // releasePasskeyAuth: called when the passkey flow succeeds with no 2FA.
  //   Clears the interception gate and applies the deferred SIGNED_IN payload.
  const releasePasskeyAuth = useCallback(() => {
    signInInProgressRef.current = false;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const deferred = deferredSignedInRef.current as { user: any; session: any } | null;
    deferredSignedInRef.current = null;
    if (deferred) {
      touchLastActivity(deferred.user.id, true);
      setSession(deferred.session);
      setUser(deferred.user);
      setTimeout(async () => {
        const deviceInfo = getDeviceInfo();
        const { isNewDevice, ipAddress, country, isp } = await trackDevice(deferred.user.id);
        checkWalletOnAuthRef.current(deferred.user.id);
        if (isNewDevice) sendLoginNotificationIfEnabled(deferred.user.id, deviceInfo, ipAddress, country, isp);
      }, 1500);
    }
  }, []);

  // pauseSessionForTOTP: called by signin.tsx immediately after passkey auth
  //   succeeds and a verified TOTP factor is detected.  Also clears
  //   signInInProgressRef (set by beginPasskeyAuth) and discards the deferred
  //   payload so the AAL1 session never reaches user state.
  //   completeTOTPSignIn() re-commits the AAL2 session after mfa.verify().
  const pauseSessionForTOTP = useCallback(() => {
    signInInProgressRef.current = false;
    deferredSignedInRef.current = null;
    totpPendingRef.current = true;
    setUser(null);
    setSession(null);
  }, []);

  // completeTOTPSignIn: called by signin.tsx after mfa.verify() succeeds.
  //   Clears totpPendingRef and commits the now-AAL2 session to auth state.
  const completeTOTPSignIn = useCallback(async () => {
    totpPendingRef.current = false;
    const supabase = await getSupabase();
    const { data: { session } } = await supabase.auth.getSession();
    if (session?.user) {
      touchLastActivity(session.user.id, true);
      setSession(session);
      setUser(session.user);
      setTimeout(async () => {
        const deviceInfo = getDeviceInfo();
        const { isNewDevice, ipAddress, country, isp } = await trackDevice(session.user.id);
        checkWalletOnAuthRef.current(session.user.id);
        if (isNewDevice) sendLoginNotificationIfEnabled(session.user.id, deviceInfo, ipAddress, country, isp);
      }, 1500);
    }
  }, []);

  // cancelTOTPSignIn: called when the user clicks "Back to Login".
  //   Clears the gate and signs out the partial AAL1 session so nothing lingers.
  const cancelTOTPSignIn = useCallback(async () => {
    totpPendingRef.current = false;
    const supabase = await getSupabase();
    await supabase.auth.signOut().catch(() => {});
  }, []);

  const signOut = useCallback(async () => {
    // Clear sensitive in-memory state immediately
    setSessionPassword(null);
    setWalletImportState({ required: false, expectedAddress: null });
    void import("./non-custodial-wallet").then(({ clearWalletStateFromMemory }) => {
      clearWalletStateFromMemory();
    });
    // Drop cached wallet rows / balances / data and any volatile secrets now,
    // before the network sign-out, so nothing stale is visible or reusable.
    const { clearWalletQueryCaches } = await import("./wallet-query-cache");
    await clearWalletQueryCaches();
    checkedUsersRef.current.clear();
    setPendingOTPWithTimestamp(null);
    setPendingSession(null);

    // Sign out from Supabase first so the server-side session is revoked
    const supabase = await getSupabase();
    await supabase.auth.signOut();

    // Call clearWorkerSessionCache on logout as a matter of habit — but note
    // it's currently a no-op: vault-crypto.ts deliberately keeps no reusable
    // derived-key cache in production (every prepare/sign call re-derives
    // and wipes its own key immediately after use), so there's nothing
    // cached in the worker heap for this to clear. Kept here in case that
    // changes later; harmless either way.
    try {
      const { clearWorkerSessionCache } = await import("@/hooks/use-signing-worker");
      await clearWorkerSessionCache();
    } catch { /* non-fatal — worker may not be running */ }

    // Wipe all browser storage: localStorage, sessionStorage, and IndexedDB.
    // This ensures no decrypted wallet data, cached keys, or session tokens remain.
    const { wipeSecureStorage } = await import("./secure-storage-wiper");
    const wipe = await wipeSecureStorage();
    if (!wipe.ok) {
      // The session is already revoked, but wallet data may still be on this
      // device. Do NOT pretend the wipe succeeded: a pending-wipe marker was
      // left, and the next session will finish it before loading any wallet
      // data (see checkWalletOnAuth).
      devLog.error("Logout storage wipe incomplete; will retry before next wallet load", {
        indexedDb: wipe.indexedDb,
      });
    }
    // Clear once more: queries that resolved during the awaits above could
    // have re-populated the cache.
    await clearWalletQueryCaches();
  }, [setSessionPassword, setPendingOTPWithTimestamp]);

  const value = {
    user,
    session,
    signUp,
    signIn,
    signOut,
    completeOTPVerification,
    cancelOTPVerification,
    completeTOTPSignIn,
    cancelTOTPSignIn,
    pauseSessionForTOTP,
    beginPasskeyAuth,
    releasePasskeyAuth,
    loading,
    isLoading: loading,
    pendingOTPVerification,
    walletImportState,
    setWalletImportState,
    isWalletUnlocked,
    unlockWallet,
    lockWallet,
    // Returns the vault password from module scope on demand.
    // NEVER place _vaultPassword directly in the value object — the context
    // value is inspectable via React DevTools and would expose the plaintext
    // password to anyone with DevTools open. A function reference is visible
    // in DevTools; its return value is not.
    getSessionPassword: () => _vaultPassword,
    setSessionPassword,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
