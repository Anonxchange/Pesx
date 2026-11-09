import { useState, useEffect, useMemo, useId } from "react";
import { setVolatileSecret, getVolatileSecret, wipeVolatileSecret } from "@/lib/volatile-secret-store";
import { useQueryClient } from "@tanstack/react-query";
import { usePasswordRateLimit } from "@/hooks/use-password-rate-limit";
import {
  Dialog,
  DialogContent,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useToast } from "@/hooks/use-toast";
import { requestWalletRefresh } from "@/hooks/use-wallet-balances";
import { getSupabase } from "@/lib/supabase";
import { walletRowsQueryKey } from "@/lib/wallet-rows";
import { AlertTriangle, X } from '@/lib/icons';
import { LoadingSpinner } from "@/components/ui/loading-spinner";

// A curated slice of the most common breached/weak passwords. This is NOT a
// substitute for a real breach-corpus check (a proper one has thousands to
// millions of entries, e.g. via an HaveIBeenPwned range query) — it's here so
// the "not a common password" requirement below rejects real garbage instead
// of just the 18 most obvious strings, closing most of the gap between
// "looks strong on paper" and "is in the first breach dump an attacker tries."
const COMMON_PASSWORDS = [
  "password","password1","password123","password1234","passw0rd","p@ssword","p@ssw0rd",
  "12345678","123456789","1234567890","123123123","12341234","1q2w3e4r","1qaz2wsx",
  "qwerty123","qwertyuiop","qwerty1234","asdfghjkl","zxcvbnm123",
  "iloveyou","iloveyou1","iloveyou123","letmein","letmein123","welcome1","welcome123",
  "admin123","administrator","monkey123","dragon123","master123","superman123",
  "abc123456","abc12345","abcd1234","a1b2c3d4","trustno1","freedom123","whatever123",
  "football1","football123","baseball1","basketball1","soccer123","hockey123",
  "shadow123","michael123","jennifer1","jordan23","daniel123","matthew123","andrew123",
  "starwars1","batman123","pokemon123","minecraft1","hunter123","tigger123",
  "sunshine1","princess1","flower123","summer2023","summer2024","winter2023","winter2024",
  "chocolate1","cheese123","coffee123","banana123","orange123",
  "changeme1","changeit1","letmeinplz","opensesame","backdoor1","secret123","private123",
  "wallet123","crypto123","bitcoin123","satoshi123","blockchain1","money123","richman123",
  "correcthorsebatterystaple","test1234","testtest1","demo12345","sample123",
  "121212121","112233445","1111111111","0000000000","9876543210",
  "aaaaaaaa1","zzzzzzzz1","asdasdasd","qazwsxedc","1a2b3c4d5",
];

function validateWalletPassword(password: string): { isValid: boolean; score: number; errors: string[] } {
  const checks = [
    { test: /.{8,}/.test(password),               msg: "At least 8 characters" },
    { test: /[A-Z]/.test(password),               msg: "One uppercase letter" },
    { test: /[a-z]/.test(password),               msg: "One lowercase letter" },
    { test: /[0-9]/.test(password),               msg: "One number" },
    { test: /[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/`~;']/.test(password), msg: "One special character" },
    { test: !COMMON_PASSWORDS.includes(password.toLowerCase()), msg: "Must not be a common password" },
  ];
  const errors = checks.filter((c) => !c.test).map((c) => c.msg);
  const score = Math.round((checks.filter((c) => c.test).length / checks.length) * 100);
  return { isValid: errors.length === 0, score, errors };
}

import securityIllustration from "@/assets/svg-image-1 20.svg";

interface WalletSetupDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  userId: string;
  onSuccess: () => void;
  expectedAddress?: string | null;
}

export function WalletSetupDialog({ open, onOpenChange, userId, onSuccess, expectedAddress }: WalletSetupDialogProps) {
  const [step, setStep] = useState<"intro" | "password" | "generating" | "backup" | "success">("intro");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [isGenerating, setIsGenerating] = useState(false);
  const [walletStateVerified, setWalletStateVerified] = useState(false);
  // The recovery phrase is NOT React state. It lives in the volatile store
  // (module scope, TTL, wiped on confirm/unmount/logout); React only holds a
  // non-secret id and a counter that forces a re-render when it changes.
  const phraseId = useId();
  const [, setPhraseNonce] = useState(0);
  const mnemonic = getVolatileSecret(phraseId);
  const setMnemonic = (value: string) => {
    if (value) {
      setVolatileSecret(phraseId, value, {
        ttlMs: 10 * 60_000,
        onExpire: () => setPhraseNonce((n) => n + 1),
      });
    } else {
      wipeVolatileSecret(phraseId);
    }
    setPhraseNonce((n) => n + 1);
  };
  useEffect(() => () => wipeVolatileSecret(phraseId), [phraseId]);
  const [mnemonicRevealed, setMnemonicRevealed] = useState(false);
  const [backupConfirmedCheckbox, setBackupConfirmedCheckbox] = useState(false);
  const [backupUnavailable, setBackupUnavailable] = useState(false);
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const rateLimit = usePasswordRateLimit({ maxAttempts: 3, baseDelayMs: 15_000 });

  const passwordValidation = useMemo(() => validateWalletPassword(password), [password]);

  // Guard: when the dialog opens, verify the RPC-scoped wallet state before
  // allowing creation. A failed check is fail-closed: never create locally
  // when the server state is unknown.
  useEffect(() => {
    if (!open || !userId) return;

    let cancelled = false;
    setWalletStateVerified(false);

    const checkExisting = async () => {
      try {
        const supabase = await getSupabase();
        const { nonCustodialWalletManager } = await import("@/lib/non-custodial-wallet");
        const wallets = await nonCustodialWalletManager.loadWalletsFromSupabase(supabase, userId);

        if (cancelled) return;

        if (wallets.length > 0) {
          // Wallet already exists — close silently and signal success
          onOpenChange(false);
          onSuccess();
          return;
        }

        setWalletStateVerified(true);
      } catch {
        if (cancelled) return;
        toast({
          title: "Wallet status unavailable",
          description: "We could not verify your wallet. No wallet was created. Please try again.",
          variant: "destructive",
        });
        onOpenChange(false);
      }
    };

    checkExisting();

    return () => {
      cancelled = true;
    };
  }, [open, userId]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleCreatePassword = async () => {
    if (!passwordValidation.isValid) {
      toast({
        title: "Password too weak",
        description: passwordValidation.errors[0] ?? "Please meet all password requirements.",
        variant: "destructive",
      });
      return;
    }

    if (password !== confirmPassword) {
      toast({
        title: "Passwords don't match",
        description: "Please make sure both passwords match.",
        variant: "destructive",
      });
      return;
    }

    // Capture before any state clearing below — needed again after creation
    // to decrypt the recovery phrase for the backup step.
    const walletPassword = password;

    setStep("generating");
    setIsGenerating(true);

    // Yield to the React render cycle so the "Generating…" UI paints before
    // scrypt saturates the CPU. Without this, the button stays in its pressed
    // state for the full 1–3 s KDF duration before the loading screen appears.
    await new Promise<void>(r => setTimeout(r, 32));

    let canonicalWallets: Awaited<ReturnType<typeof import("@/lib/non-custodial-wallet").createMyWallets>> | null = null;

    try {
      const supabase = await getSupabase();
      const { createMyWallets, nonCustodialWalletManager } = await import("@/lib/non-custodial-wallet");

      // Single source of truth for wallet generation: one worker call inside
      // generateNonCustodialWallets() handles mnemonic generation, all 5
      // chain key derivations, and all 6 vault encryptions (one shared
      // scrypt derivation) entirely inside the isolated worker realm. The
      // mnemonic is generated, used, and wiped inside the worker and never
      // crosses the postMessage wire.
      //
      // persist:false here is deliberate: createMyWallets below is the one
      // atomic, RPC-canonical write path (it checks for an existing wallet
      // server-side and reloads the canonical rows afterward). Letting the
      // manager also persist directly would race a second, uncoordinated
      // write against that RPC call.
      const { wallets: baseWallets } = await nonCustodialWalletManager.generateNonCustodialWallets(
        walletPassword,
        undefined,
        userId,
        undefined,
        { persist: false },
      );

      const evmWallet = baseWallets.find((w) => w.chainId === "ethereum");
      if (!evmWallet) {
        throw new Error("Wallet generator returned no Ethereum wallet.");
      }

      // Verify BEFORE persisting, not after. The previous version checked
      // this against canonicalWallets (post-RPC-write) — if it ever actually
      // failed, the mismatched wallet was already saved server-side with
      // nothing to clean it up. Checking the locally generated address first
      // means a mismatch never reaches the database at all.
      if (expectedAddress && evmWallet.address.toLowerCase() !== expectedAddress.toLowerCase()) {
        throw new Error("Generated wallet address did not match the expected address.");
      }

      // BNB and Avalanche share the same EVM key/address/vault — pure
      // relabeling via addEvmChainVariant, no extra derivation needed.
      // Polygon/Arbitrum/Optimism get their own rows too. Without them the
      // receive dialog could show the shared EVM address for these networks
      // while balance monitoring never read those chains.
      const [bnbWallet, avalancheWallet, polygonWallet, arbitrumWallet, optimismWallet] = await Promise.all([
        nonCustodialWalletManager.addEvmChainVariant(
          evmWallet, "BNB", "binance", userId, undefined, undefined, { persist: false },
        ),
        nonCustodialWalletManager.addEvmChainVariant(
          evmWallet, "Avalanche", "ethereum", userId, undefined, undefined, { persist: false },
        ),
        nonCustodialWalletManager.addEvmChainVariant(
          evmWallet, "Polygon", "ethereum", userId, undefined, undefined, { persist: false },
        ),
        nonCustodialWalletManager.addEvmChainVariant(
          evmWallet, "Arbitrum", "ethereum", userId, undefined, undefined, { persist: false },
        ),
        nonCustodialWalletManager.addEvmChainVariant(
          evmWallet, "Optimism", "ethereum", userId, undefined, undefined, { persist: false },
        ),
      ]);

      const coreWallets = [
        ...baseWallets.map((w) =>
          w.chainId === "bitcoin" ? { ...w, chainId: "Bitcoin (SegWit)" } : w
        ),
        bnbWallet,
        avalancheWallet,
      ];
      const generatedWallets = [...coreWallets, polygonWallet, arbitrumWallet, optimismWallet];

      // The RPC write is authoritative. Only cache the canonical rows returned
      // by the RPC-backed reload; never make failed writes look successful
      // through local storage.
      try {
        canonicalWallets = await createMyWallets(supabase, generatedWallets, userId);
      } catch (fullSetError: any) {
        // If the server rejects the extra L2 chain rows (e.g. a chain_id
        // allow-list), fall back to the original wallet set so creation is
        // never blocked by them. createMyWallets is idempotent: if the first
        // attempt actually landed, this returns the existing rows.
        console.warn("Wallet creation with L2 rows failed, retrying core set:", fullSetError?.code ?? fullSetError?.message);
        canonicalWallets = await createMyWallets(supabase, coreWallets, userId);
      }
      if (canonicalWallets.length === 0) {
        throw new Error("Wallet creation returned no saved wallets.");
      }

      // The shared wallet-rows query may be holding an empty pre-creation
      // result; refresh it so receive addresses appear immediately.
      void queryClient.invalidateQueries({ queryKey: walletRowsQueryKey(userId) });
      requestWalletRefresh();
      rateLimit.reset();
    } catch (error: any) {
      console.error("Wallet creation failed:", error?.message ?? error, error);
      rateLimit.recordFailure();
      setPassword("");
      setConfirmPassword("");
      setStep("password");
      setIsGenerating(false);
      toast({
        title: "Generation failed",
        description: "We could not secure your wallet. No wallet was saved. Please try again.",
        variant: "destructive",
      });
      return;
    }

    // Wallet is now persisted. From here on, creation itself cannot be
    // retried from scratch (re-opening this dialog will see the wallet
    // already exists and skip straight past creation) — so a failure in
    // THIS step must never be presented as "please try again" the same way
    // a creation failure is. The user's funds-recovery phrase is what's at
    // stake here, not whether the wallet exists.
    try {
      const { nonCustodialWalletManager } = await import("@/lib/non-custodial-wallet");
      const mnemonicVault = canonicalWallets.find((w) => w.encryptedMnemonic)?.encryptedMnemonic;
      if (!mnemonicVault) {
        throw new Error("No recovery-phrase vault was returned for this wallet.");
      }
      const revealedMnemonic = await nonCustodialWalletManager.getWalletMnemonicForBackup(
        mnemonicVault as any,
        walletPassword,
      );
      setMnemonic(revealedMnemonic);
      setPassword("");
      setConfirmPassword("");
      setStep("backup");
    } catch (error: any) {
      // Never log the error object: it can originate in the crypto path.
      console.error("Recovery phrase retrieval failed after wallet creation", { name: error?.name ?? null });
      setPassword("");
      setConfirmPassword("");
      setBackupUnavailable(true);
      setStep("success");
      toast({
        title: "Wallet created — backup phrase unavailable",
        description: "Your wallet was created, but we couldn't display your recovery phrase right now. Go to Settings → Security to view and back it up before adding funds.",
        variant: "destructive",
      });
    } finally {
      setIsGenerating(false);
    }
  };

  const handleBackupContinue = async () => {
    if (!backupConfirmedCheckbox) return;

    // Best-effort only: this app's Supabase access goes exclusively through
    // RPCs (create_my_wallets, get_my_wallet) everywhere else in
    // non-custodial-wallet.ts — there's no existing RPC to flip isBackedUp,
    // and a raw table update from the client would likely be rejected by RLS
    // anyway (or worse, silently succeed via an unintended policy). Rather
    // than guess at a write this codebase doesn't otherwise make, this is
    // left as a no-op with a clear TODO: add a `mark_wallet_backed_up` (or
    // similar) RPC and call it here once it exists.
    // TODO: await supabase.rpc("mark_wallet_backed_up", { wallet_id: ... });

    // Drop the mnemonic from component state as soon as it's no longer
    // needed on screen — it's a plain JS string (can't be actively wiped
    // the way the worker wipes its Uint8Arrays), so the best available
    // mitigation is minimizing how long a reference to it exists at all.
    setMnemonic("");
    setStep("success");
  };

  const handleFinish = () => {
    localStorage.setItem(`wallet_setup_done_${userId}`, 'true');
    onOpenChange(false);
    onSuccess();
  };

  return (
    <Dialog open={open} onOpenChange={(isGenerating || step === "backup") ? undefined : (open) => {
      if (step === "success") {
        onOpenChange(open);
      }
    }}>
      <DialogContent className="max-w-[380px] w-[90vw] p-0 overflow-visible bg-white border-none shadow-2xl rounded-[32px]">
        <div className="relative flex flex-col items-center pt-10 pb-7 px-7">
          {/* Floating SVG Illustration */}
          <div className="absolute -top-20 left-1/2 -translate-x-1/2 w-44 h-44 pointer-events-none z-50">
            <img
              src={securityIllustration}
              alt="Security Illustration"
              className="w-full h-full object-contain drop-shadow-[0_15px_30px_rgba(180,242,46,0.4)]"
            />
          </div>

          <div className="w-full space-y-5 mt-14 max-h-[70vh] overflow-y-auto no-scrollbar">
            {step === "intro" && (
              <div className="space-y-6 text-center animate-in fade-in slide-in-from-bottom-4 duration-500">
                <div className="space-y-3">
                  <h2 className="text-3xl font-bold tracking-tight text-black">
                    Password Protected
                  </h2>
                  <p className="text-gray-500 text-base leading-relaxed">
                    Secure your digital assets with Pexly's non-custodial wallet. You are in full control of your private keys and funds.
                  </p>
                </div>

                <div className="bg-red-50 border border-red-100 p-4 rounded-2xl flex gap-3 text-left">
                  <AlertTriangle className="w-5 h-5 text-red-600 shrink-0 mt-0.5" />
                  <p className="text-xs text-red-800 leading-relaxed font-medium">
                    <span className="font-bold text-red-700 block mb-1 uppercase tracking-wider">Crucial Security Notice:</span>
                    We cannot recover your password. Keep your password and secret phrase safe. Your secret phrase can also restore access to your wallet on another non-custodial platform.
                  </p>
                </div>

                <div className="space-y-3 pt-2">
                  <Button
                    className="w-full h-14 bg-[#B4F22E] hover:bg-[#a3db29] text-black font-bold text-lg rounded-full transition-all hover:scale-[1.02] shadow-[0_4px_12px_rgba(180,242,46,0.3)]"
                     onClick={() => setStep("password")}
                     disabled={!walletStateVerified}
                  >
                    Enter now
                  </Button>
                </div>
              </div>
            )}

            {step === "password" && (
              <div className="space-y-6 text-center animate-in fade-in slide-in-from-right-4 duration-500">
                <div className="space-y-1">
                  <h2 className="text-2xl font-bold text-black">Security Credentials</h2>
                  <p className="text-gray-500 text-sm">Establish your master access password.</p>
                </div>
                <div className="space-y-3">
                  <div className="relative group">
                    <Input
                      type="password"
                      placeholder="New password"
                      className="bg-gray-50 border-gray-100 focus:border-[#B4F22E] h-14 px-6 rounded-full text-black placeholder:text-gray-400 text-base text-center transition-all"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                    />
                  </div>

                  {password.length > 0 && (
                    <div className="text-left px-2 space-y-2">
                      <div className="flex items-center justify-between text-xs mb-1">
                        <span className="text-gray-500">Strength</span>
                        <span className={
                          passwordValidation.score >= 100 ? "text-green-600 font-semibold" :
                          passwordValidation.score >= 60  ? "text-yellow-600 font-semibold" :
                          "text-red-500 font-semibold"
                        }>
                          {passwordValidation.score >= 100 ? "Strong" :
                           passwordValidation.score >= 60  ? "Fair" : "Weak"}
                        </span>
                      </div>
                      <div className="w-full h-1.5 bg-gray-200 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all duration-300 ${
                            passwordValidation.score >= 100 ? "bg-green-500" :
                            passwordValidation.score >= 60  ? "bg-yellow-400" :
                            "bg-red-400"
                          }`}
                          style={{ width: `${passwordValidation.score}%` }}
                        />
                      </div>
                      <ul className="space-y-1 pt-1">
                        {passwordValidation.errors.map((err, i) => (
                          <li key={i} className="flex items-center gap-2 text-xs text-red-500">
                            <X className="w-3 h-3 shrink-0" />
                            {err}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  <div className="relative group">
                    <Input
                      type="password"
                      placeholder="Confirm password"
                      className="bg-gray-50 border-gray-100 focus:border-[#B4F22E] h-14 px-6 rounded-full text-black placeholder:text-gray-400 text-base text-center transition-all"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                    />
                  </div>

                  {rateLimit.isLocked && (
                    <p className="text-xs text-destructive text-center font-medium py-1">
                      Too many failed attempts — try again in {rateLimit.lockoutSeconds}s
                    </p>
                  )}
                  <Button
                    className="w-full h-14 bg-[#B4F22E] hover:bg-[#a3db29] text-black font-bold text-lg rounded-full mt-2 transition-all hover:scale-[1.02] shadow-[0_4px_12px_rgba(180,242,46,0.2)] disabled:opacity-50"
                    onClick={handleCreatePassword}
                    disabled={isGenerating || rateLimit.isLocked}
                  >
                    {rateLimit.isLocked
                      ? `Locked (${rateLimit.lockoutSeconds}s)`
                      : "Confirm & Secure"}
                  </Button>
                </div>
              </div>
            )}

            {step === "generating" && (
              <div className="flex flex-col items-center justify-center py-10 space-y-6 animate-in zoom-in-95 duration-500">
                <div className="relative">
                  <div className="absolute inset-0 bg-[#B4F22E]/20 blur-2xl rounded-full"></div>
                   <LoadingSpinner size={64} color="hsl(var(--primary))" className="relative" />
                </div>
                <div className="text-center space-y-2">
                  <h2 className="text-xl font-bold text-black uppercase tracking-widest">Encrypting</h2>
                  <p className="text-gray-500 text-sm max-w-xs">
                     Do not disconnect from Wi-Fi or close this tab while encryption is in progress. The process may take several minutes.
                  </p>
                </div>
              </div>
            )}

            {step === "backup" && (
              <div className="space-y-5 text-center animate-in fade-in slide-in-from-right-4 duration-500">
                <div className="space-y-1">
                  <h2 className="text-2xl font-bold text-black">Back Up Your Recovery Phrase</h2>
                  <p className="text-gray-500 text-sm">
                    Write these {mnemonic.split(/\s+/).filter(Boolean).length} words down in order and store them somewhere safe. This is the only way to recover your wallet.
                  </p>
                </div>

                <div className="bg-red-50 border border-red-100 p-3 rounded-2xl flex gap-2 text-left">
                  <AlertTriangle className="w-4 h-4 text-red-600 shrink-0 mt-0.5" />
                  <p className="text-[11px] text-red-800 leading-snug font-medium">
                    This phrase will not be shown again after you continue. Anyone with these words can take your funds — never share them, and never enter them anywhere except this app.
                  </p>
                </div>

                <div className="relative">
                  <div
                    className={`grid grid-cols-3 gap-2 bg-gray-50 border border-gray-100 rounded-2xl p-4 select-none transition-all ${
                      mnemonicRevealed ? "" : "blur-md pointer-events-none"
                    }`}
                  >
                    {mnemonic.split(/\s+/).filter(Boolean).map((word, i) => (
                      <div
                        key={i}
                        className="flex items-center gap-1.5 bg-white border border-gray-100 rounded-lg px-2 py-1.5 text-left"
                      >
                        <span className="text-[10px] text-gray-400 font-semibold w-4 shrink-0">{i + 1}</span>
                        <span className="text-xs font-mono font-medium text-black truncate">{word}</span>
                      </div>
                    ))}
                  </div>
                  {!mnemonicRevealed && (
                    <button
                      type="button"
                      onClick={() => setMnemonicRevealed(true)}
                      className="absolute inset-0 flex items-center justify-center"
                    >
                      <span className="bg-black/80 text-white text-xs font-bold px-4 py-2 rounded-full">
                        Tap to reveal
                      </span>
                    </button>
                  )}
                </div>

                <label className="flex items-start gap-2.5 text-left px-1 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={backupConfirmedCheckbox}
                    onChange={(e) => setBackupConfirmedCheckbox(e.target.checked)}
                    className="mt-0.5 w-4 h-4 accent-[#B4F22E] shrink-0"
                  />
                  <span className="text-xs text-gray-600 leading-snug">
                    I've written down my recovery phrase and stored it somewhere safe. I understand Pexly cannot recover it for me.
                  </span>
                </label>

                <Button
                  className="w-full h-14 bg-[#B4F22E] hover:bg-[#a3db29] text-black font-bold text-lg rounded-full transition-all hover:scale-[1.02] shadow-[0_4px_12px_rgba(180,242,46,0.2)] disabled:opacity-50"
                  onClick={handleBackupContinue}
                  disabled={!backupConfirmedCheckbox || !mnemonicRevealed}
                >
                  Continue
                </Button>
              </div>
            )}

            {step === "success" && (
              <div className="space-y-6 text-center animate-in fade-in zoom-in-95 duration-500">
                <div className="space-y-3">
                  <h2 className="text-3xl font-bold text-black leading-tight">Vault Secured</h2>
                  <p className="text-gray-500 text-base leading-relaxed">
                    Your non-custodial wallet is now ready.
                  </p>
                </div>
                {backupUnavailable && (
                  <div className="bg-red-50 border border-red-100 p-4 rounded-2xl flex gap-3 text-left">
                    <AlertTriangle className="w-5 h-5 text-red-600 shrink-0 mt-0.5" />
                    <p className="text-xs text-red-800 leading-relaxed font-medium">
                      We couldn't display your recovery phrase due to an error. Your wallet was still created — go to
                      Settings → Security to view and back it up before adding funds.
                    </p>
                  </div>
                )}
                <div className="bg-gray-50 p-5 rounded-[24px] border border-gray-100">
                  <p className="text-[10px] text-[#8BB424] font-bold uppercase tracking-[0.2em] mb-3">Supported Networks</p>
                  <div className="flex flex-wrap gap-2 justify-center">
                    {["BTC", "ETH", "BNB", "TRX", "SOL", "AVAX", "USDT", "USDC"].map((s) => (
                      <span key={s} className="px-2.5 py-1 bg-white border border-gray-100 rounded-lg text-[10px] font-bold text-black shadow-sm">
                        {s}
                      </span>
                    ))}
                  </div>
                </div>
                <Button
                  className="w-full h-14 bg-[#B4F22E] hover:bg-[#a3db29] text-black font-bold text-lg rounded-full transition-all hover:scale-[1.02] shadow-[0_4px_12px_rgba(180,242,46,0.3)]"
                  onClick={handleFinish}
                >
                  Enter Dashboard
                </Button>
              </div>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
