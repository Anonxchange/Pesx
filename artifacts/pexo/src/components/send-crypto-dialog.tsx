import { useState, useEffect, useRef, useCallback } from "react";
import { usePasswordRateLimit } from "@/hooks/use-password-rate-limit";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  AlertCircle,
  Loader2,
  CheckCircle2,
  X,
  ShieldCheck,
  ShieldAlert,
  ArrowRight,
  ChevronLeft,
} from "@/lib/icons";
import {
  prepareEVMTransferIntent,
  signEVMTransactionFromVault,
  prepareBitcoinTransferIntent,
  signBitcoinTransactionFromVault,
  prepareSolanaTransferIntent,
  signSolanaTransactionFromVault,
  prepareSplTokenTransferIntent,
  signSplTokenTransactionFromVault,
  prepareTronTransferIntent,
  signTronTransactionFromVault,
  prepareTrc20TransferIntent,
  signTrc20TransactionFromVault,
} from "@/hooks/use-signing-worker";
import { broadcastEVMTransaction } from "@/lib/evmSigner";
import { broadcastSolanaTransaction } from "@/lib/solanaSigner";
import { broadcastTronTransaction } from "@/lib/tronSigner";
import { btcFees, btcUtxos, chainBroadcast } from "@/lib/chain-gateway";
import { monitorWithdrawal } from "@/lib/withdrawal-monitor";
import { requestWalletRefresh } from "@/hooks/use-wallet-balances";
import { recordWithdrawalTransaction, toMonitorChainKey } from "@/lib/wallet-api";
import { useAuth } from "@/lib/auth-context";
import { CoinIcon } from "@/components/trading/CoinIcon";
import { useSendFee } from "@/hooks/use-fees";
import { getCryptoPrices, convertCurrency } from "@/lib/crypto-prices";
import { useToast } from "@/hooks/use-toast";
import {
  preTransactionCheck,
  type AddressSecurityResult,
  type TokenSecurityResult,
  GOPLUS_CHAINS,
} from "@/lib/goplusSecurity";
import { useIsMobile } from "@/hooks/use-mobile";

interface SendCryptoDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  wallets: Array<{ symbol: string; balance: number; name: string; icon: string }>;
  initialSymbol?: string;
  onSuccess?: () => void;
}

type Step = "select" | "details" | "confirm";

// ── Swipe-to-confirm slider ───────────────────────────────────────────────────
interface SwipeConfirmProps {
  onConfirm: () => void;
  disabled?: boolean;
  loading?: boolean;
  confirmed?: boolean;
}

function SwipeConfirmButton({ onConfirm, disabled, loading, confirmed: externalConfirmed }: SwipeConfirmProps) {
  const [progress, setProgress] = useState(0);
  const [isDragging, setIsDragging] = useState(false);
  const [localConfirmed, setLocalConfirmed] = useState(false);
  const trackRef = useRef<HTMLDivElement>(null);
  const dragStartX = useRef(0);
  const dragStartProgress = useRef(0);
  const THUMB_PX = 52;
  const THRESHOLD = 0.82;
  const confirmed = externalConfirmed || localConfirmed;

  // Reset when re-opened
  useEffect(() => {
    if (!externalConfirmed) {
      setLocalConfirmed(false);
      setProgress(0);
    }
  }, [externalConfirmed]);

  const trackAvailable = useCallback(() => {
    return (trackRef.current?.offsetWidth ?? 280) - THUMB_PX - 8;
  }, []);

  const handlePointerDown = (e: React.PointerEvent<HTMLDivElement>) => {
    if (disabled || loading || confirmed) return;
    e.currentTarget.setPointerCapture(e.pointerId);
    setIsDragging(true);
    dragStartX.current = e.clientX;
    dragStartProgress.current = progress;
  };

  const handlePointerMove = (e: React.PointerEvent<HTMLDivElement>) => {
    if (!isDragging) return;
    const delta = e.clientX - dragStartX.current;
    const available = trackAvailable();
    const next = Math.max(0, Math.min(dragStartProgress.current + delta / available, 1));
    setProgress(next);
  };

  const handlePointerUp = () => {
    if (!isDragging) return;
    setIsDragging(false);
    if (progress >= THRESHOLD) {
      setLocalConfirmed(true);
      setProgress(1);
      onConfirm();
    } else {
      setProgress(0);
    }
  };

  const thumbX = progress * trackAvailable();

  const trackLabel = loading
    ? "Sending…"
    : confirmed
    ? "Confirmed!"
    : "Slide to confirm";

  return (
    <div
      ref={trackRef}
      className={`relative h-[56px] rounded-full overflow-hidden select-none transition-colors ${
        confirmed ? "bg-emerald-500/20" : "bg-muted"
      } ${disabled ? "opacity-50" : ""}`}
    >
      {/* Fill */}
      <div
        className={`absolute inset-y-0 left-0 rounded-full transition-colors ${
          confirmed ? "bg-emerald-500/30" : "bg-primary/15"
        }`}
        style={{ width: `${THUMB_PX + 4 + thumbX}px`, transition: isDragging ? "none" : "width 0.3s ease" }}
      />

      {/* Track label */}
      <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
        <span
          className={`text-sm font-medium tracking-wide transition-opacity ${
            confirmed ? "text-emerald-600 dark:text-emerald-400" : "text-muted-foreground"
          }`}
          style={{ opacity: confirmed ? 1 : Math.max(0, 1 - progress * 2) }}
        >
          {trackLabel}
        </span>
        {/* Arrow hint dots */}
        {!confirmed && !loading && (
          <span
            className="absolute right-6 flex items-center gap-0.5 text-muted-foreground/40 pointer-events-none"
            style={{ opacity: Math.max(0, 1 - progress * 3) }}
          >
            <ArrowRight className="h-3.5 w-3.5" />
            <ArrowRight className="h-3.5 w-3.5 -ml-2" />
            <ArrowRight className="h-3.5 w-3.5 -ml-2" />
          </span>
        )}
      </div>

      {/* Thumb */}
      <div
        className={`absolute top-[4px] bottom-[4px] w-[${THUMB_PX}px] rounded-full flex items-center justify-center shadow-md cursor-grab active:cursor-grabbing transition-colors ${
          confirmed
            ? "bg-emerald-500"
            : loading
            ? "bg-primary/70"
            : "bg-primary"
        }`}
        style={{
          width: THUMB_PX,
          left: 4,
          transform: `translateX(${thumbX}px)`,
          transition: isDragging ? "none" : "transform 0.35s cubic-bezier(0.34,1.56,0.64,1)",
        }}
        onPointerDown={handlePointerDown}
        onPointerMove={handlePointerMove}
        onPointerUp={handlePointerUp}
        onPointerLeave={handlePointerUp}
      >
        {loading ? (
          <Loader2 className="h-5 w-5 text-primary-foreground animate-spin" />
        ) : confirmed ? (
          <CheckCircle2 className="h-5 w-5 text-white" />
        ) : (
          <ArrowRight className="h-5 w-5 text-primary-foreground" />
        )}
      </div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export function SendCryptoDialog({
  open,
  onOpenChange,
  wallets,
  initialSymbol,
  onSuccess,
}: SendCryptoDialogProps) {
  const { user, isWalletUnlocked, getSessionPassword, setSessionPassword } = useAuth();
  const rateLimit = usePasswordRateLimit({ maxAttempts: 5, baseDelayMs: 10_000 });
  const { toast } = useToast();
  const isMobile = useIsMobile();
  const successTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const [step, setStep] = useState<Step>("select");
  const [selectedCrypto, setSelectedCrypto] = useState<string>("");
  const [toAddress, setToAddress] = useState<string>("");
  const [amount, setAmount] = useState<string>("");
  const [notes, setNotes] = useState<string>("");
  const [selectedNetwork, setSelectedNetwork] = useState<string>("");
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [selectedCurrency, setSelectedCurrency] = useState<string>("USD");
  const [amountInputMode, setAmountInputMode] = useState<"fiat" | "crypto">("fiat");
  const [cryptoAmount, setCryptoAmount] = useState<string>("");
  const [fiatAmount, setFiatAmount] = useState<string>("");
  const [cryptoPrice, setCryptoPrice] = useState<number>(0);
  const [userPassword, setUserPassword] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [securityCheck, setSecurityCheck] = useState<{
    loading: boolean;
    safe: boolean;
    warnings: string[];
    addressCheck?: AddressSecurityResult;
    tokenCheck?: TokenSecurityResult;
  }>({ loading: false, safe: true, warnings: [] });

  useEffect(() => {
    return () => {
      if (successTimerRef.current) clearTimeout(successTimerRef.current);
    };
  }, []);

  useEffect(() => {
    if (open) {
      if (initialSymbol) {
        setSelectedCrypto(initialSymbol);
        setStep("details");
      } else {
        setStep("select");
        setSelectedCrypto("");
      }
    }
  }, [open, initialSymbol]);

  // Security check on address change
  useEffect(() => {
    const performSecurityCheck = async () => {
      if (!toAddress || toAddress.length < 30 || !selectedCrypto || !selectedNetwork) {
        setSecurityCheck({ loading: false, safe: true, warnings: [] });
        return;
      }
      setSecurityCheck((prev) => ({ ...prev, loading: true }));
      try {
        const chainId =
          GOPLUS_CHAINS[selectedNetwork.toLowerCase().split(" ")[0]] ||
          GOPLUS_CHAINS[selectedCrypto.toLowerCase()] ||
          "1";
        const result = await preTransactionCheck({ chainId, toAddress });
        setSecurityCheck({
          loading: false,
          safe: result.safe,
          warnings: result.warnings,
          addressCheck: result.addressCheck,
          tokenCheck: result.tokenCheck,
        });
      } catch {
        setSecurityCheck((prev) => ({ ...prev, loading: false }));
      }
    };
    const timer = setTimeout(performSecurityCheck, 800);
    return () => clearTimeout(timer);
  }, [toAddress, selectedCrypto, selectedNetwork]);

  const networkMap: Record<string, string[]> = {
    BTC: ["Bitcoin (SegWit)"],
    ETH: ["Ethereum (ERC-20)"],
    SOL: ["Solana"],
    BNB: ["Binance Smart Chain (BEP-20)"],
    TRX: ["Tron (TRC-20)"],
    AVAX: ["Avalanche (C-Chain)"],
    USDC: ["Ethereum (ERC-20)", "Binance Smart Chain (BEP-20)", "Tron (TRC-20)", "Solana (SPL)"],
    USDT: ["Ethereum (ERC-20)", "Binance Smart Chain (BEP-20)", "Tron (TRC-20)", "Solana (SPL)"],
  };

  useEffect(() => {
    const fetchPrice = async () => {
      if (!selectedCrypto) return;
      try {
        const prices = await getCryptoPrices([selectedCrypto]);
        if (prices[selectedCrypto]) {
          const priceInSelectedCurrency =
            selectedCurrency === "NGN"
              ? await convertCurrency(prices[selectedCrypto].current_price, "NGN")
              : prices[selectedCrypto].current_price;
          setCryptoPrice(priceInSelectedCurrency);
        }
      } catch {
        // silent
      }
    };
    fetchPrice();
  }, [selectedCrypto, selectedCurrency]);

  useEffect(() => {
    if (!cryptoPrice || cryptoPrice === 0) return;
    if (amountInputMode === "fiat") {
      const fiatValue = parseFloat(amount);
      if (isNaN(fiatValue) || !amount) { setCryptoAmount(""); return; }
      setCryptoAmount((fiatValue / cryptoPrice).toFixed(8));
    } else {
      const cryptoValue = parseFloat(amount);
      if (isNaN(cryptoValue) || !amount) { setFiatAmount(""); return; }
      setFiatAmount((cryptoValue * cryptoPrice).toFixed(2));
    }
  }, [amount, cryptoPrice, amountInputMode]);

  const getNetworkSpecificSymbol = (crypto: string, network: string): string => {
    if (crypto === "USDT" || crypto === "USDC") {
      if (network.includes("ERC-20")) return `${crypto}_ETH`;
      if (network.includes("BEP-20")) return `${crypto}_BSC`;
      if (network.includes("TRC-20")) return `${crypto}-TRC20`;
      if (network.includes("SPL"))    return `${crypto}-SOL`;
    }
    return crypto;
  };

  // Currency key format the *signing worker* actually recognizes
  // (TOKEN_CONTRACTS / SPL_TOKENS / TRC20_TOKENS in signing.worker.ts all key
  // on e.g. "USDT_TRX", "USDC_SOL" — underscored, and TRX/SOL not TRC20/SOL-
  // with-a-hyphen). Deliberately kept separate from getNetworkSpecificSymbol
  // above, which feeds the fee-quote API and may intentionally use a
  // different key shape for that unrelated concern — conflating the two is
  // exactly how the previous TRC-20 currency key ended up wrong.
  const getWorkerCurrencyKey = (crypto: string, network: string): string => {
    if (crypto === "USDT" || crypto === "USDC") {
      if (network.includes("ERC-20")) return `${crypto}_ETH`;
      if (network.includes("BEP-20")) return `${crypto}_BSC`;
      if (network.includes("TRC-20")) return `${crypto}_TRX`;
      if (network.includes("SPL"))    return `${crypto}_SOL`;
    }
    return crypto;
  };

  const selectedWallet = wallets.find((w) => w.symbol === selectedCrypto);
  const networkSpecificSymbol =
    selectedCrypto && selectedNetwork
      ? getNetworkSpecificSymbol(selectedCrypto, selectedNetwork)
      : selectedCrypto;
  const cryptoAmountForFee =
    amountInputMode === "crypto" ? parseFloat(amount) || 0 : parseFloat(cryptoAmount) || 0;

  const { data: feeData, isLoading: feeLoading, error: feeError } = useSendFee(
    networkSpecificSymbol || "",
    cryptoAmountForFee,
    false
  );

  const networkFee = feeData?.networkFee || 0;
  const feeSameToken = !feeData?.networkFeeSymbol || feeData.networkFeeSymbol === selectedCrypto;
  const total = feeSameToken ? cryptoAmountForFee + networkFee : cryptoAmountForFee;

  const handleSelectCrypto = (symbol: string) => {
    setSelectedCrypto(symbol);
    const networks = networkMap[symbol] || [];
    setSelectedNetwork(networks[0] || "");
    setStep("details");
  };

  // Validate without password (used for "Continue" on details step)
  const validateDetails = (): string | null => {
    if (!selectedCrypto || !toAddress || !amount) return "Please fill in all required fields";
    const cryptoAmountNum =
      amountInputMode === "crypto" ? parseFloat(amount) : parseFloat(cryptoAmount);
    if (isNaN(cryptoAmountNum) || cryptoAmountNum <= 0) return "Please enter a valid amount";
    if (selectedWallet && total > selectedWallet.balance) return "Insufficient balance";
    if (!securityCheck.safe) return "Security check failed. This address may be malicious.";
    return null;
  };

  const validateSendForm = (): string | null => {
    const detailsError = validateDetails();
    if (detailsError) return detailsError;
    if (!isWalletUnlocked && !userPassword) return "Please enter your wallet password";
    return null;
  };

  const executeSend = async (vault: unknown, password: string, fromAddress: string) => {
    if (!user) return;
    const cryptoAmountNum =
      amountInputMode === "crypto" ? parseFloat(amount) : parseFloat(cryptoAmount);
    // Worker-facing currency key (USDT_TRX, USDC_SOL, ...) — see note above
    // getWorkerCurrencyKey for why this is a separate mapping from the
    // fee-display symbol used elsewhere in this component.
    const workerCurrency = getWorkerCurrencyKey(selectedCrypto, selectedNetwork);
    const broadcastAt = Math.floor(Date.now() / 1000);
    let txHash = "";

    // Every branch below follows the same shape: prepare (resolves
    // network-derived values and returns a single-use approvalDigest bundled
    // into `signRequest`), then sign with EXACTLY that `signRequest` object —
    // not a hand-built one — since the sign step's approval check requires
    // it to match what prepare actually resolved. See use-signing-worker.ts's
    // comment above prepareEVMTransferIntent for the full explanation.

    if (selectedNetwork.includes("Bitcoin")) {
      const [feesResult, utxoResult] = await Promise.all([btcFees(), btcUtxos(fromAddress)]);
      const feeRate = feesResult.fast || feesResult.normal || 10;
      const amountSats = Math.floor(cryptoAmountNum * 1e8);
      if (!Number.isSafeInteger(amountSats) || amountSats <= 0) {
        throw new Error("Enter a valid Bitcoin amount.");
      }

      // Never spend mempool outputs. The gateway returns a dedicated
      // spendableUtxos list, and the fallback still requires one confirmation.
      const isConfirmedUtxo = (u: {
        confirmed?: boolean;
        confirmations?: number;
        blockHeight?: number | null;
      }) => u.confirmed === true || (u.confirmations ?? 0) >= 1 || (u.blockHeight ?? null) !== null;

      const spendableList = Array.isArray(utxoResult.spendableUtxos)
        ? utxoResult.spendableUtxos
        : [];

      const confirmedUtxos = (
        spendableList.length > 0 ? spendableList : (utxoResult.utxos ?? []).filter(isConfirmedUtxo)
      ).map((u) => ({
        txid: u.txid,
        vout: u.vout,
        value: Number(u.value),
      })).filter((u) => Number.isSafeInteger(u.value) && u.value > 0);

      if (confirmedUtxos.length === 0) {
        throw new Error("No confirmed Bitcoin funds are available yet. Wait for at least one confirmation.");
      }

      // Match the conservative SegWit signing estimate used by the worker:
      // inputs*148 + two outputs + overhead. Select the fewest large confirmed
      // UTXOs that can cover the amount and fee.
      const selectedUtxos: typeof confirmedUtxos = [];
      let selectedTotal = 0;
      for (const utxo of [...confirmedUtxos].sort((a, b) => b.value - a.value)) {
        selectedUtxos.push(utxo);
        selectedTotal += utxo.value;
        const estimatedFee = Math.ceil(
          (selectedUtxos.length * 148 + 2 * 34 + 10) * feeRate,
        );
        if (selectedTotal >= amountSats + estimatedFee) break;
      }

      const selectedFee = Math.ceil(
        (selectedUtxos.length * 148 + 2 * 34 + 10) * feeRate,
      );
      if (selectedTotal < amountSats + selectedFee) {
        throw new Error("Insufficient confirmed Bitcoin funds for this amount and network fee.");
      }

      const btcTxData = {
        to: toAddress,
        // parseDecimalUnits in the worker requires a string — previously this
        // passed the raw number `cryptoAmountNum`, which would have failed
        // ("Invalid amount") the moment the two-step approval was wired up.
        amount: cryptoAmountNum.toString(),
        utxos: selectedUtxos,
        feeRate,
        fromAddress,
      };
      const prepared = await prepareBitcoinTransferIntent(vault, password, btcTxData);
      const result = await signBitcoinTransactionFromVault(vault, password, prepared.signRequest) as any;
      const broadcastResult = await chainBroadcast("BTC", "sendrawtransaction", [result.signedTx]);
      txHash = broadcastResult?.result ?? broadcastResult;
    } else if (selectedNetwork.includes("Ethereum") || selectedNetwork.includes("Binance")) {
      const chainKey = selectedNetwork.includes("Binance") ? "BSC" : "ETH";
      const txData = { to: toAddress, amount: cryptoAmountNum.toString(), currency: workerCurrency as any };
      const prepared = await prepareEVMTransferIntent(vault, password, txData);
      const result = await signEVMTransactionFromVault(vault, password, prepared.signRequest) as any;
      // broadcastEVMTransaction(chain, signedTxHex) => { txHash }. Previous
      // version called it with the arguments reversed and assigned the whole
      // returned object to txHash instead of pulling .txHash out of it.
      txHash = (await broadcastEVMTransaction(chainKey, result.signedTx)).txHash;
    } else if (selectedNetwork.includes("Avalanche") || selectedCrypto === "AVAX") {
      const txData = { to: toAddress, amount: cryptoAmountNum.toString(), currency: "AVAX" as any };
      const prepared = await prepareEVMTransferIntent(vault, password, txData);
      const result = await signEVMTransactionFromVault(vault, password, prepared.signRequest) as any;
      txHash = (await broadcastEVMTransaction("AVAX", result.signedTx)).txHash;
    } else if (selectedNetwork.includes("Solana")) {
      // BUG FIXED: this branch previously matched on `selectedNetwork.includes("Solana")`,
      // which is also true for the "Solana (SPL)" network entry — but it
      // unconditionally sent `currency: "SOL"` regardless of which coin was
      // selected. A user choosing to send USDC or USDT on "Solana (SPL)"
      // would have had native SOL sent instead. Branch on the actual coin.
      if (selectedCrypto === "USDC" || selectedCrypto === "USDT") {
        const prepared = await prepareSplTokenTransferIntent(vault, password, {
          to: toAddress,
          amount: cryptoAmountNum.toString(),
          currency: workerCurrency as any, // "USDC_SOL" | "USDT_SOL"
        });
        const result = await signSplTokenTransactionFromVault(vault, password, prepared.signRequest) as any;
        // broadcastSolanaTransaction returns { signature }, not a bare string.
        txHash = (await broadcastSolanaTransaction(result.signedTx)).signature;
      } else {
        const prepared = await prepareSolanaTransferIntent(vault, password, {
          to: toAddress,
          amount: cryptoAmountNum.toString(),
          currency: "SOL",
        });
        const result = await signSolanaTransactionFromVault(vault, password, prepared.signRequest) as any;
        txHash = (await broadcastSolanaTransaction(result.signedTx)).signature;
      }
    } else if (selectedNetwork.includes("Tron")) {
      // Same class of bug as Solana above: native TRX vs TRC-20 USDC/USDT
      // need different prepare/sign pairs and a currency key the worker
      // actually recognizes (USDT_TRX / USDC_TRX, not "USDT-TRC20").
      if (selectedCrypto === "USDC" || selectedCrypto === "USDT") {
        const prepared = await prepareTrc20TransferIntent(vault, password, {
          to: toAddress,
          amount: cryptoAmountNum.toString(),
          currency: workerCurrency as any, // "USDC_TRX" | "USDT_TRX"
        });
        const result = await signTrc20TransactionFromVault(vault, password, prepared.signRequest) as any;
        // broadcastTronTransaction returns { txID }, not a bare string.
        txHash = (await broadcastTronTransaction(result.signedTx)).txID;
      } else {
        const prepared = await prepareTronTransferIntent(vault, password, {
          to: toAddress,
          amount: cryptoAmountNum.toString(),
        });
        const result = await signTronTransactionFromVault(vault, password, prepared.signRequest) as any;
        txHash = (await broadcastTronTransaction(result.signedTx)).txID;
      }
    } else {
      throw new Error(`Signing not supported for ${selectedNetwork}`);
    }

    // The chain broadcast above is the source of truth for send success.
    // Monitoring runs separately so an indexer outage cannot make an
    // irreversible, already-broadcast withdrawal appear to have failed.
    if (txHash) {
      try {
        await recordWithdrawalTransaction({
          userId: user.id,
          cryptoSymbol: selectedCrypto,
          amount: cryptoAmountNum,
          txHash: String(txHash),
          fromAddress,
          toAddress,
          createdAt: new Date(broadcastAt * 1000).toISOString(),
        });
      } catch (recordError) {
        // The funds are already broadcast. Keep the send successful, but log
        // the indexing failure so the transaction can be recovered manually.
        if (import.meta.env.DEV) {
          console.warn("[withdrawal-monitor] activity index write failed:", recordError);
        }
      }

      void monitorWithdrawal({
        // The monitor rejects UI labels like "Bitcoin (SegWit)"; send a chain key.
        chain: toMonitorChainKey(selectedNetwork),
        txHash,
        fromAddress,
        broadcastAt,
        expected: {
          toAddress,
          amount: cryptoAmountNum.toString(),
          asset: selectedCrypto,
        },
      }).catch((monitorError) => {
        if (import.meta.env.DEV) {
          console.warn("[withdrawal-monitor] initial status read failed:", monitorError);
        }
      });
      // Refresh balances, recent activity, and the wallet activity notifier
      // through the same event used by deposit monitoring. This is a signal,
      // not a background polling loop.
      requestWalletRefresh();
    }

    toast({
      title: "Transaction Sent!",
      description: "Your transaction has been signed and broadcast to the network.",
    });
    setSuccess(true);
    if (successTimerRef.current) clearTimeout(successTimerRef.current);
    successTimerRef.current = setTimeout(() => {
      setSuccess(false);
      onOpenChange(false);
      resetForm();
      onSuccess?.();
    }, 2000);
  };

  const handleSend = async () => {
    if (!user) return;
    const validationError = validateSendForm();
    if (validationError) { setError(validationError); return; }
    if (rateLimit.isLocked) return;

    setError("");
    setLoading(true);
    try {
      const passwordToUse = getSessionPassword() || userPassword;
      const { nonCustodialWalletManager } = await import("@/lib/non-custodial-wallet");
      const userWallets = await nonCustodialWalletManager.getNonCustodialWallets(user.id);
      const symbolMap: Record<string, string> = {
        BTC: "Bitcoin (SegWit)", ETH: "Ethereum", SOL: "Solana",
        BNB: "Binance Smart Chain (BEP-20)", TRX: "Tron (TRC-20)",
        AVAX: "Avalanche",
        USDT: "USDT", USDC: "USDC",
      };
      const chainIdToFind = symbolMap[selectedCrypto] || selectedCrypto;
      const targetWallet = userWallets.find(
        (w) => w.chainId === chainIdToFind || w.chainId === selectedNetwork || w.assetType === selectedCrypto
      );
      if (!targetWallet) throw new Error("Local wallet not found for the selected asset");
      const vault = targetWallet.encryptedMnemonic ?? targetWallet.encryptedPrivateKey;
      if (!vault) throw new Error("Wallet vault not found. Please recreate your wallet.");
      if (!getSessionPassword() && userPassword) setSessionPassword(userPassword);
      await executeSend(vault, passwordToUse, targetWallet.address);
      rateLimit.reset();
    } catch (err: any) {
      const msg = err.message || "Failed to send crypto";
      const isWrongPassword = /password|decrypt|invalid|corrupted/i.test(msg);
      if (isWrongPassword) rateLimit.recordFailure();
      setError(msg);
      setLoading(false);
    }
  };

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      setToAddress(text);
    } catch {
      // silent
    }
  };

  const resetForm = () => {
    setStep("select");
    setSelectedCrypto("");
    setToAddress("");
    setAmount("");
    setCryptoAmount("");
    setFiatAmount("");
    setNotes("");
    setSelectedNetwork("");
    setSelectedCurrency("USD");
    setAmountInputMode("fiat");
    setCryptoPrice(0);
    setError("");
    setSuccess(false);
    setUserPassword("");
  };

  const handleClose = () => {
    onOpenChange(false);
    resetForm();
  };

  // ── Formatting helpers ──────────────────────────────────────────────────────
  const fiatSymbol = selectedCurrency === "NGN" ? "₦" : "$";
  const fmt = (n: number) =>
    fiatSymbol +
    new Intl.NumberFormat("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 }).format(n);
  const fmtCrypto = (n: number) => {
    const sym = selectedCrypto;
    const dp =
      sym === "BTC" ? 8 :
      sym === "ETH" ? 6 :
      sym === "SOL" ? 5 :
      sym === "TRX" || sym === "BNB" ? 4 :
      sym === "USDT" || sym === "USDC" ? 2 : 6;
    return n.toLocaleString("en-US", { minimumFractionDigits: dp, maximumFractionDigits: dp });
  };
  const truncateAddress = (addr: string) =>
    addr.length > 16 ? `${addr.slice(0, 8)}…${addr.slice(-8)}` : addr;

  const title =
    step === "select" ? "Select an asset" :
    step === "confirm" ? "Confirm Send" :
    `Send ${selectedCrypto}`;

  // ── Step: select ─────────────────────────────────────────────────────────────
  const selectContent = (
    <ScrollArea className="h-[400px]">
      <div className="space-y-2 pr-4">
        {wallets
          .filter((w) => w.symbol && !["success", "message", "timestamp", "status"].includes(w.symbol.toLowerCase()))
          .map((wallet) => (
            <Button
              key={wallet.symbol}
              variant="ghost"
              className="w-full h-auto py-4 px-4 justify-start hover:bg-primary/10"
              onClick={() => handleSelectCrypto(wallet.symbol)}
            >
              <div className="flex items-center gap-3 w-full">
                <CoinIcon symbol={wallet.symbol.toUpperCase()} className="w-10 h-10" />
                <div className="text-left flex-1">
                  <div className="font-semibold">{wallet.symbol}</div>
                  <div className="text-xs text-muted-foreground">{wallet.name}</div>
                </div>
              </div>
            </Button>
          ))}
      </div>
    </ScrollArea>
  );

  // ── Step: details (clean — no password, no fee) ───────────────────────────
  const detailsContent = (
    <div className="flex flex-col flex-1 min-h-0">
      <div className="overflow-y-auto flex-1 min-h-0 pr-1">
        <div className="space-y-4">

          {/* Asset selector */}
          <div>
            <Label className="text-sm font-medium mb-2 block">Asset</Label>
            <Select
              value={selectedCrypto}
              onValueChange={(value) => {
                setSelectedCrypto(value);
                const networks = networkMap[value] || [];
                setSelectedNetwork(networks[0] || "");
              }}
            >
              <SelectTrigger className="h-12 bg-muted">
                <div className="flex items-center gap-2">
                  <CoinIcon symbol={(selectedCrypto || "").toUpperCase()} className="w-6 h-6" />
                  <span>{selectedCrypto}</span>
                </div>
              </SelectTrigger>
              <SelectContent>
                {wallets.map((wallet) => (
                  <SelectItem key={wallet.symbol} value={wallet.symbol}>
                    <div className="flex items-center gap-2">
                      <CoinIcon symbol={wallet.symbol.toUpperCase()} className="w-6 h-6" />
                      <span>{wallet.symbol}</span>
                    </div>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Recipient address */}
          <div>
            <Label className="text-sm font-medium mb-2 block">
              Receiver address or Pexly username
            </Label>
            <div className="relative">
              <Input
                placeholder="Enter address or username"
                value={toAddress}
                onChange={(e) => setToAddress(e.target.value)}
                className={`h-12 pr-20 bg-muted ${
                  !securityCheck.safe
                    ? "border-red-500"
                    : securityCheck.warnings.length > 0
                    ? "border-yellow-500"
                    : ""
                }`}
              />
              <div className="absolute right-12 top-2 h-8 flex items-center pr-2">
                {securityCheck.loading ? (
                  <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
                ) : toAddress.length > 30 ? (
                  securityCheck.safe ? (
                    <ShieldCheck className="h-4 w-4 text-green-500" />
                  ) : (
                    <ShieldAlert className="h-4 w-4 text-red-500" />
                  )
                ) : null}
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={handlePaste}
                className="absolute right-2 top-2 h-8"
              >
                Paste
              </Button>
            </div>
            {securityCheck.warnings.length > 0 && (
              <div className="mt-2 space-y-1">
                {securityCheck.warnings.map((warning, i) => (
                  <p key={i} className="text-xs text-red-500 flex items-center gap-1">
                    <AlertCircle className="h-3 w-3" />
                    {warning}
                  </p>
                ))}
              </div>
            )}
          </div>

          {/* Network */}
          <div>
            <Label className="text-sm font-medium mb-2 block">Network</Label>
            <Select value={selectedNetwork} onValueChange={setSelectedNetwork}>
              <SelectTrigger className="h-12 bg-muted">
                <SelectValue placeholder="Select a network" />
              </SelectTrigger>
              <SelectContent>
                {(networkMap[selectedCrypto] || []).map((network) => (
                  <SelectItem key={network} value={network}>
                    {network}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Amount */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <Label className="text-sm font-medium">Enter amount in</Label>
              <div className="flex gap-2">
                {amountInputMode === "fiat" ? (
                  <Select value={selectedCurrency} onValueChange={setSelectedCurrency}>
                    <SelectTrigger className="w-24 h-8 text-xs">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="NGN">NGN</SelectItem>
                      <SelectItem value="USD">USD</SelectItem>
                    </SelectContent>
                  </Select>
                ) : (
                  <div className="w-24 h-8 flex items-center justify-center text-xs font-medium border rounded-md px-3">
                    {selectedCrypto}
                  </div>
                )}
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    setAmountInputMode(amountInputMode === "fiat" ? "crypto" : "fiat");
                    setAmount("");
                  }}
                  className="h-8 text-xs"
                >
                  Switch
                </Button>
              </div>
            </div>
            <div className="text-center py-4">
              <Input
                type="number"
                step={amountInputMode === "crypto" ? "0.00000001" : "0.01"}
                placeholder="0.00"
                value={amount}
                onChange={(e) => setAmount(e.target.value)}
                className="text-4xl font-bold text-center border-0 bg-transparent h-auto p-0"
              />
              {amountInputMode === "fiat" && cryptoAmount && (
                <p className="text-sm text-muted-foreground mt-2">
                  ≈ {cryptoAmount} {selectedCrypto}
                </p>
              )}
              {amountInputMode === "crypto" && fiatAmount && (
                <p className="text-sm text-muted-foreground mt-2">
                  ≈ {selectedCurrency} {fiatAmount}
                </p>
              )}
              {selectedWallet && (
                <p className="text-sm text-muted-foreground mt-1">
                  Available: {selectedWallet.balance.toFixed(8)} {selectedCrypto}
                </p>
              )}
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  if (selectedWallet) {
                    if (amountInputMode === "fiat" && cryptoPrice) {
                      setAmount((selectedWallet.balance * cryptoPrice).toFixed(2));
                    } else {
                      setAmount(selectedWallet.balance.toFixed(8));
                    }
                  }
                }}
                className="mt-2"
                disabled={amountInputMode === "fiat" && !cryptoPrice}
              >
                Max
              </Button>
            </div>
          </div>

          {/* Remarks */}
          <div>
            <Label className="text-sm font-medium mb-2 block">Remarks (optional)</Label>
            <Input
              placeholder="Add a note"
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              className="h-12 bg-muted"
            />
          </div>

          {error && (
            <div className="flex items-center gap-2 text-sm text-destructive bg-destructive/10 p-3 rounded-lg">
              <AlertCircle className="h-4 w-4" />
              <span>{error}</span>
            </div>
          )}
        </div>
      </div>

      {/* Action buttons */}
      <div className="flex gap-2 pt-3 pb-1 flex-shrink-0 border-t border-border mt-2">
        <Button variant="outline" onClick={handleClose} className="flex-1 h-12">
          Cancel
        </Button>
        <Button
          onClick={() => {
            const err = validateDetails();
            if (err) { setError(err); return; }
            setError("");
            setStep("confirm");
          }}
          className="flex-1 h-12"
          disabled={!selectedCrypto || !toAddress || !amount || securityCheck.loading}
        >
          Continue
        </Button>
      </div>
    </div>
  );

  // ── Step: confirm ─────────────────────────────────────────────────────────
  const confirmContent = (
    <div className="flex flex-col flex-1 min-h-0">
      {success ? (
        <div className="flex flex-col items-center justify-center py-10 flex-1">
          <CheckCircle2 className="h-16 w-16 text-emerald-500 mb-4" />
          <h3 className="text-lg font-semibold mb-2">Transaction Initiated!</h3>
          <p className="text-sm text-muted-foreground text-center">
            Your crypto is being sent. Check your transactions for status.
          </p>
        </div>
      ) : (
        <>
          <div className="overflow-y-auto flex-1 min-h-0 space-y-4 pr-1">

            {/* Summary card */}
            <div className="rounded-xl border border-border bg-card overflow-hidden text-sm">
              {/* Header */}
              <div className="px-4 py-2.5 bg-muted/40 border-b border-border">
                <span className="text-[11px] font-semibold uppercase tracking-widest text-muted-foreground">
                  Transaction Summary
                </span>
              </div>

              <div className="divide-y divide-border">
                {/* To */}
                <div className="flex items-center justify-between px-4 py-3">
                  <span className="text-muted-foreground">To</span>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm tabular-nums">
                      {truncateAddress(toAddress)}
                    </span>
                    {securityCheck.safe ? (
                      <ShieldCheck className="h-3.5 w-3.5 text-emerald-500 flex-shrink-0" />
                    ) : (
                      <ShieldAlert className="h-3.5 w-3.5 text-red-500 flex-shrink-0" />
                    )}
                  </div>
                </div>

                {/* Network */}
                <div className="flex items-center justify-between px-4 py-3">
                  <span className="text-muted-foreground">Network</span>
                  <span className="text-right max-w-[180px] text-sm">{selectedNetwork}</span>
                </div>

                {/* You send */}
                <div className="flex items-center justify-between px-4 py-3">
                  <span className="text-muted-foreground">You send</span>
                  <div className="text-right">
                    <div className="font-semibold tabular-nums">
                      {fmtCrypto(cryptoAmountForFee)} {selectedCrypto}
                    </div>
                    {cryptoPrice > 0 && (
                      <div className="text-xs text-muted-foreground tabular-nums mt-0.5">
                        {fmt(cryptoAmountForFee * cryptoPrice)}
                      </div>
                    )}
                  </div>
                </div>

                {/* Network fee */}
                {feeLoading ? (
                  <div className="flex items-center justify-between px-4 py-3">
                    <span className="text-muted-foreground">Network fee</span>
                    <div className="flex items-center gap-1.5 text-muted-foreground text-xs">
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      Fetching…
                    </div>
                  </div>
                ) : feeData ? (
                  <div className="flex items-center justify-between px-4 py-3">
                    <div>
                      <span className="text-muted-foreground">Network fee</span>
                      {feeData.networkFeeSymbol && feeData.networkFeeSymbol !== selectedCrypto && (
                        <div className="text-[10px] text-muted-foreground/60 mt-0.5">
                          paid in {feeData.networkFeeSymbol} (gas)
                        </div>
                      )}
                    </div>
                    <div className="text-right">
                      <div className="tabular-nums">
                        {fmtCrypto(feeData.networkFee)} {feeData.networkFeeSymbol ?? selectedCrypto}
                      </div>
                      {feeData.networkFeeSymbol && feeData.networkFeeSymbol !== selectedCrypto && (
                        <div className="flex items-center justify-end">
                          <span className="flex items-center gap-1 text-[10px] text-emerald-500 mt-0.5">
                            <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse inline-block" />
                            Live
                          </span>
                        </div>
                      )}
                    </div>
                  </div>
                ) : feeError ? (
                  <div className="flex items-center gap-1.5 px-4 py-3 text-xs text-destructive">
                    <AlertCircle className="h-3.5 w-3.5 flex-shrink-0" />
                    Could not fetch live fee — check connection
                  </div>
                ) : null}

                {/* Total */}
                {feeData && (
                  <div className={`px-4 py-3.5 bg-muted/30 ${!feeSameToken ? "space-y-1" : ""}`}>
                    {feeSameToken ? (
                      <div className="flex items-center justify-between">
                        <span className="font-semibold">Total deducted</span>
                        <div className="text-right">
                          <div className="font-bold tabular-nums">
                            {fmtCrypto(total)} {selectedCrypto}
                          </div>
                          {cryptoPrice > 0 && (
                            <div className="text-xs text-muted-foreground tabular-nums mt-0.5">
                              {fmt(total * cryptoPrice)}
                            </div>
                          )}
                        </div>
                      </div>
                    ) : (
                      <>
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-xs text-muted-foreground uppercase tracking-wide">
                            Total deducted
                          </span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-sm text-muted-foreground">Token</span>
                          <span className="font-bold tabular-nums">
                            {fmtCrypto(cryptoAmountForFee)} {selectedCrypto}
                          </span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-sm text-muted-foreground">Gas</span>
                          <span className="font-semibold tabular-nums">
                            {fmtCrypto(feeData.networkFee)} {feeData.networkFeeSymbol}
                          </span>
                        </div>
                      </>
                    )}
                  </div>
                )}
              </div>
            </div>

            {/* Password — only if wallet not unlocked */}
            {!isWalletUnlocked && (
              <div className="space-y-2">
                <Label className="text-sm font-medium">Wallet password</Label>
                {rateLimit.isLocked ? (
                  <div className="flex items-center gap-2 text-sm text-destructive bg-destructive/10 p-3 rounded-lg">
                    <AlertCircle className="h-4 w-4" />
                    Too many failed attempts — try again in {rateLimit.lockoutSeconds}s
                  </div>
                ) : (
                  <Input
                    type="password"
                    placeholder="Enter your wallet password"
                    value={userPassword}
                    onChange={(e) => setUserPassword(e.target.value)}
                    className="h-12 bg-muted"
                    autoFocus
                  />
                )}
              </div>
            )}

            {isWalletUnlocked && (
              <div className="flex items-center gap-2 bg-emerald-500/10 border border-emerald-500/20 rounded-lg p-3">
                <ShieldCheck className="h-4 w-4 text-emerald-500 flex-shrink-0" />
                <p className="text-xs text-emerald-800 dark:text-emerald-200">
                  Password cached for this session.
                </p>
              </div>
            )}

            {/* Error */}
            {error && (
              <div className="flex items-center gap-2 text-sm text-destructive bg-destructive/10 p-3 rounded-lg">
                <AlertCircle className="h-4 w-4" />
                <span>{error}</span>
              </div>
            )}
          </div>

          {/* Swipe to confirm */}
          <div className="pt-3 pb-1 flex-shrink-0 space-y-3 border-t border-border mt-2">
            <SwipeConfirmButton
              onConfirm={handleSend}
              disabled={
                rateLimit.isLocked ||
                (!isWalletUnlocked && !userPassword) ||
                feeLoading
              }
              loading={loading}
              confirmed={success}
            />
            <p className="text-[11px] text-muted-foreground text-center">
              Slide the arrow all the way to authorize this transaction
            </p>
          </div>
        </>
      )}
    </div>
  );

  // ── Layout wrapper ────────────────────────────────────────────────────────
  const buildHeader = () => {
    if (step === "confirm" && !success) {
      return (
        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="icon"
            onClick={() => { setStep("details"); setError(""); }}
            className="h-8 w-8 -ml-1"
          >
            <ChevronLeft className="h-4 w-4" />
          </Button>
          <span className="font-semibold text-base">{title}</span>
        </div>
      );
    }
    return <span className="font-semibold text-base">{title}</span>;
  };

  const content = (
    <>
      {step === "select" && selectContent}
      {step === "details" && detailsContent}
      {step === "confirm" && confirmContent}
    </>
  );

  if (isMobile) {
    return (
      <Sheet open={open} onOpenChange={handleClose}>
        <SheetContent
          side="bottom"
          className="rounded-t-2xl px-4 pt-2 pb-6 max-h-[92dvh] overflow-hidden flex flex-col"
        >
          <div className="mx-auto w-10 h-1 rounded-full bg-muted-foreground/30 mb-3 flex-shrink-0" />
          <SheetHeader className="flex flex-row items-center justify-between mb-4 flex-shrink-0">
            <SheetTitle asChild>
              {buildHeader()}
            </SheetTitle>
            <Button variant="ghost" size="icon" onClick={handleClose} className="h-8 w-8">
              <X className="h-4 w-4" />
            </Button>
          </SheetHeader>
          {content}
        </SheetContent>
      </Sheet>
    );
  }

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="sm:max-w-[500px] bg-background flex flex-col max-h-[85vh]">
        <DialogHeader className="flex flex-row items-center justify-between flex-shrink-0">
          <DialogTitle asChild>
            {buildHeader()}
          </DialogTitle>
          <Button variant="ghost" size="icon" onClick={handleClose} className="h-8 w-8">
            <X className="h-4 w-4" />
          </Button>
        </DialogHeader>
        {content}
      </DialogContent>
    </Dialog>
  );
}
