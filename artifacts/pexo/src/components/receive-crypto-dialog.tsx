import { useState, useEffect, useMemo } from "react";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Copy, X, Info } from '@/lib/icons';
import { useAuth } from "@/lib/auth-context";
import { useToast } from "@/hooks/use-toast";
import { QRCodeCanvas } from "qrcode.react";
import { CoinIcon } from "@/components/trading/CoinIcon";
import { cryptoIconUrls } from "@/lib/crypto-icons";
import { useIsMobile } from "@/hooks/use-mobile";
import { useWalletRows } from "@/hooks/use-wallet-rows";
import { isActiveRow } from "@/lib/wallet-rows";
import { findWalletForNetwork } from "@/lib/wallet-address-match";

interface ReceiveCryptoDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  wallets: Array<{ symbol: string; balance: number; name: string; icon: string }>;
  initialSymbol?: string;
}

export function ReceiveCryptoDialog({ open, onOpenChange, wallets, initialSymbol }: ReceiveCryptoDialogProps) {
  const { user } = useAuth();
  const { toast } = useToast();
  const isMobile = useIsMobile();
  const [selectedCrypto, setSelectedCrypto] = useState<string>("");
  const [selectedNetwork, setSelectedNetwork] = useState<string>("");

  const networkMap: Record<string, string[]> = {
    BTC: ["Bitcoin (SegWit)"],
    ETH: ["Ethereum (ERC-20)"],
    SOL: ["Solana"],
    BNB: ["Binance Smart Chain (BEP-20)"],
    TRX: ["Tron (TRC-20)"],
    MATIC: ["Polygon"],
    OP: ["Optimism"],
    ARB: ["Arbitrum"],
    XRP: ["Ripple"],
    AVAX: ["Avalanche (C-Chain)"],
    USDC: ["Ethereum (ERC-20)", "Binance Smart Chain (BEP-20)", "Tron (TRC-20)", "Solana (SPL)", "Polygon", "Optimism", "Arbitrum"],
    USDT: ["Ethereum (ERC-20)", "Binance Smart Chain (BEP-20)", "Tron (TRC-20)", "Solana (SPL)", "Polygon", "Optimism", "Arbitrum"],
  };

  const ASSET_NAMES: Record<string, string> = {
    BTC: "Bitcoin",
    ETH: "Ethereum",
    USDT: "Tether",
    USDC: "USD Coin",
    BNB: "BNB",
    SOL: "Solana",
    TRX: "Tron",
    MATIC: "Polygon",
    OP: "Optimism",
    ARB: "Arbitrum",
    XRP: "Ripple",
    AVAX: "Avalanche",
  };

  const handleClose = () => onOpenChange(false);

  const handleCopyAddress = () => {
    if (!walletAddress) return;
    navigator.clipboard
      .writeText(walletAddress)
      .then(() => toast({ title: "Copied", description: "Wallet address copied to clipboard" }))
      .catch(() => toast({ title: "Copy failed", description: "Select the address and copy it manually" }));
  };

  // ── Address resolution ────────────────────────────────────────────────
  // Server rows (shared, deduplicated query) are the ONLY source; there is no
  // local copy. The address is DERIVED from the current selection, so it can
  // never show a previous asset's address.
  const userId = user?.id;
  const selectionReady = open && !!userId && !!selectedCrypto && !!selectedNetwork;
  const rowsQuery = useWalletRows(open ? userId : undefined);

  const serverMatch = useMemo(() => {
    if (!selectionReady || !rowsQuery.data) return null;
    const rows = rowsQuery.data
      .filter(isActiveRow)
      .map((r) => ({ chainId: r.chain_id, address: r.address }));
    return findWalletForNetwork(rows, selectedCrypto, selectedNetwork);
  }, [selectionReady, rowsQuery.data, selectedCrypto, selectedNetwork]);

  const serverSettled = !rowsQuery.isFetching && (rowsQuery.isSuccess || rowsQuery.isError);

  let addressStatus: "idle" | "loading" | "ready" | "error";
  let walletAddress = "";
  if (!selectionReady) {
    addressStatus = "idle";
  } else if (serverMatch) {
    addressStatus = "ready";
    walletAddress = serverMatch.address.trim();
  } else if (!serverSettled) {
    addressStatus = "loading";
  } else {
    addressStatus = "error";
  }

  const addressError = rowsQuery.isError
    ? "We couldn't load your wallet address. Check your connection and try again."
    : "No deposit address is available for this network yet. Try again, or pick a different network.";

  const handleRetry = () => {
    void rowsQuery.refetch();
  };

  const handleAssetChange = (value: string) => {
    setSelectedCrypto(value);
    const networks = networkMap[value] || ["Mainnet"];
    setSelectedNetwork(networks[0]);
  };

  useEffect(() => {
    if (open) handleAssetChange(initialSymbol || "BTC");
  }, [open, initialSymbol]);

  const title = `Receive ${ASSET_NAMES[selectedCrypto] || selectedCrypto}`;

  const content = (
    <div className="space-y-5 pb-2">
      {/* Asset */}
      <div className="space-y-1.5">
        <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Asset</label>
        <Select value={selectedCrypto} onValueChange={handleAssetChange}>
          <SelectTrigger className="h-11 bg-muted/30 border-border/50 focus:ring-0 rounded-lg">
            <SelectValue>
              <div className="flex items-center gap-2">
                <CoinIcon symbol={selectedCrypto.toUpperCase()} className="w-5 h-5" />
                <span className="font-bold text-sm">{ASSET_NAMES[selectedCrypto] || selectedCrypto}</span>
              </div>
            </SelectValue>
          </SelectTrigger>
          <SelectContent className="rounded-lg max-h-[250px] bg-popover border-border" position="popper" sideOffset={4}>
            <ScrollArea className="h-full w-full">
              {Object.entries(ASSET_NAMES).map(([symbol, name]) => (
                <SelectItem key={symbol} value={symbol} className="rounded-md cursor-pointer hover:bg-accent">
                  <div className="flex items-center gap-2 py-1">
                    <CoinIcon symbol={symbol.toUpperCase()} className="w-5 h-5" />
                    <span className="font-bold text-sm">{name}</span>
                  </div>
                </SelectItem>
              ))}
            </ScrollArea>
          </SelectContent>
        </Select>
      </div>

      {/* Network */}
      <div className="space-y-1.5">
        <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Network</label>
        <Select value={selectedNetwork} onValueChange={setSelectedNetwork}>
          <SelectTrigger className="h-11 bg-muted/30 border-border/50 focus:ring-0 rounded-lg">
            <SelectValue placeholder="Select a network" />
          </SelectTrigger>
          <SelectContent className="rounded-lg bg-popover border-border" position="popper" sideOffset={4}>
            {(networkMap[selectedCrypto] || ["Mainnet"]).map((network) => (
              <SelectItem key={network} value={network} className="rounded-md hover:bg-accent">
                <span className="font-medium text-sm">{network}</span>
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* QR + Address */}
      <div className="space-y-3">
        <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Deposit address</label>

        <div className="flex flex-col items-center gap-4">
          <div className="bg-white p-3 rounded-xl shadow-sm border border-border/10">
            {addressStatus === "ready" ? (
              <QRCodeCanvas
                value={walletAddress}
                size={148}
                level="M"
                includeMargin={false}
                imageSettings={{
                  src: cryptoIconUrls[selectedCrypto],
                  height: 30,
                  width: 30,
                  excavate: true,
                }}
              />
            ) : (
              <div
                className={`w-[148px] h-[148px] rounded-md bg-muted/40 ${addressStatus === "loading" ? "animate-pulse" : ""}`}
                aria-hidden="true"
              />
            )}
          </div>

          <div className="w-full space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold">
                {ASSET_NAMES[selectedCrypto] || selectedCrypto} #1 ({selectedNetwork?.split(' ')[0] || selectedCrypto})
              </span>
              <Button
                variant="ghost"
                size="icon"
                onClick={handleCopyAddress}
                disabled={!walletAddress}
                className="h-7 w-7 text-muted-foreground hover:text-foreground"
              >
                <Copy className="h-3.5 w-3.5" />
              </Button>
            </div>
            {addressStatus === "error" ? (
              <div
                role="alert"
                className="p-3 rounded-lg border border-destructive/40 bg-destructive/5 space-y-2"
              >
                <p className="text-xs text-destructive leading-snug">{addressError}</p>
                <Button variant="outline" size="sm" className="h-8 text-xs" onClick={handleRetry}>
                  Retry
                </Button>
              </div>
            ) : (
              <div
                className="p-3 bg-muted/30 rounded-lg break-all text-sm font-mono leading-relaxed tracking-tight border border-border/50 shadow-inner cursor-pointer select-all"
                onClick={handleCopyAddress}
              >
                {walletAddress || "Loading address…"}
              </div>
            )}
          </div>
        </div>

        <Button
          variant="outline"
          className="w-full h-10 rounded-lg text-muted-foreground/60 font-bold bg-muted/10 text-xs"
          disabled
        >
          Deposit to your wallet
        </Button>

        <p className="text-[10px] text-destructive/80 text-center leading-tight px-4 font-medium">
          Only send this exact asset to this address.
          Sending any other asset will result in permanent loss.
        </p>
      </div>
    </div>
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
            <SheetTitle>{title}</SheetTitle>
            <Button variant="ghost" size="icon" onClick={handleClose} className="h-8 w-8">
              <X className="h-4 w-4" />
            </Button>
          </SheetHeader>
          <div className="flex-1 overflow-y-auto pr-1">
            {content}
          </div>
        </SheetContent>
      </Sheet>
    );
  }

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="sm:max-w-[420px] p-0 bg-background border border-border shadow-lg gap-0 overflow-hidden">
        <DialogHeader className="p-4 flex flex-row items-center justify-between border-b border-border/50">
          <DialogTitle className="text-base font-bold">{title}</DialogTitle>
          <Button
            variant="ghost"
            size="icon"
            onClick={handleClose}
            className="h-7 w-7 rounded-full text-muted-foreground hover:text-foreground"
          >
            <X className="h-4 w-4" />
          </Button>
        </DialogHeader>
        <div className="p-4 overflow-y-auto max-h-[80vh]">
          {content}
        </div>
      </DialogContent>
    </Dialog>
  );
}
