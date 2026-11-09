import { Button } from "@/components/ui/button";
import { useWalletData } from "@/hooks/use-wallet-data";
import {
  Eye,
  EyeOff,
  BitcoinSmartphone,
  CreditCardChange,
  Send,
  WalletAdd,
} from '@/lib/icons';
import { useEffect, useState } from "react";
import { Skeleton } from "@/components/ui/skeleton";

interface WalletHeaderProps {
  onSend: () => void;
  onReceive: () => void;
  onSwap: () => void;
  onTopup: () => void;
}

export function WalletHeader({
  onSend,
  onReceive,
  onSwap,
  onTopup,
}: WalletHeaderProps) {
  const { data: wallet, isLoading, isError, isRefetching } = useWalletData();
  const [showBalance, setShowBalance] = useState(true);

  // Show skeleton while loading (includes live balance fetch) or converting currency.
  // Only fall back to skeleton on error when there's no cached data to show.
  const loading = isLoading || (isRefetching && !wallet) || (isError && !wallet) || wallet?.isConverting;
  const preferredCurrency = wallet?.preferredCurrency || "USD";

  const hasAssets =
    wallet?.assets?.some(asset => asset.balance > 0) ?? false;

  return (
    <div className="bg-[#eaf1e3] dark:bg-card overflow-hidden transition-colors">
      <div className="p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-4">
            <div className="flex items-center gap-2 text-muted-foreground">
              <span className="text-sm font-medium">Wallet balance</span>
              <button
                onClick={() => setShowBalance(v => !v)}
                className="hover:text-foreground transition-colors"
                aria-label={showBalance ? "Hide wallet balance" : "Show wallet balance"}
              >
                {showBalance ? (
                  <Eye className="h-4 w-4" />
                ) : (
                  <EyeOff className="h-4 w-4" />
                )}
              </button>
            </div>

            <div className="space-y-1">
              <div className="text-4xl font-bold tracking-tight text-[#091e1c] dark:text-foreground flex flex-wrap items-baseline gap-x-2">
                {loading ? (
                  <div className="flex items-center gap-2">
                    <Skeleton className="h-9 w-32" />
                    <Skeleton className="h-6 w-16" />
                  </div>
                ) : showBalance ? (
                  <>
                    <span>
                      {wallet?.totalBalance.toLocaleString(undefined, {
                        minimumFractionDigits: 2,
                        maximumFractionDigits: 2,
                      })}
                    </span>
                    <span className="text-2xl font-semibold text-muted-foreground whitespace-nowrap">
                      {preferredCurrency}
                    </span>
                  </>
                ) : (
                  <span className="tracking-widest">••••</span>
                )}
              </div>

              <div className="text-sm text-muted-foreground">
                {loading ? (
                  <Skeleton className="h-4 w-40" />
                ) : hasAssets ? (
                  <span>Portfolio value across all assets</span>
                ) : (
                  <>
                    There are no assets in your account{" "}
                    <button
                      onClick={onReceive}
                      className="text-primary font-medium hover:underline"
                    >
                      Deposit
                    </button>
                  </>
                )}
              </div>
            </div>
          </div>

          {/* ACTIONS — unchanged */}
          <div className="w-full flex justify-end">
            <div className="grid grid-cols-4 bg-background dark:bg-card rounded-lg border p-1 w-full md:hidden transition-colors">
              <Button variant="ghost" size="sm" className="h-9 flex-col gap-0 px-1" onClick={onTopup}>
                <BitcoinSmartphone className="h-4 w-4" />
                <span className="text-[10px] font-semibold mt-0.5">Top-up</span>
              </Button>
              <Button variant="ghost" size="sm" className="h-9 flex-col gap-0 px-1" onClick={onSwap}>
                <CreditCardChange className="h-4 w-4" />
                <span className="text-[10px] font-semibold mt-0.5">Swap</span>
              </Button>
              <Button variant="ghost" size="sm" className="h-9 flex-col gap-0 px-1" onClick={onSend}>
                <Send className="h-4 w-4" />
                <span className="text-[10px] font-semibold mt-0.5">Send</span>
              </Button>
              <Button variant="ghost" size="sm" className="h-9 flex-col gap-0 px-1 text-primary" onClick={onReceive}>
                <WalletAdd className="h-4 w-4" />
                <span className="text-[10px] font-semibold mt-0.5">Deposit</span>
              </Button>
            </div>

            <div className="hidden md:flex flex-row items-center gap-2 bg-background dark:bg-card rounded-lg border p-1">
              <Button variant="ghost" size="sm" className="h-9 gap-2 px-4" onClick={onTopup}>
                <BitcoinSmartphone className="h-4 w-4" />
                <span>Mobile top up</span>
              </Button>
              <Button variant="ghost" size="sm" className="h-9 gap-2 px-4" onClick={onSend}>
                <Send className="h-4 w-4" />
                <span>Send</span>
              </Button>
              <Button variant="ghost" size="sm" className="h-9 gap-2 px-4 text-primary" onClick={onReceive}>
                <WalletAdd className="h-4 w-4" />
                <span>Deposit</span>
              </Button>
              <Button variant="ghost" size="sm" className="h-9 gap-2 px-4" onClick={onSwap}>
                <CreditCardChange className="h-4 w-4" />
                <span>Swap</span>
              </Button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
