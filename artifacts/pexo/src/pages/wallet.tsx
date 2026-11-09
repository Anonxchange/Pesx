import { useHead } from "@unhead/react";
import { useState, useEffect } from "react";
import { useLocation } from "wouter";
import { useAuth } from "@/lib/auth-context";
import { SendCryptoDialog } from "@/components/send-crypto-dialog";
import { ReceiveCryptoDialog } from "@/components/receive-crypto-dialog";
import { ReceiveMethodDialog } from "@/components/receive-method-dialog";
import { type Wallet, getUserWallets } from "@/lib/wallet-api";
import { useRegisterWalletQueryClient } from "@/lib/wallet-query-cache";
import { useQueryClient } from "@tanstack/react-query";
import { walletRowsQueryOptions } from "@/lib/wallet-rows";
import { useWalletData } from "@/hooks/use-wallet-data";
import { WalletHeader } from "@/components/wallet/WalletHeader";
import { AssetList } from "@/components/wallet/AssetList";
import { WalletSetupDialog } from "@/components/wallet/WalletSetupDialog";
import { WalletPageSkeleton } from "@/components/page-skeleton";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Wallet as WalletIcon, Landmark, ChevronRight, Gift } from '@/lib/icons';

export default function WalletPage() {
  useHead({ title: "My Wallet | Pexly", meta: [{ name: "description", content: "Send, receive, swap, stake, pay bills, and manage all your crypto assets in one place." }] });
  const { user, loading } = useAuth();
  const queryClient = useQueryClient();
  useRegisterWalletQueryClient();
  const [, setLocation] = useLocation();
  const [sendDialogOpen, setSendDialogOpen] = useState(false);
  const [receiveDialogOpen, setReceiveDialogOpen] = useState(false);
  const [receiveMethodDialogOpen, setReceiveMethodDialogOpen] = useState(false);
  const { data: wallet, isLoading: isWalletLoading, isError: isWalletError, isRefetching } = useWalletData();
  const [setupDialogOpen, setSetupDialogOpen] = useState(false);
  // Address of an existing server-side wallet — when set, the dialog opens in
  // "import / sync" mode instead of "create new" mode. Prevents the dangerous
  // race condition of creating a duplicate wallet over an existing one.
  const [importExpectedAddress, setImportExpectedAddress] = useState<string | null>(null);
  // Must be declared here (before any early return) to satisfy Rules of Hooks.
  const [selectedAsset, setSelectedAsset] = useState<string | undefined>();

  // showSkeleton is true while loading (includes live balance fetch) or fetching without existing data.
  // Only show skeleton on error when there's no cached data to fall back to.
  const showSkeleton = isWalletLoading || (isRefetching && !wallet) || (isWalletError && !wallet);

  useEffect(() => {
    if (!loading && !user) {
      setLocation("/signin");
    }
  }, [user, loading, setLocation]);

  // ────────────────────────────────────────────────────────────────────────
  // Wallet existence check — race-condition safe
  // ----------------------------------------------------------------------
  // Old logic only checked the LOCAL browser cache, which was wrong:
  //   • New device / cleared cache → opens "create new" → would overwrite
  //     the user's existing server wallet, locking them out of their funds.
  //   • Slow network / transient API error → wallet feed momentarily empty
  //     → opens "create new" prematurely.
  //
  // New logic: the RPC-backed server state is the source of truth.
  //   1) Wait for the wallet feed to either succeed or stop loading entirely
  //      (no opening the dialog while still in flight or while errored).
  //   2) Query get_my_wallet through Supabase. Retry up to
  //      3 times with backoff to absorb transient network failures.
  //   3) If the server has wallets but local doesn't → open dialog in
  //      IMPORT mode with the existing address as expectedAddress.
  //   4) If neither has wallets → open dialog in CREATE mode.
  //   5) If server check itself fails after retries → do nothing
  //      (better to show empty wallet than to risk overwriting funds).
  // ────────────────────────────────────────────────────────────────────────
  useEffect(() => {
    if (!user) return;
    // Don't even consider opening the dialog while data is in flight or errored
    if (isWalletLoading || isRefetching || isWalletError) return;
    // Only proceed when wallet feed says definitively "no assets"
    if (!wallet || wallet.assets.length > 0) return;
    // Don't re-open if it's already open / dismissed
    if (setupDialogOpen) return;

    let cancelled = false;

    const checkWalletsRaceSafe = async () => {
      // The server (get_my_wallet) is the ONLY authority on whether a wallet
      // exists. Nothing is cached or registered from the browser.

      // Ask the RPC as the source of truth, with retry
      const fetchServerWallets = async (): Promise<{ ok: boolean; address: string | null }> => {
        try {
          // Deliberately a FRESH read (staleTime 0), not a cached one: a stale
          // empty result here would open the "create wallet" dialog over real
          // funds. It still goes through the shared fetcher/cache key, so the
          // result also refreshes every other consumer of the wallet rows.
          const data = await queryClient.fetchQuery({
            ...walletRowsQueryOptions(user.id),
            staleTime: 0,
            retry: false,
          });
          // Prefer the ETH wallet's address as the canonical "expected" address
          const eth = data.find((r: any) =>
            (r.chain_id || '').toLowerCase().includes('ethereum')
          );
          const first = data[0];
          return { ok: true, address: eth?.address ?? first?.address ?? null };
        } catch {
          return { ok: false, address: null };
        }
      };

      const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
      let attempt = 0;
      let serverResult: { ok: boolean; address: string | null } = { ok: false, address: null };
      while (attempt < 3) {
        if (cancelled) return;
        serverResult = await fetchServerWallets();
        if (serverResult.ok) break;
        attempt += 1;
        await sleep(500 * attempt); // 500ms, 1000ms, 1500ms backoff
      }
      if (cancelled) return;

      if (!serverResult.ok) {
        // Could not confirm server state after retries — refuse to open
        // the create dialog. Safer to leave the wallet appearing empty
        // than to risk creating a duplicate over real funds.
        return;
      }

      if (serverResult.address) {
        // Server has wallets — IDB will be populated by auth-context's
        // loadWalletsFromSupabase. Do not open the dialog.
        return;
      }

      // Genuinely no wallet anywhere — fresh creation flow
      setImportExpectedAddress(null);
      setSetupDialogOpen(true);
    };

    checkWalletsRaceSafe();
    return () => {
      cancelled = true;
    };
  }, [user, isWalletLoading, isRefetching, isWalletError, wallet, setupDialogOpen, queryClient]);

  if (!loading && !user) {
    setLocation("/signin");
    return null;
  }

  if (loading || showSkeleton) return <WalletPageSkeleton />;

  const walletsForDialog = (wallet?.assets || []).map(asset => ({
    symbol: asset.symbol,
    balance: asset.balance,
    name: asset.name,
    icon: asset.symbol
  }));

  const handleSend = (symbol?: string) => {
    setSelectedAsset(symbol);
    setSendDialogOpen(true);
  };

  const handleReceive = (symbol?: string) => {
    setSelectedAsset(symbol);
    if (symbol) {
      setReceiveDialogOpen(true);
    } else {
      setReceiveMethodDialogOpen(true);
    }
  };

  const handleSelectReceiveMethod = (method: "crypto" | "fiat") => {
    setReceiveMethodDialogOpen(false);
    if (method === "crypto") {
      setReceiveDialogOpen(true);
    } else if (method === "fiat") {
      setLocation("/buy-crypto");
    }
  };

  return (
    <div className="min-h-[100dvh] flex flex-col bg-[#f7faf1] dark:bg-background transition-colors">
      <div className="flex-1 w-full mx-auto px-0 sm:px-6 lg:px-8 py-4 sm:py-8 max-w-7xl">
        <h1 className="text-3xl font-bold mb-6 sm:mb-8 px-4 sm:px-0 text-foreground">My assets</h1>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 sm:gap-8">
          {/* Main Content */}
          <div className="lg:col-span-8 space-y-4 sm:space-y-8">
            <div className="space-y-4 sm:space-y-6">
              <div className="px-4 sm:px-0">
                <Tabs defaultValue="wallet" className="w-full">
                  <TabsList className="bg-transparent p-0 h-auto gap-1">
                    <TabsTrigger
                      value="wallet"
                      className="rounded-lg px-6 py-2 font-semibold border border-border bg-[#fffefa] text-foreground transition-colors dark:bg-muted data-[state=active]:bg-[#d8ff85] data-[state=active]:text-[#091e1c] data-[state=active]:border-[#d8ff85] dark:data-[state=active]:bg-[#d8ff85] dark:data-[state=active]:text-[#091e1c] dark:data-[state=active]:border-[#d8ff85]"
                    >
                      <WalletIcon className="h-4 w-4 mr-2" />
                      Wallet
                    </TabsTrigger>
                    <TabsTrigger
                      value="virtual-numbers"
                      onClick={() => setLocation("/wallet/virtual-numbers")}
                      className="rounded-lg px-6 py-2 font-semibold border border-border bg-[#fffefa] dark:bg-muted text-foreground/80 hover:text-foreground hover:bg-muted/80 transition-colors"
                    >
                      <Landmark className="h-4 w-4 mr-2" />
                      Virtual Numbers
                    </TabsTrigger>
                  </TabsList>
                </Tabs>
              </div>

              <Card className="border border-[#e7ede2] shadow-[0_16px_40px_rgba(19,56,43,.07)] bg-[#fffefa] dark:bg-card overflow-hidden rounded-[18px] transition-colors">
                <CardContent className="p-0">
                  <div className="divide-y divide-border">
                    <WalletHeader 
                      onSend={() => handleSend()}
                      onReceive={() => handleReceive()}
                      onSwap={() => setLocation("/swap")}
                      onTopup={() => setLocation("/wallet/mobile-topup")}
                    />
                    
                    <div className="p-6">
                      {showSkeleton ? (
                        <div className="space-y-4">
                          {[1, 2, 3, 4].map((i) => (
                            <div key={i} className="flex items-center justify-between py-4">
                              <div className="flex items-center gap-4">
                                <Skeleton className="h-10 w-10 rounded-full" />
                                <div className="space-y-2">
                                  <Skeleton className="h-5 w-32" />
                                  <Skeleton className="h-3 w-20" />
                                </div>
                              </div>
                              <div className="text-right space-y-2">
                                <Skeleton className="h-5 w-24 ml-auto" />
                                <Skeleton className="h-3 w-16 ml-auto" />
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <AssetList 
                          onSend={handleSend}
                          onReceive={handleReceive}
                          onSwap={(symbol) => setLocation(symbol ? `/swap?symbol=${symbol}` : "/swap")}
                        />
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>

          {/* Sidebar */}
          <div className="lg:col-span-4 space-y-6 px-4 sm:px-0">
            <Card className="border border-[#e7ede2] shadow-[0_12px_32px_rgba(19,56,43,.06)] bg-[#fffefa] dark:bg-card overflow-hidden rounded-[16px]">
              <CardContent className="p-0">
                  <div className="p-4 flex items-center justify-between border-b border-[#e7ede2] cursor-pointer hover:bg-[#f0f7e4] transition-colors">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-sm">Trading limits</span>
                    <Badge className="bg-orange-100 text-orange-600 hover:bg-orange-100 border-none text-[10px] font-bold px-1.5 h-5 uppercase">Level 3</Badge>
                    <span className="text-[#66864d] text-[10px] font-bold hover:underline ml-1">Learn more</span>
                  </div>
                  <ChevronRight className="h-4 w-4 text-muted-foreground" />
                </div>
              </CardContent>
            </Card>

            <div className="relative rounded-[18px] overflow-hidden bg-[#183f36] aspect-[4/3] flex flex-col p-6 text-[#f7faf1] group cursor-pointer shadow-[0_20px_55px_rgba(9,30,28,.15)]">
               <div className="relative z-10 space-y-4">
                  <h3 className="text-2xl font-bold leading-tight max-w-[180px]">
                    Save up to 20% on gift cards
                  </h3>
                   <p className="text-sm text-[#c2d0c6] max-w-[200px]">
                    Exclusive discounts on the gift cards you love—shop now and save more!
                  </p>
                   <Button className="w-fit bg-[#d8ff85] text-[#091e1c] hover:bg-[#c9f16f] font-bold rounded-lg px-4 h-9">
                    <Gift className="h-4 w-4 mr-2" />
                    Buy a gift card
                  </Button>
               </div>
               
               {/* Visual elements representing gift cards */}
               <div className="absolute top-8 right-[-20px] w-48 h-64 transition-transform duration-500 group-hover:translate-x-[-10px]">
                 {/* This would be the stack of cards image from the screenshot */}
                  <div className="absolute top-0 right-0 w-32 h-20 bg-[#202020] rounded-lg shadow-xl transform rotate-[-5deg] flex items-center justify-center border border-white/10">
                   <span className="text-xs font-bold">amazon</span>
                 </div>
                  <div className="absolute top-10 right-4 w-32 h-20 bg-[#d8ff85] text-[#091e1c] rounded-lg shadow-xl transform rotate-[5deg] flex items-center justify-center border border-white/10">
                   <span className="text-xs font-bold">Steam</span>
                 </div>
                  <div className="absolute top-20 right-2 w-32 h-20 bg-[#f0f7e4] text-[#091e1c] rounded-lg shadow-xl transform rotate-[-2deg] flex items-center justify-center border border-white/10">
                   <span className="text-xs font-bold">Razer</span>
                 </div>
               </div>
            </div>
          </div>
        </div>
      </div>

      <SendCryptoDialog
        open={sendDialogOpen}
        onOpenChange={setSendDialogOpen}
        wallets={walletsForDialog}
        initialSymbol={selectedAsset}
        onSuccess={() => {}}
      />

      <ReceiveCryptoDialog
        open={receiveDialogOpen}
        onOpenChange={setReceiveDialogOpen}
        wallets={walletsForDialog}
        initialSymbol={selectedAsset}
      />

      <ReceiveMethodDialog
        open={receiveMethodDialogOpen}
        onOpenChange={setReceiveMethodDialogOpen}
        onSelectMethod={handleSelectReceiveMethod}
      />

      {user && (
        <WalletSetupDialog
          open={setupDialogOpen}
          onOpenChange={setSetupDialogOpen}
          userId={user.id}
          expectedAddress={importExpectedAddress}
          onSuccess={() => {}}
        />
      )}
    </div>
  );
}
