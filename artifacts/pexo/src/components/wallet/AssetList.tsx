import { useEffect, useMemo, useState } from "react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useWalletData } from "@/hooks/use-wallet-data";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { MoreHorizontal, ArrowDownToLine, Send, RefreshCw } from '@/lib/icons';
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Drawer,
  DrawerTrigger,
  DrawerContent,
  DrawerHeader,
  DrawerTitle,
} from "@/components/ui/drawer";

import { CoinIcon } from "@/components/trading/CoinIcon";
import { RecentActivity } from "./RecentActivity";

interface ActionMenuProps {
  symbol: string;
  onSend?: (symbol: string) => void;
  onReceive?: (symbol: string) => void;
  onSwap?: (symbol: string) => void;
  isMobile?: boolean;
}

const ActionMenu = ({
  symbol,
  onSend,
  onReceive,
  onSwap,
  isMobile,
}: ActionMenuProps) => {
  const stop = (e: React.MouseEvent) => e.stopPropagation();

  if (isMobile) {
    return (
      <Drawer>
        <DrawerTrigger asChild onClick={stop}>
          <Button variant="ghost" size="icon" className="h-8 w-8">
            <MoreHorizontal className="h-4 w-4" />
          </Button>
        </DrawerTrigger>
        <DrawerContent className="pb-8">
          <DrawerHeader className="border-b">
            <DrawerTitle>Select an action</DrawerTitle>
          </DrawerHeader>
          <div className="p-4 space-y-3">
            <Button variant="outline" className="h-14" onClick={() => onReceive?.(symbol)}>
              <ArrowDownToLine className="mr-3 h-5 w-5" /> Deposit
            </Button>
            <Button variant="outline" className="h-14" onClick={() => onSend?.(symbol)}>
              <Send className="mr-3 h-5 w-5" /> Send
            </Button>
            <Button variant="outline" className="h-14" onClick={() => onSwap?.(symbol)}>
              <RefreshCw className="mr-3 h-5 w-5" /> Swap
            </Button>
          </div>
        </DrawerContent>
      </Drawer>
    );
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild onClick={stop}>
        <Button variant="ghost" size="icon" className="h-8 w-8">
          <MoreHorizontal className="h-4 w-4" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem onClick={() => onReceive?.(symbol)}>Deposit</DropdownMenuItem>
        <DropdownMenuItem onClick={() => onSend?.(symbol)}>Send</DropdownMenuItem>
        <DropdownMenuItem onClick={() => onSwap?.(symbol)}>Swap</DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
};

export function AssetList({
  onSend,
  onReceive,
  onSwap,
}: {
  onSend?: (symbol: string) => void;
  onReceive?: (symbol?: string) => void;
  onSwap?: (symbol: string) => void;
}) {
  const { data: wallet, isLoading, isError, isRefetching } = useWalletData();
  const [hideZero, setHideZero] = useState(false);
  const [activeTab, setActiveTab] = useState(() => {
    if (typeof window === "undefined") return "assets";
    const tab = new URLSearchParams(window.location.search).get("tab");
    return tab === "activity" || tab === "operations" ? tab : "assets";
  });

  // Show skeleton while loading (includes live balance fetch) or converting currency.
  // Only fall back to skeleton on error when there's no cached data to show.
  const loading = isLoading || (isRefetching && !wallet) || (isError && !wallet) || (wallet && 'isConverting' in (wallet as any) && (wallet as any).isConverting);
  const preferredCurrency = (wallet as any)?.preferredCurrency || "USD";

  const assets = useMemo(() => {
    if (!wallet?.assets) return [];
    return hideZero
      ? wallet.assets.filter(a => a.balance > 0)
      : wallet.assets;
  }, [wallet?.assets, hideZero]);

  return (
    <div className="space-y-6">
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="gap-8">
          <TabsTrigger value="assets">Wallet assets</TabsTrigger>
          <TabsTrigger value="activity">Recent activity</TabsTrigger>
          <TabsTrigger value="operations">All operations</TabsTrigger>
        </TabsList>
      </Tabs>

      {activeTab === "assets" && (
        <>
          <div className="flex items-center gap-2">
            <Checkbox
              id="hide-zero"
              checked={hideZero}
              onCheckedChange={v => setHideZero(!!v)}
            />
            <Label htmlFor="hide-zero">Hide 0 balance</Label>
          </div>

          <div className="rounded-lg border overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Asset</TableHead>
                  <TableHead className="hidden sm:table-cell">Price</TableHead>
                  <TableHead>Balance</TableHead>
                  <TableHead className="text-right">Action</TableHead>
                </TableRow>
              </TableHeader>

              <TableBody>
                {loading ? (
                  Array.from({ length: 5 }).map((_, i) => (
                    <TableRow key={i}>
                      <TableCell><Skeleton className="h-6 w-24" /></TableCell>
                      <TableCell className="hidden sm:table-cell"><Skeleton className="h-6 w-24" /></TableCell>
                      <TableCell><Skeleton className="h-6 w-24" /></TableCell>
                      <TableCell><Skeleton className="h-6 w-6 ml-auto" /></TableCell>
                    </TableRow>
                  ))
                ) : assets.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={4} className="text-center">
                      No assets found
                    </TableCell>
                  </TableRow>
                ) : (
                  assets.map(asset => {
                    return (
                      <TableRow key={asset.symbol}>
                        <TableCell>
                          <div className="flex items-center gap-3">
                            <CoinIcon
                              symbol={asset.symbol.toUpperCase()}
                              className="h-8 w-8"
                            />
                            <span className="font-semibold">{asset.name}</span>
                          </div>
                        </TableCell>

                        <TableCell className="hidden sm:table-cell">
                          <div className="font-semibold">
                            {asset.price.toLocaleString()} {preferredCurrency}
                          </div>
                          <div
                            className={`text-xs font-bold ${
                              asset.change24h >= 0 ? "text-green-500" : "text-red-500"
                            }`}
                          >
                            {asset.change24h >= 0 ? "+" : ""}
                            {asset.change24h.toFixed(2)}%
                          </div>
                        </TableCell>

                        <TableCell>
                          <div className="font-bold">
                            {asset.balance.toLocaleString(undefined, { maximumFractionDigits: 8 })}
                          </div>
                          <div className="text-xs text-muted-foreground">
                            {asset.value.toLocaleString(undefined, {
                              minimumFractionDigits: 2,
                              maximumFractionDigits: 2,
                            })}{" "}
                            {preferredCurrency}
                          </div>
                        </TableCell>

                        <TableCell className="text-right">
                          <ActionMenu
                            symbol={asset.symbol}
                            onSend={onSend}
                            onReceive={onReceive}
                            onSwap={onSwap}
                          />
                        </TableCell>
                      </TableRow>
                    );
                  })
                )}
              </TableBody>
            </Table>
          </div>
        </>
      )}

      {(activeTab === "activity" || activeTab === "operations") && (
        <RecentActivity type={activeTab as any} onDeposit={onReceive} />
      )}
    </div>
  );
}
