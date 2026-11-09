import { queryOptions } from "@tanstack/react-query";
import { getSupabase } from "@/lib/supabase";
import { getMyPublicWalletRows } from "@/lib/non-custodial-wallet";

/**
 * Public, non-secret view of a `get_my_wallet` row.
 *
 * The fetcher below copies ONLY these fields out of the server response, so
 * encrypted_private_key / encrypted_mnemonic can never end up in the React
 * Query cache, devtools, or a log line by way of this query.
 */
export interface WalletRow {
  id: string;
  chain_id: string;
  address: string;
  wallet_type?: string | null;
  is_active?: boolean | string | null;
  is_backed_up?: boolean | string | null;
  created_at?: string | null;
}

export const walletRowsQueryKey = (userId: string | undefined) =>
  ["wallet-rows", userId] as const;

const WALLET_ROWS_TIMEOUT_MS = 15_000;

/** A row is active unless the server explicitly says otherwise. */
export function isActiveRow(row: Pick<WalletRow, "is_active">): boolean {
  return row.is_active !== false && row.is_active !== "false";
}

function toPublicRow(raw: any): WalletRow {
  return {
    id: String(raw?.id ?? ""),
    chain_id: String(raw?.chain_id ?? raw?.chainId ?? "").trim(),
    address: String(raw?.address ?? "").trim(),
    wallet_type: raw?.wallet_type ?? null,
    is_active: raw?.is_active,
    is_backed_up: raw?.is_backed_up ?? null,
    created_at: raw?.created_at ?? null,
  };
}

async function loadRows(userId: string): Promise<WalletRow[]> {
  const supabase = await getSupabase();
  // Public-only RPC: encrypted vaults never enter the public wallet-UI path.
  const rows = await getMyPublicWalletRows(supabase, userId);
  return (Array.isArray(rows) ? rows : []).map(toPublicRow);
}

/**
 * The ONLY place wallet rows are read from the server. Never touches balances.
 * Times out so a hung request becomes an error (and a retry button) instead of
 * an endless spinner.
 */
export async function fetchWalletRows(userId: string): Promise<WalletRow[]> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error("WALLET_ROWS_TIMEOUT")), WALLET_ROWS_TIMEOUT_MS);
  });
  try {
    return await Promise.race([loadRows(userId), timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/**
 * Shared query options. Use with `useQuery` (via useWalletRows) or with
 * `queryClient.fetchQuery(...)` from non-React code so every consumer hits
 * the same cache entry and in-flight request.
 */
export function walletRowsQueryOptions(userId: string | undefined) {
  return queryOptions({
    queryKey: walletRowsQueryKey(userId),
    queryFn: () => (userId ? fetchWalletRows(userId) : Promise.resolve<WalletRow[]>([])),
    staleTime: 60_000,
    retry: 2,
    refetchOnWindowFocus: true,
    refetchOnReconnect: true,
  });
}
