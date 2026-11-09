import { devLog } from "./dev-logger";
import {
  callSigningWorker,
  createSecureWallet,
  getMnemonicForBackup,
} from "@/hooks/use-signing-worker";
import type { EncryptedVault, SecureWalletResult } from "@/hooks/use-signing-worker";
import { runWithUnlockGate } from "./security/wallet-unlock-gate";
import type { SupabaseClient } from "@supabase/supabase-js";

// NOTE: this file no longer touches mnemonics, seeds, HDKeys, or raw private
// key bytes on the main thread. All of that — mnemonic generation, per-chain
// key derivation (EVM/BTC/SOL/TRX/XRP), and vault encryption — now happens
// exclusively inside signing.worker.ts via createSecureWallet(). This file
// only ever sees addresses and EncryptedVault blobs, both safe to hold on
// the main thread and to persist to storage/Supabase as-is.
//
// Previously this file also imported per-chain signer modules
// (evmSigner/bitcoinSigner/solanaSigner/tronSigner) and duplicated XRP/base58
// address encoding locally so it could derive keys on the main thread. Those
// are gone now that the worker is the single source of truth for wallet
// generation — see createSecureWallet() / generateNonCustodialWallets() below.

export interface NonCustodialWallet {
  id: string;
  chainId: string;
  address: string;
  walletType: string;
  encryptedPrivateKey: string | EncryptedVault;
  encryptedMnemonic?: string | EncryptedVault;
  createdAt: string;
  isActive: boolean;
  isBackedUp: boolean;
  assetType?: string;
  baseChainWalletId?: string;
  balance?: number;
}


/**
 * Normalises a vault field that may arrive from the DB as a JSON string.
 *
 * Supabase can return `encrypted_private_key` / `encrypted_mnemonic` as a plain
 * string when the column type is `text`, or when an older code path stored the
 * object via JSON.stringify. This helper tries to parse the string into an
 * EncryptedVault object so the rest of the decryption pipeline works correctly.
 *
 * If the value is already an object (jsonb column), it is returned as-is.
 * If the value is null/undefined, it is returned unchanged.
 */
function parseVaultField(value: any): any {
  if (!value || typeof value !== "string") return value;
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

/**
 * Returns true if a stored vault value is in the legacy string format
 * (deterministic salt — a cryptographic weakness). Modern vaults are
 * EncryptedVault objects; legacy ones are a raw base64 string.
 */
function isLegacyVault(vault: string | EncryptedVault | undefined): boolean {
  return typeof vault === "string";
}

export type WalletRpcRow = {
  id: string;
  chain_id: string;
  address: string;
  wallet_type: string;
  encrypted_private_key: string;
  encrypted_mnemonic: string | null;
  is_active: string | boolean;
  is_backed_up: string | boolean;
  created_at: string;
};

// In-flight wallet operations, keyed by userId so one user's promise can never
// be handed to another user, and load/create are serialized PER USER only.
const walletOps = new Map<string, Promise<NonCustodialWallet[]>>();
// Bumped on sign-out / account switch. Operations started before a bump must
// not write to the cache or return results afterwards.
let walletEpoch = 0;

function assertSameEpoch(epoch: number): void {
  if (epoch !== walletEpoch) throw new Error("WALLET_SESSION_CHANGED");
}

async function resolveUserId(supabase: SupabaseClient, expectedUserId?: string): Promise<string> {
  if (expectedUserId) return expectedUserId;
  const { data, error } = await supabase.auth.getUser();
  if (error) throw error;
  if (!data.user) throw new Error("AUTH_REQUIRED");
  return data.user.id;
}

function asBoolean(value: string | boolean | null | undefined): boolean {
  return value === true || value === "true";
}

function mapWalletRpcRow(row: WalletRpcRow): NonCustodialWallet {
  return {
    id: row.id,
    chainId: row.chain_id,
    address: row.address,
    walletType: row.wallet_type,
    encryptedPrivateKey: parseVaultField(row.encrypted_private_key),
    encryptedMnemonic: parseVaultField(row.encrypted_mnemonic),
    createdAt: row.created_at,
    isActive: asBoolean(row.is_active),
    isBackedUp: asBoolean(row.is_backed_up),
  };
}

/**
 * The only frontend read path for public.user_wallets.
 *
 * The RPC derives ownership from auth.uid(). The frontend deliberately does
 * not send user_id and never falls back to a direct table query.
 */
export async function getMyWalletRows(
  supabase: SupabaseClient,
  expectedUserId?: string,
): Promise<WalletRpcRow[]> {
  const {
    data: { user },
    error: userError,
  } = await supabase.auth.getUser();

  if (userError) throw userError;
  if (!user) throw new Error("AUTH_REQUIRED");
  if (expectedUserId && expectedUserId !== user.id) {
    throw new Error("AUTH_USER_MISMATCH");
  }

  const { data, error } = await supabase.rpc("get_my_wallet");
  if (error) throw error;
  return Array.isArray(data) ? (data as WalletRpcRow[]) : [];
}

/** Public wallet metadata only: no encrypted vault fields exist on this shape. */
export interface WalletPublicRpcRow {
  id: string;
  chain_id: string;
  address: string;
  wallet_type?: string | null;
  is_active?: string | boolean | null;
  is_backed_up?: string | boolean | null;
  created_at?: string | null;
}

/**
 * Reads the account's PUBLIC wallet rows through get_my_wallet_public, which
 * never returns encrypted_private_key / encrypted_mnemonic. Public UI (receive
 * addresses, balances, monitoring) must use this, so vault ciphertext never
 * reaches the main thread for those flows. Vaults are fetched only by the
 * explicit secure flows via getMyWalletRows (sign, reveal phrase, unlock).
 *
 * If the RPC has not been deployed yet, falls back to get_my_wallet and
 * strips to public fields, so shipping the client first does not break the
 * app. Remove the fallback once the migration is live.
 */
export async function getMyPublicWalletRows(
  supabase: SupabaseClient,
  expectedUserId?: string,
): Promise<WalletPublicRpcRow[]> {
  const {
    data: { user },
    error: userError,
  } = await supabase.auth.getUser();
  if (userError) throw userError;
  if (!user) throw new Error("AUTH_REQUIRED");
  if (expectedUserId && expectedUserId !== user.id) {
    throw new Error("AUTH_USER_MISMATCH");
  }

  const { data, error } = await supabase.rpc("get_my_wallet_public");
  if (!error) return Array.isArray(data) ? (data as WalletPublicRpcRow[]) : [];

  // 42883 = undefined_function, PGRST202 = function not found in schema cache.
  if (error.code === "42883" || error.code === "PGRST202") {
    const full = await getMyWalletRows(supabase, expectedUserId);
    return full.map((r) => ({
      id: r.id,
      chain_id: r.chain_id,
      address: r.address,
      wallet_type: (r as any).wallet_type ?? null,
      is_active: r.is_active,
      is_backed_up: (r as any).is_backed_up ?? null,
      created_at: (r as any).created_at ?? null,
    }));
  }
  throw error;
}

/**
 * Loads the authenticated user's canonical wallet rows and caches the
 * encrypted blobs. Nothing is written to browser storage.
 *
 * Deduplicated and serialized PER USER: concurrent callers for the same user
 * share one request; different users never share state.
 */
export async function loadMyWallets(
  supabase: SupabaseClient,
  expectedUserId?: string,
): Promise<NonCustodialWallet[]> {
  const userId = await resolveUserId(supabase, expectedUserId);
  const inflight = walletOps.get(userId);
  if (inflight) return inflight;

  const epoch = walletEpoch;
  const operation = (async () => {
    const rows = await getMyWalletRows(supabase, userId);
    assertSameEpoch(epoch);
    const wallets = rows.map(mapWalletRpcRow);
    assertSameEpoch(epoch);
    return wallets;
  })();

  walletOps.set(userId, operation);
  try {
    return await operation;
  } finally {
    if (walletOps.get(userId) === operation) walletOps.delete(userId);
  }
}

/**
 * Persists a newly generated wallet set through the RPC, then reloads the
 * database response as the only canonical frontend state.
 *
 * Waits for any in-flight operation FOR THIS USER, then runs its own create.
 * The existing-rows check keeps it idempotent. Callers must pass freshly
 * generated wallets, never wallets rebuilt from the local browser cache.
 */
export async function createMyWallets(
  supabase: SupabaseClient,
  wallets: NonCustodialWallet[],
  expectedUserId: string,
): Promise<NonCustodialWallet[]> {
  let inflight: Promise<NonCustodialWallet[]> | undefined;
  while ((inflight = walletOps.get(expectedUserId))) {
    try {
      await inflight;
    } catch {
      // The other operation's failure is not ours; proceed with our create.
    }
  }

  const epoch = walletEpoch;
  const operation = (async () => {
    const existing = await getMyWalletRows(supabase, expectedUserId);
    assertSameEpoch(epoch);
    if (existing.length > 0) {
      const canonical = existing.map(mapWalletRpcRow);
      return canonical;
    }

    if (!wallets.length) throw new Error("WALLET_DATA_REQUIRED");

    const serialize = (value: string | EncryptedVault | undefined) =>
      value === undefined ? null : typeof value === "string" ? value : JSON.stringify(value);

    const payload = wallets.map((wallet) => ({
      id: wallet.id,
      chain_id: wallet.chainId,
      address: wallet.address,
      wallet_type: wallet.walletType,
      encrypted_private_key: serialize(wallet.encryptedPrivateKey),
      encrypted_mnemonic: serialize(wallet.encryptedMnemonic),
      is_active: wallet.isActive ? "true" : "false",
      is_backed_up: wallet.isBackedUp ? "true" : "false",
    }));

    const { error: createError } = await supabase.rpc("create_my_wallets", {
      wallets: payload,
    });
    if (createError) throw createError;

    const savedRows = await getMyWalletRows(supabase, expectedUserId);
    assertSameEpoch(epoch);
    if (savedRows.length === 0) throw new Error("WALLET_CREATE_EMPTY");

    const canonical = savedRows.map(mapWalletRpcRow);
    return canonical;
  })();

  walletOps.set(expectedUserId, operation);
  try {
    return await operation;
  } finally {
    if (walletOps.get(expectedUserId) === operation) walletOps.delete(expectedUserId);
  }
}

/**
 * Clears in-memory coordination state on sign-out / account switch and
 * invalidates every operation still in flight (they will not cache or return).
 * Pass a userId to drop only that user's entry; omit to drop all.
 */
export function clearWalletStateFromMemory(userId?: string): void {
  walletEpoch += 1;
  if (userId) walletOps.delete(userId);
  else walletOps.clear();
}

class NonCustodialWalletManager {
  /**
   * Generates a full wallet set (EVM + Bitcoin + Solana + Tron + XRP) with a
   * single call into the signing worker.
   *
   * Replaces the old per-chain, main-thread `generateNonCustodialWallet`.
   * That method generated the mnemonic, derived each chain's HDKey, and hex-
   * encoded each private key on the MAIN THREAD before handing the data off
   * to be encrypted — meaning the mnemonic and every private key briefly
   * existed as unzeroable JS strings/heap objects outside the worker.
   *
   * Now: `createSecureWallet()` runs entirely inside signing.worker.ts. It
   * generates (or reuses `existingMnemonic`), derives all five chains' keys,
   * encrypts all six vaults (5 keys + the mnemonic) with a single scrypt
   * round, and returns only `{ addresses, encryptedVaults }` — the mnemonic
   * and every raw private key are wiped inside the worker and never appear
   * in the postMessage response. This file never sees them.
   *
   * To show the one-time seed-phrase backup screen, call
   * `getWalletMnemonicForBackup()` separately with the returned mnemonic
   * vault — that is the only controlled point where the mnemonic crosses
   * back to the main thread, exactly as documented in signing.worker.ts.
   */
  async generateNonCustodialWallets(
    userPassword: string,
    supabase?: any,
    userId?: string,
    existingMnemonic?: string,
    options?: { persist?: boolean },
  ): Promise<{ wallets: NonCustodialWallet[]; mnemonicVault: EncryptedVault }> {
    if (!userId) throw new Error("userId is required");
    if (!userPassword) throw new Error("Password is required");
    // Local-cache-to-server registration is removed. Generation only returns
    // wallet objects; the caller registers them through createMyWallets, which
    // is server-authoritative (checks existing rows, reloads canonical rows).
    if (options?.persist) {
      throw new Error("PERSIST_REMOVED: use createMyWallets to register generated wallets");
    }

    const origin = typeof window !== "undefined" ? window.location.origin : undefined;

    const { addresses, encryptedVaults }: SecureWalletResult = await createSecureWallet(
      userPassword,
      origin,
      existingMnemonic,
    );

    const createdAt = new Date().toISOString();
    const baseWallet = (
      chainId: string,
      walletType: string,
      address: string,
      encryptedPrivateKey: EncryptedVault,
      assetType?: string,
    ): NonCustodialWallet => ({
      id: crypto.randomUUID(),
      chainId,
      address,
      walletType,
      encryptedPrivateKey,
      encryptedMnemonic: encryptedVaults.mnemonic,
      createdAt,
      isActive: true,
      isBackedUp: false,
      ...(assetType ? { assetType } : {}),
    });

    const wallets: NonCustodialWallet[] = [
      baseWallet("ethereum", "ethereum", addresses.EVM, encryptedVaults.EVM),
      baseWallet("bitcoin", "bitcoin", addresses.BTC, encryptedVaults.BTC),
      baseWallet("Solana", "solana", addresses.SOL, encryptedVaults.SOL),
      baseWallet("Tron (TRC-20)", "tron", addresses.TRX, encryptedVaults.TRX),
      baseWallet("XRP", "xrp", addresses.XRP, encryptedVaults.XRP),
    ];

    return { wallets, mnemonicVault: encryptedVaults.mnemonic };
  }

  /**
   * Adds an extra row for an EVM-family chain (BNB, Polygon, Arbitrum, USDT,
   * USDC, …) that reuses an already-generated EVM wallet's address and vault.
   * Every EVM-compatible chain shares the SAME keypair — there is no separate
   * derivation to run, so this never touches the worker or any key material,
   * it just relabels the existing EVM wallet under a different chainId.
   */
  async addEvmChainVariant(
    evmWallet: NonCustodialWallet,
    chainId: string,
    walletType: string,
    userId: string,
    supabase?: any,
    assetType?: string,
    options?: { persist?: boolean },
  ): Promise<NonCustodialWallet> {
    if (options?.persist) {
      throw new Error("PERSIST_REMOVED: use createMyWallets to register wallet rows");
    }
    const variant: NonCustodialWallet = {
      id: crypto.randomUUID(),
      chainId,
      address: evmWallet.address,
      walletType,
      encryptedPrivateKey: evmWallet.encryptedPrivateKey,
      encryptedMnemonic: evmWallet.encryptedMnemonic,
      createdAt: new Date().toISOString(),
      isActive: true,
      isBackedUp: false,
      ...(assetType ? { assetType } : {}),
    };

    return variant;
  }

  /**
   * One-time seed-phrase backup screen. Decrypts the mnemonic vault inside
   * the worker and returns the plaintext phrase — the only point where the
   * mnemonic crosses back to the main thread. Caller must discard it from
   * component state immediately after the user confirms they've saved it.
   */
  async getWalletMnemonicForBackup(mnemonicVault: EncryptedVault, password: string): Promise<string> {
    return getMnemonicForBackup(mnemonicVault, password);
  }

  /**
   * The server (get_my_wallet) is the ONLY wallet source. Nothing is cached in
   * the browser: vaults are fetched when needed and live in memory only for
   * the operation that uses them. Identity failures (signed out, wrong user,
   * session changed) surface as errors, never as an empty/other-user result.
   */
  private async fetchWallets(userId: string): Promise<NonCustodialWallet[]> {
    const { getSupabase } = await import("./supabase");
    const supabase = await getSupabase();
    return loadMyWallets(supabase as SupabaseClient, userId);
  }

  /**
   * @deprecated There is no local wallet storage any more. Kept so existing
   * callers keep compiling; it now returns the server's wallets.
   */
  public async getWalletsFromStorage(userId: string): Promise<NonCustodialWallet[]> {
    return this.fetchWallets(userId);
  }

  public async getNonCustodialWallets(userId: string): Promise<NonCustodialWallet[]> {
    return this.fetchWallets(userId);
  }

  public async getWalletMnemonic(walletId: string, password: string, userId: string): Promise<string | null> {
    // Server-first: the wallet id must exist on the account's server rows.
    const wallets = await this.fetchWallets(userId);
    const wallet = wallets.find(w => w.id === walletId);
    if (!wallet) return null;
    return this.getMnemonicFromWallet(wallet, password, userId);
  }

  /**
   * Same as getWalletMnemonic but for a wallet object the caller already holds
   * (e.g. just loaded from the server), so a failed local cache write cannot
   * turn into a false "wrong password".
   */
  public async getMnemonicFromWallet(wallet: NonCustodialWallet, password: string, userId: string): Promise<string | null> {
    if (!wallet.encryptedMnemonic) return null;
    return runWithUnlockGate(userId, () =>
      this.decryptPrivateKey(wallet.encryptedMnemonic!, password)
    );
  }

  public async loadWalletsFromSupabase(supabase: any, userId: string): Promise<NonCustodialWallet[]> {
    return loadMyWallets(supabase as SupabaseClient, userId);
  }

  public async saveWalletsToSupabase(supabase: any, wallets: NonCustodialWallet[], userId: string): Promise<void> {
    if (!wallets.length) return;
    const serialize = (v: string | EncryptedVault | undefined) =>
      v === undefined ? null : typeof v === 'string' ? v : JSON.stringify(v);

    // user_id is intentionally omitted — create_my_wallets scopes every row
    // to auth.uid() server-side, so the RPC can't be tricked into writing
    // into another user's rows even if the caller's userId were wrong.
    const payload = wallets.map(w => ({
      id:                     w.id,
      chain_id:               w.chainId,
      address:                w.address,
      wallet_type:            w.walletType,
      encrypted_private_key:  serialize(w.encryptedPrivateKey),
      encrypted_mnemonic:     serialize(w.encryptedMnemonic),
      is_active:              w.isActive   ? 'true' : 'false',
      is_backed_up:           w.isBackedUp ? 'true' : 'false',
    }));

    const { error } = await supabase.rpc('create_my_wallets', { wallets: payload });

    if (error) {
      devLog.error("Error batch-saving wallets:", error);
      throw error;
    }
    // ETH address pinning to user_profiles now happens inside the RPC,
    // atomically with the wallet insert — no separate client-side call needed.
  }

  public async saveWalletToSupabase(supabase: any, wallet: NonCustodialWallet, userId: string): Promise<void> {
    await this.saveWalletsToSupabase(supabase, [wallet], userId);
  }

  async decryptPrivateKey(
    vault: string | EncryptedVault,
    password: string,
    userId?: string
  ): Promise<string> {
    const inner = async (): Promise<string> => {
      if (typeof vault === "string") {
        // The vault arrived as a JSON string (e.g. text DB column or old serialisation path).
        // Try to parse it into an EncryptedVault object before giving up.
        const parsed = parseVaultField(vault);
        if (parsed && typeof parsed === "object" && "ciphertext" in parsed) {
          return callSigningWorker<string>("decryptVault", { vault: parsed, password });
        }
        throw new Error("Legacy vault string found. Please migrate your wallet.");
      }
      return callSigningWorker<string>("decryptVault", { vault, password });
    };
    // When a userId is supplied, route the attempt through the server-side
    // brute-force gate (4+ failures → escalating lockout up to 24h).
    return userId ? runWithUnlockGate(userId, inner) : inner();
  }

  /**
   * Returns true if any wallet for this user still uses the legacy vault format
   * (deterministic salt — a cryptographic weakness). Call this after loading
   * wallets to decide whether to prompt migration.
   */
  async hasLegacyVaults(userId: string): Promise<boolean> {
    const wallets = await this.fetchWallets(userId);
    return wallets.some(
      (w) => isLegacyVault(w.encryptedPrivateKey) || isLegacyVault(w.encryptedMnemonic)
    );
  }

  /**
   * Detects and migrates any legacy-format vaults for this user.
   * Requires the user's plaintext password (only available when the wallet is
   * unlocked). Upgraded vaults are persisted to both local storage and Supabase.
   *
   * Safe to call multiple times — wallets already in the modern format are skipped.
   */
  async migrateLegacyVaults(userId: string, password: string, supabase?: any): Promise<void> {
    // Server rows are the source. Migrating from the local cache and then
    // pushing the result up would let browser state define what gets written
    // to the account. Without a server client we only upgrade the local copy.
    if (!supabase) throw new Error("SUPABASE_REQUIRED");
    const wallets = await loadMyWallets(supabase as SupabaseClient, userId);
    let anyMigrated = false;

    const upgraded = await Promise.all(
      wallets.map(async (wallet) => {
        const needsPrivKey = isLegacyVault(wallet.encryptedPrivateKey);
        const needsMnemonic = isLegacyVault(wallet.encryptedMnemonic);
        if (!needsPrivKey && !needsMnemonic) return wallet;

        try {
          const updatedWallet = { ...wallet };
          if (needsPrivKey) {
            updatedWallet.encryptedPrivateKey = await callSigningWorker<EncryptedVault>(
              "migrateLegacyVault", { legacyData: wallet.encryptedPrivateKey, password, userId, origin: window.location.origin }
            );
          }
          if (needsMnemonic && wallet.encryptedMnemonic) {
            updatedWallet.encryptedMnemonic = await callSigningWorker<EncryptedVault>(
              "migrateLegacyVault", { legacyData: wallet.encryptedMnemonic, password, userId, origin: window.location.origin }
            );
          }
          anyMigrated = true;
          return updatedWallet;
        } catch (e) {
          devLog.error(`Failed to migrate legacy vault for wallet ${wallet.id}:`, e);
          return wallet;
        }
      })
    );

    if (!anyMigrated) return;

    await Promise.all(
      upgraded.map((w) => this.saveWalletToSupabase(supabase, w, userId))
    );
  }
}

const managerInstance = new NonCustodialWalletManager();
export { managerInstance as nonCustodialWalletManager, managerInstance as walletManager };
