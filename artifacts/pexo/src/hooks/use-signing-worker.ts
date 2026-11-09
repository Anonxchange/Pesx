/**
 * use-signing-worker.ts
 *
 * Bridge between the React UI thread and the isolated cryptographic vault worker.
 *
 * All sensitive operations (key derivation, signing, encryption, hashing) run
 * inside signing.worker.ts in an isolated CPU thread. The UI thread only ever
 * sees addresses, signed tx hex, and EncryptedVault blobs — never raw keys.
 *
 * ─── Usage ───────────────────────────────────────────────────────────────────
 *
 *   // Module-level singleton (works outside React too)
 *   import { callSigningWorker } from "@/lib/use-signing-worker";
 *
 *   const mnemonic = await callSigningWorker("generateMnemonic", { strength: 256 });
 *
 *   const vault = await callSigningWorker("encryptVault", {
 *     data: mnemonic, password: userPassword, origin: window.location.origin
 *   });
 *
 *   const { signedTx, txHash } = await callSigningWorker("signEVMTransaction", {
 *     mnemonic, request: { to, amount, currency }
 *   });
 *
 *   // React hook variant
 *   const { call, ready } = useSigningWorker();
 *   const address = await call("getEVMAddress", { mnemonic });
 *
 * ─── Security properties ─────────────────────────────────────────────────────
 *
 *  • The worker is instantiated ONCE per page; never terminated (avoids
 *    re-init cost on each transaction).
 *  • postMessage is structured-clone — no prototype pollution across the boundary.
 *  • scrypt (N=262144) runs inside the worker — the main thread never blocks
 *    during the 1–3 s KDF computation.
 *  • Error messages from the worker are forwarded as plain strings so no
 *    stack traces with sensitive paths leak back.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import type { WorkerRequest, WorkerResponse } from "./signing.worker";

// Re-export types consumers may need
export type { EncryptedVault, PasskeyVault, MultiChainWalletResult, SecureWalletResult, KdfParams } from "./signing.worker";

// ─── Singleton worker + pending-call registry ─────────────────────────────────

type PendingCall = {
  resolve: (value: unknown) => void;
  reject:  (reason: Error)  => void;
};

let sharedWorker: Worker | null = null;
const pending = new Map<string, PendingCall>();
let callSeq = 0;

// ─── Access-token plumbing ───────────────────────────────────────────────────
// The signing worker's chain-gateway calls now require a Supabase access
// token on every gateway-touching request (see assertAccessToken in
// signing.worker.ts) — reads included, not just broadcasts. This file has no
// visibility into this app's auth module, so rather than guessing an import
// path and silently getting it wrong, the app must register a provider once
// at startup:
//
//   import { setAccessTokenProvider } from "@/hooks/use-signing-worker";
//   setAccessTokenProvider(async () => {
//     const { data } = await supabase.auth.getSession();
//     return data.session?.access_token ?? null;
//   });
//
// Until that's wired up, gateway-touching calls fail loudly with "Missing or
// invalid access token" (from the worker) rather than silently sending an
// unauthenticated request — fail-closed, not fail-open.
type AccessTokenProvider = () => Promise<string | null> | string | null;
let accessTokenProvider: AccessTokenProvider | null = null;

export function setAccessTokenProvider(provider: AccessTokenProvider): void {
  accessTokenProvider = provider;
}

// Message types whose `request` object needs an accessToken merged in before
// it crosses the postMessage boundary — i.e. everything that talks to the
// chain-gateway from inside the worker.
const GATEWAY_REQUEST_TYPES = new Set([
  "prepareBitcoinTransferIntent", "signBitcoinTransactionFromVault",
  "prepareSolanaTransferIntent", "signSolanaTransactionFromVault",
  "prepareTronTransferIntent", "signTronTransactionFromVault",
  "prepareSplTokenTransferIntent", "signSplTokenTransactionFromVault",
  "prepareTrc20TransferIntent", "signTrc20TransactionFromVault",
  "prepareEVMTransferIntent", "prepareEVMContractIntent",
  "signEVMTransactionFromVault", "signEVMContractCallFromVault",
]);

async function resolveAccessToken(): Promise<string | null> {
  if (!accessTokenProvider) {
    if (import.meta.env.DEV) {
      console.warn(
        "[use-signing-worker] No access-token provider registered — call " +
        "setAccessTokenProvider() at app startup. Gateway-touching calls will fail."
      );
    }
    return null;
  }
  try {
    return await accessTokenProvider();
  } catch (err) {
    if (import.meta.env.DEV) console.warn("[use-signing-worker] access-token provider threw:", err);
    return null;
  }
}

function getWorker(): Worker {
  if (sharedWorker) return sharedWorker;
  sharedWorker = new Worker(
  new URL("../lib/signing.worker.ts", import.meta.url),
    { type: "module" }
  );
  sharedWorker.onmessage = ({ data }: MessageEvent<WorkerResponse>) => {
    const cb = pending.get(data.id);
    if (!cb) return;
    pending.delete(data.id);
    data.ok ? cb.resolve(data.result) : cb.reject(new Error(data.error));
  };
  sharedWorker.onerror = (err) => {
    console.error("[CryptoVaultWorker]", err.message ?? err);
    // FIX: reject ALL pending calls so they don't hang forever.
    // Without this, any in-flight callSigningWorker() promise would leak
    // and never resolve if the worker crashes (e.g. OOM, syntax error in
    // a dynamically loaded module, or an unhandled exception at top level).
    const workerErr = new Error(`CryptoVaultWorker crashed: ${err.message ?? "unknown error"}`);
    for (const cb of pending.values()) cb.reject(workerErr);
    pending.clear();
    // Null the singleton so the next call recreates the worker.
    sharedWorker = null;
  };
  return sharedWorker;
}

// ─── Core dispatch function ───────────────────────────────────────────────────

type RequestArgs<T extends WorkerRequest["type"]> =
  Omit<Extract<WorkerRequest, { type: T }>, "id" | "type">;

/**
 * Dispatch a request to the cryptographic vault worker and await the result.
 *
 * @example
 * const mnemonic = await callSigningWorker("generateMnemonic", {});
 * const vault    = await callSigningWorker("encryptVault", { data: mnemonic, password, origin });
 */
export async function callSigningWorker<T = unknown>(
  type: WorkerRequest["type"],
  args: RequestArgs<typeof type>
): Promise<T> {
  const id = `cvw-${++callSeq}-${Date.now()}`;
  const worker = getWorker();

  const payload: any = { id, type, ...args };

  // ── Access-token injection ──────────────────────────────────────────────
  // For any message type whose worker handler talks to the chain-gateway,
  // ensure request.accessToken is present. We always fetch a fresh token
  // here rather than trusting a caller-supplied one, since callers building
  // `request` by hand (or forwarding a stale `signRequest` from an earlier
  // prepare step) have no reliable way to know if it's still valid — and a
  // short-lived Supabase session token is exactly the kind of thing that
  // goes stale between a user unlocking their wallet and confirming a send.
  if (GATEWAY_REQUEST_TYPES.has(type) && payload.request && typeof payload.request === "object") {
    const accessToken = await resolveAccessToken();
    payload.request = { ...payload.request, accessToken };
  }

  // ── Transferable password hardening ────────────────────────────────────────
  // If args contains a `password` string, encode it to a Uint8Array and send
  // the underlying ArrayBuffer as a Transferable. After transfer the buffer is
  // detached on the main thread (byteLength → 0) so no other code can read it.
  // The worker receives it as `passwordBytes` and zero-fills it after the KDF.
  const transfer: Transferable[] = [];
  if (typeof (args as any).password === "string" && (args as any).password.length > 0) {
    const pwBytes = new TextEncoder().encode((args as any).password);
    payload.passwordBytes = pwBytes;
    delete payload.password;          // don't send the string form
    transfer.push(pwBytes.buffer as ArrayBuffer);
  }

  return new Promise<T>((resolve, reject) => {
    pending.set(id, { resolve: resolve as (v: unknown) => void, reject });
    worker.postMessage(payload, transfer);
  });
}

// ─── React hook ───────────────────────────────────────────────────────────────

/**
 * React hook that exposes the cryptographic vault worker.
 *
 * `ready` is true once the worker is loaded. Calls before the worker is ready
 * are queued automatically via the singleton — `ready` is primarily useful for
 * showing a loading indicator on the first render.
 */
export function useSigningWorker() {
  const [ready, setReady] = useState(false);
  const workerRef = useRef<Worker | null>(null);

  useEffect(() => {
    workerRef.current = getWorker();
    // Fire a cheap no-op ping to confirm the worker is alive
    callSigningWorker("validateMnemonic", { mnemonic: "" })
      .catch(() => { /* expected — empty string is invalid */ })
      .finally(() => setReady(true));
    return () => { /* never terminate the singleton */ };
  }, []);

  const call = useCallback(
    <T = unknown>(
      type: WorkerRequest["type"],
      args: RequestArgs<typeof type>
    ): Promise<T> => callSigningWorker<T>(type, args as any),
    []
  );

  return { call, ready };
}

// ─── Convenience wrappers ─────────────────────────────────────────────────────
// These are thin wrappers so callers don't have to remember the message type strings.
//
// ⚠️ NOT CONNECTED TO THE CURRENT WORKER: everything in this block
// (generateMnemonic, getEVMAddress, getBitcoinAddress, getSolanaAddress,
// getTronAddress, getXRPAddress, getAllAddresses) calls a message `type` that
// does not exist in signing.worker.ts's WorkerRequest union as it stands today
// — that union only has validateMnemonic, encryptVault(Batch), clearSessionCache,
// validateVaultPassword, migrateLegacyVault, hash, hmacSha256, createSecureWallet,
// getMnemonicForBackup, the prepare/sign pairs for BTC/SOL/TRX/SPL/TRC-20/EVM, and
// the two EVM vault-signing calls. Calling any of these today throws "Unknown
// worker message type" at runtime, and `as any` below is only there so this file
// still type-checks — it is NOT a sign these are safe to call.
// This strongly suggests this file predates a worker rewrite that deliberately
// dropped the "derive an address / mnemonic from a plaintext mnemonic argument"
// API (consistent with vault-crypto.ts's own createMultiChainWallet being
// disabled). If your app still needs plaintext-mnemonic address derivation,
// that's a worker feature to design and add deliberately — not something to
// leave silently broken behind a working-looking wrapper. If nothing calls
// these, delete them; if something does, that call site is currently broken.

/** Generate a fresh BIP-39 mnemonic inside the worker */
export const generateMnemonic = (strength: 128 | 256 = 256) =>
  callSigningWorker<string>("generateMnemonic" as any, { strength } as any);

/** Validate a BIP-39 mnemonic */
export const validateMnemonic = (mnemonic: string) =>
  callSigningWorker<boolean>("validateMnemonic", { mnemonic });

/** Derive the EVM (ETH/BSC/ARB/…) address for a mnemonic */
export const getEVMAddress = (mnemonic: string) =>
  callSigningWorker<string>("getEVMAddress" as any, { mnemonic } as any);

/** Derive the Bitcoin SegWit (P2WPKH / bc1q…) address */
export const getBitcoinAddress = (mnemonic: string) =>
  callSigningWorker<string>("getBitcoinAddress" as any, { mnemonic } as any);

/** Derive the Solana address */
export const getSolanaAddress = (mnemonic: string) =>
  callSigningWorker<string>("getSolanaAddress" as any, { mnemonic } as any);

/** Derive the Tron (TRC-20) address */
export const getTronAddress = (mnemonic: string) =>
  callSigningWorker<string>("getTronAddress" as any, { mnemonic } as any);

/** Derive the XRP address */
export const getXRPAddress = (mnemonic: string) =>
  callSigningWorker<string>("getXRPAddress" as any, { mnemonic } as any);

/** Derive ALL chain addresses in one call */
export const getAllAddresses = (mnemonic: string) =>
  callSigningWorker<{ EVM: string; BTC: string; SOL: string; TRX: string; XRP: string }>(
    "getAllAddresses" as any, { mnemonic } as any
  );

/** Encrypt a secret (mnemonic or private key) with scrypt + AES-256-GCM */
export const encryptVault = (data: string, password: string, origin?: string) =>
  callSigningWorker("encryptVault", { data, password, origin });

/** Encrypt multiple secrets with a single scrypt round */
export const encryptVaultBatch = (items: Array<{ data: string }>, password: string, origin?: string) =>
  callSigningWorker("encryptVaultBatch", { items, password, origin });

/**
 * Decrypt a vault and return the plaintext (mnemonic or raw private key).
 * Unlike getMnemonicForBackup, this has no one-time-per-session limit and
 * doesn't validate the output as a BIP-39 mnemonic — it's used by
 * non-custodial-wallet.ts's decryptPrivateKey for "reveal my seed phrase /
 * private key" style UI. That caller already gates repeated attempts behind
 * a server-side lockout (runWithUnlockGate) before a request gets here, so
 * this being repeatable (rather than one-time like getMnemonicForBackup) is
 * an intentional difference, not an oversight — see signing.worker.ts's
 * WorkerRequest entry for "decryptVault" for the full reasoning. Every call
 * here puts the plaintext on the main thread; callers must discard it from
 * component state as soon as the UI no longer needs it displayed.
 */
export const decryptVault = (vault: unknown, password: string) =>
  callSigningWorker<string>("decryptVault", { vault, password });

/** Decrypt a passkey vault (WebAuthn PRF) — no scrypt, pure AES-GCM in worker */
// ⚠️ NOT CONNECTED: no "decryptVaultWithRawKey" message type exists in the
// current worker. The live passkey decrypt path is webCrypto.ts's own
// decryptVaultWithRawKey, called directly on the main thread (WebAuthn PRF
// output can't easily cross into a Worker) — this wrapper is a leftover
// pointing at a worker capability that was never built. Don't wire this one
// the way decryptVault above just was without first checking whether
// anything actually calls this main-thread version; if nothing does, delete
// this wrapper instead.
export const decryptVaultWithRawKey = (vault: import("./signing.worker").PasskeyVault, rawKey: ArrayBuffer) =>
  callSigningWorker<string>("decryptVaultWithRawKey" as any, { vault, rawKey } as any);

/** Validate a vault password without returning the plaintext */
export const validateVaultPassword = (vault: unknown, password: string) =>
  callSigningWorker<boolean>("validateVaultPassword", { vault, password });

/** Migrate a legacy (deterministic-salt) vault to a modern random-salt vault */
export const migrateLegacyVault = (legacyData: any, password: string, userId: string, origin?: string) =>
  callSigningWorker("migrateLegacyVault", { legacyData, password, userId, origin });

/** Create a full multi-chain wallet with a single scrypt round */
// ⚠️ NOT CONNECTED — vault-crypto.ts's createMultiChainWallet is itself
// deliberately disabled (it throws) pending a tested implementation per chain.
// Use createSecureWallet below instead.
export const createMultiChainWallet = (password: string, origin?: string, existingMnemonic?: string) =>
  callSigningWorker("createMultiChainWallet" as any, { password, origin, existingMnemonic } as any);

/** Hash arbitrary data */
export const hash = (algorithm: "keccak256" | "sha256" | "sha512" | "ripemd160", hex: string) =>
  callSigningWorker<string>("hash", { algorithm, hex });

/** HMAC-SHA256 */
export const hmacSha256 = (keyHex: string, dataHex: string) =>
  callSigningWorker<string>("hmacSha256", { keyHex, dataHex });

// ─── Secure vault-based API ───────────────────────────────────────────────────
// These wrappers use vault + password instead of plaintext mnemonic.
// The mnemonic is decrypted, used, and wiped entirely inside the worker —
// it never appears as a postMessage argument.

/**
 * Create a full multi-chain wallet where the mnemonic NEVER leaves the worker.
 * Returns addresses + EncryptedVaults. Call getMnemonicForBackup() once for
 * the seed phrase display screen.
 */
export const createSecureWallet = (password: string, origin?: string, existingMnemonic?: string) =>
  callSigningWorker<import("./signing.worker").SecureWalletResult>(
    "createSecureWallet", { password, origin, existingMnemonic }
  );

/**
 * Decrypt the mnemonic vault and return the plaintext phrase for the seed
 * phrase backup screen. This is the ONLY time the mnemonic crosses the wire.
 * Discard it from component state immediately after the user confirms backup.
 */
export const getMnemonicForBackup = (vault: unknown, password: string) =>
  callSigningWorker<string>("getMnemonicForBackup", { vault, password });

/** Sign an EVM transfer/send from vault — mnemonic never on postMessage wire */
export const signEVMTransactionFromVault = (vault: unknown, password: string, request: any) =>
  callSigningWorker("signEVMTransactionFromVault", { vault, password, request });

/** Sign an EVM contract call from vault — mnemonic never on postMessage wire */
export const signEVMContractCallFromVault = (vault: unknown, password: string, request: any) =>
  callSigningWorker("signEVMContractCallFromVault", { vault, password, request });

// ⚠️ NOT CONNECTED — no "signEVMRawHashFromVault" message type in the current worker.
export const signEVMRawHashFromVault = (vault: unknown, password: string, hashHex: string) =>
  callSigningWorker<string>("signEVMRawHashFromVault" as any, { vault, password, hashHex } as any);

/** Sign an EIP-191 personal_sign message from vault */
// ⚠️ NOT CONNECTED — no "signEVMMessageFromVault" message type in the current worker.
export const signEVMMessageFromVault = (vault: unknown, password: string, message: string) =>
  callSigningWorker<string>("signEVMMessageFromVault" as any, { vault, password, message } as any);

/** Sign a Bitcoin SegWit transaction from vault */
export const signBitcoinTransactionFromVault = (vault: unknown, password: string, request: any) =>
  callSigningWorker("signBitcoinTransactionFromVault", { vault, password, request });

/** Sign a Solana transaction from vault */
export const signSolanaTransactionFromVault = (vault: unknown, password: string, request: any) =>
  callSigningWorker("signSolanaTransactionFromVault", { vault, password, request });

/** Sign a Tron transaction from vault */
export const signTronTransactionFromVault = (vault: unknown, password: string, request: any) =>
  callSigningWorker("signTronTransactionFromVault", { vault, password, request });

// ─── Two-step approval: prepare, then sign ───────────────────────────────────
// Every chain's signing handler requires a prior `prepare*` call: the worker
// resolves all network-derived values (nonce, fees, UTXOs, blockhash, token
// account addresses, ...), stores the exact intent, and returns a single-use
// `approvalDigest` plus a ready-to-use `signRequest`. The corresponding
// `sign*FromVault` call MUST be given that `signRequest` object as-is — it
// carries the approvalDigest and the exact resolved fields the sign step
// checks against. Building your own request object for the sign step (rather
// than passing through what prepare returned) will fail the approval-digest
// check by design; that check is what stops a value from being changed
// between "user approved this" and "this got signed."
//
//   const prepared = await prepareEVMTransferIntent(vault, password, { to, amount, currency });
//   const result   = await signEVMTransactionFromVault(vault, password, prepared.signRequest);

/** Resolve nonce + gas/fee fields for an EVM transfer, returns { signRequest, approvalDigest, intent } */
export const prepareEVMTransferIntent = (vault: unknown, password: string, request: any) =>
  callSigningWorker<{ from: string; intent: unknown; approvalDigest: string; signRequest: any }>(
    "prepareEVMTransferIntent", { vault, password, request }
  );

/** Resolve nonce + gas/fee fields for an EVM contract call, returns { signRequest, approvalDigest, intent } */
export const prepareEVMContractIntent = (vault: unknown, password: string, request: any) =>
  callSigningWorker<{ from: string; intent: unknown; approvalDigest: string; signRequest: any }>(
    "prepareEVMContractIntent", { vault, password, request }
  );

/** Verify UTXOs on-chain + compute fee/change for a Bitcoin send, returns { signRequest, approvalDigest, intent } */
export const prepareBitcoinTransferIntent = (vault: unknown, password: string, request: any) =>
  callSigningWorker<{ from: string; intent: unknown; approvalDigest: string; signRequest: any }>(
    "prepareBitcoinTransferIntent", { vault, password, request }
  );

/** Fetch a fresh blockhash for a native SOL transfer, returns { signRequest, approvalDigest, intent } */
export const prepareSolanaTransferIntent = (vault: unknown, password: string, request: any) =>
  callSigningWorker<{ from: string; intent: unknown; approvalDigest: string; signRequest: any }>(
    "prepareSolanaTransferIntent", { vault, password, request }
  );

/** Build + verify a native TRX transfer via the gateway, returns { signRequest, approvalDigest, intent } */
export const prepareTronTransferIntent = (vault: unknown, password: string, request: any) =>
  callSigningWorker<{ from: string; intent: unknown; approvalDigest: string; signRequest: any }>(
    "prepareTronTransferIntent", { vault, password, request }
  );

/**
 * Derive + verify sender/recipient Associated Token Accounts for a USDC/USDT
 * (SPL) transfer on Solana. `request.currency` must be "USDC_SOL" or
 * "USDT_SOL". Throws if the recipient has no token account for that mint yet
 * — this signer does not create one on their behalf (see signing.worker.ts).
 * Returns { signRequest, approvalDigest, intent }.
 */
export const prepareSplTokenTransferIntent = (vault: unknown, password: string, request: any) =>
  callSigningWorker<{ from: string; intent: unknown; approvalDigest: string; signRequest: any }>(
    "prepareSplTokenTransferIntent", { vault, password, request }
  );

/** Sign a prepared USDC/USDT (SPL) transfer on Solana. Pass prepare's signRequest through as-is. */
export const signSplTokenTransactionFromVault = (vault: unknown, password: string, request: any) =>
  callSigningWorker("signSplTokenTransactionFromVault", { vault, password, request });

/**
 * Build + verify a USDC/USDT (TRC-20) transfer on TRON via the gateway.
 * `request.currency` must be "USDC_TRX" or "USDT_TRX". Returns
 * { signRequest, approvalDigest, intent }.
 */
export const prepareTrc20TransferIntent = (vault: unknown, password: string, request: any) =>
  callSigningWorker<{ from: string; intent: unknown; approvalDigest: string; signRequest: any }>(
    "prepareTrc20TransferIntent", { vault, password, request }
  );

/** Sign a prepared USDC/USDT (TRC-20) transfer on TRON. Pass prepare's signRequest through as-is. */
export const signTrc20TransactionFromVault = (vault: unknown, password: string, request: any) =>
  callSigningWorker("signTrc20TransactionFromVault", { vault, password, request });

/**
 * Call on logout (or whenever you want to be extra sure). Maps to
 * clearSessionCache in the worker, which — despite the name — is a no-op
 * kept only for API compatibility: vault-crypto.ts deliberately keeps NO
 * reusable derived-key cache in production ("Every vault open re-runs
 * scrypt, reducing the time a derived AES key remains in memory" — see
 * vault-crypto.ts). So every prepare/sign call already re-derives and wipes
 * its own key; there's no cached key for this call to clear. It's harmless
 * to keep calling on logout, just don't rely on it to do anything.
 */
export const clearWorkerSessionCache = () =>
  callSigningWorker("clearSessionCache", {} as any);
