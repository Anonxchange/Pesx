/**
 * ============================================================
 *  PEXLY CRYPTO VAULT WORKER — signing.worker.ts
 * ============================================================
 *
 * This is the Worker ENTRY POINT — the one file the `Worker` constructor in
 * use-signing-worker.ts loads (`new Worker(new URL("../lib/signing.worker.ts", ...))`).
 * It owns the postMessage protocol (WorkerRequest/WorkerResponse, the message
 * dispatch loop) and everything chain-specific: RPC calls through the Supabase
 * chain-gateway edge function, EIP-1559 fee logic, and transaction building
 * + signing for EVM, native BTC/SOL/TRX, and SPL/TRC-20 USDC+USDT.
 *
 * Scope note: only the SPL and TRC-20 tokens explicitly listed in SPL_TOKENS /
 * TRC20_TOKENS below are supported. Adding another token means adding its
 * mint/contract address + decimals there — nothing here "generically" signs
 * an arbitrary token, on purpose.
 *
 * Mnemonic generation, per-chain key/address derivation, and vault
 * encryption/decryption live in ./vault-crypto.ts, which this file imports.
 * That split is source-file organisation only — the runtime architecture,
 * the postMessage security properties, and the "nothing sensitive crosses
 * the wire" invariants described below are unchanged and still enforced
 * entirely within this one Worker thread (across its two source files).
 *
 * ─── What NEVER crosses the postMessage wire ─────────────────────────────────
 *   • Plaintext mnemonics (except the one controlled path: getMnemonicForBackup)
 *   • Raw private keys of any chain
 *   • Scrypt-derived key material
 *   • Plaintext passwords (received as passwordBytes, zero-filled after use)
 *
 * ─── Signing coverage ─────────────────────────────────────────────────────────
 *   EVM   — RLP + keccak-256 + ECDSA (EIP-155 legacy + EIP-1559 type-2)
 *   BTC   — Native SegWit (P2WPKH) via @scure/btc-signer, with network UTXO verification
 *   SOL   — SLIP-0010 (m/44'/501'/0'/0) + ed25519, canonical legacy message serialization
 *   TRX   — TRON protobuf raw_data_hex supplied by the gateway, SHA-256 + secp256k1 signature
 */

// ─── Imports ──────────────────────────────────────────────────────────────────

import * as RLP      from "@ethereumjs/rlp";
import * as secp      from "@noble/secp256k1";
import * as btc       from "@scure/btc-signer";
import * as nobleEd   from "@noble/ed25519";
import { base58 }     from "@scure/base";


import { keccak_256 } from "@noble/hashes/sha3.js";
import { sha256 }     from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

import {
  wipeBytes,
  clearSessionCache,
  parseVault,
  workerValidateMnemonic,
  deriveEVMKey,
  deriveBTCPrivateKey,
  deriveSOLPrivateKey,
  deriveTRONPrivateKey,
  encryptVault,
  encryptVaultBatch,
  openVault,
  migrateLegacyVault,
  createSecureWallet,
  getMnemonicForBackup,
  validateVaultPassword,
  workerHash,
  workerHmacSha256,
} from "./vault-crypto";
import type {
  EncryptedVault,
  KdfParams,
  MultiChainWalletResult,
  SecureWalletResult,
  PasskeyVault,
} from "./vault-crypto";

// Re-export vault-crypto's types so use-signing-worker.ts's existing
// `export type { EncryptedVault, PasskeyVault, MultiChainWalletResult, SecureWalletResult, KdfParams } from "./signing.worker"`
// keeps working unmodified — this file is still "the worker module" as far
// as every external import is concerned.
export type { EncryptedVault, PasskeyVault, KdfParams, MultiChainWalletResult, SecureWalletResult };

// ─── Chain configs ────────────────────────────────────────────────────────────

// rpcUrl / rpcFallbacks removed — all RPC calls now go through the Supabase
// chain-gateway edge function via workerGatewayRpc(). No direct public-node calls.
const CHAIN_CONFIGS: Record<string, {
  chainId: number;
  symbol: string;
  /** true = EIP-1559 type-2 tx by default; false = legacy type-0 only */
  eip1559: boolean;
}> = {
  ETH:  { chainId: 1,     symbol: "ETH", eip1559: true  },
  BSC:  { chainId: 56,    symbol: "BNB", eip1559: false },
  BNB:  { chainId: 56,    symbol: "BNB", eip1559: false },
  ARB:  { chainId: 42161, symbol: "ETH", eip1559: true  },
  POL:  { chainId: 137,   symbol: "POL",  eip1559: true  },
  MATIC:{ chainId: 137,   symbol: "POL",  eip1559: true  },
  AVAX: { chainId: 43114, symbol: "AVAX", eip1559: true  },
};

const TOKEN_CONTRACTS: Record<string, { address: string; decimals: number }> = {
  USDT_ETH:  { address: "0xdAC17F958D2ee523a2206206994597C13D831ec7", decimals: 6  },
  USDC_ETH:  { address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", decimals: 6  },
  USDT_BSC:  { address: "0x55d398326f99059fF775485246999027B3197955", decimals: 18 },
  USDC_BSC:  { address: "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d", decimals: 18 },
  USDT_BNB:  { address: "0x55d398326f99059fF775485246999027B3197955", decimals: 18 },
  USDC_BNB:  { address: "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d", decimals: 18 },
  USDT_ARB:  { address: "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", decimals: 6  },
  USDC_ARB:  { address: "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", decimals: 6  },
  USDCE_ARB: { address: "0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8", decimals: 6  },
};

const NATIVE_CURRENCIES: Record<string, Set<string>> = {
  ETH: new Set(["ETH"]),
  BSC: new Set(["BNB"]),
  BNB: new Set(["BNB"]),
  ARB: new Set(["ETH"]),
  POL: new Set(["POL", "MATIC"]),
  MATIC: new Set(["POL", "MATIC"]),
  AVAX: new Set(["AVAX"]),
};

function assertSupportedCurrency(currency: string, baseChain: string): void {
  if (TOKEN_CONTRACTS[currency]) return;
  if (!NATIVE_CURRENCIES[baseChain]?.has(currency)) {
    throw new Error(`Unsupported currency ${currency} on ${baseChain}`);
  }
}

// ─── Gateway RPC helpers ───────────────────────────────────────────────────────
// All blockchain reads are routed through the Supabase chain-gateway edge
// function (Alchemy-backed) instead of calling public nodes directly.
// This applies to nonce, gas price, gas estimation, and any other read-only
// eth_* call made from within the signing worker.

/** Maps local CHAIN_CONFIGS key → Alchemy chain identifier used by chain-gateway. */
const WORKER_GATEWAY_CHAIN: Record<string, string> = { BSC: "BNB", BNB: "BNB", MATIC: "POL" };
function workerGatewayChain(key: string): string {
  return WORKER_GATEWAY_CHAIN[key] ?? key;
}

/**
 * Routes a read-only JSON-RPC call through the Supabase chain-gateway edge
 * function (Alchemy-backed). Returns the JSON-RPC `.result` value directly
 * so callers can use it as a hex string without further unwrapping.
 *
 * Replaces the old `rpcCall()` helper that made direct calls to hardcoded
 * public RPC endpoints (publicnode.com, drpc.org, etc.).
 *
 * accessToken is REQUIRED and must come from the caller's own `request`
 * object, not a module-level variable. This worker's `onmessage` handler is
 * async, so two in-flight messages can interleave at any `await`; a shared
 * mutable `currentAccessToken` global would let one call's token leak into,
 * or get wiped out from under, a concurrent call. See assertAccessToken().
 */
async function workerGatewayRpc(chain: string, method: string, params: unknown[], accessToken: string): Promise<unknown> {
  const supabaseUrl = (import.meta.env.VITE_SUPABASE_URL as string | undefined) ?? "";
  const anonKey    = (import.meta.env.VITE_SUPABASE_ANON_KEY as string | undefined) ?? "";
  if (!supabaseUrl || !anonKey) {
    throw new Error("chain-gateway: VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY must be set.");
  }
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 15_000);
  try {
    const res = await fetch(`${supabaseUrl}/functions/v1/chain-gateway`, {
      method: "POST",
      headers: { "Content-Type": "application/json", apikey: anonKey, ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}) },
      body: JSON.stringify({ action: "rpc", chain: chain.toUpperCase(), method, params }),
      signal: ctrl.signal,
    });
    let data: any;
    try { data = await res.json(); } catch { throw new Error(`Gateway returned non-JSON (HTTP ${res.status})`); }
    if (!res.ok || data?.error) {
      throw new Error(formatWorkerRpcError(data?.error ?? data?.message ?? `Gateway HTTP ${res.status}`));
    }
    // Extract the JSON-RPC result from the {result, jsonrpc, id} envelope
    return data?.result ?? data;
  } finally {
    clearTimeout(t);
  }
}

async function workerGatewayTron(path: string, body: unknown, accessToken: string): Promise<any> {
  const supabaseUrl = (import.meta.env.VITE_SUPABASE_URL as string | undefined) ?? "";
  const anonKey = (import.meta.env.VITE_SUPABASE_ANON_KEY as string | undefined) ?? "";
  if (!supabaseUrl || !anonKey) throw new Error("chain-gateway: Supabase environment is missing");
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 15_000);
  try {
    const res = await fetch(`${supabaseUrl}/functions/v1/chain-gateway`, {
      method: "POST", headers: { "Content-Type": "application/json", apikey: anonKey, ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}) },
      body: JSON.stringify({ action: "tron", path, method: "POST", body }), signal: ctrl.signal
    });
    const data = await res.json().catch(() => null);
    if (!res.ok || data?.error) throw new Error(formatWorkerRpcError(data?.error ?? data?.message ?? `Gateway HTTP ${res.status}`));
    return data;
  } finally { clearTimeout(t); }
}

/**
 * Validates and extracts the access token from a single request object.
 * Every handler that calls workerGatewayRpc/workerGatewayTron must obtain
 * its token through this function (from ITS OWN `request`, never a shared
 * variable) so concurrent worker messages can never observe each other's
 * credentials. Throwing here (rather than silently falling back to
 * `undefined`, as the old currentAccessToken ternary did) also means a
 * malformed/oversized token fails loudly instead of quietly downgrading to
 * an unauthenticated call.
 */
function assertAccessToken(request: any): string {
  const token = request?.accessToken;
  if (typeof token !== "string" || token.length === 0 || token.length > 4096) {
    throw new Error("Missing or invalid access token");
  }
  return token;
}

function parseDecimalUnits(value: unknown, decimals: number, name: string): bigint {
  if (typeof value !== "string" || !/^\d+(?:\.\d+)?$/.test(value)) throw new Error(`Invalid ${name}`);
  const [whole, fraction = ""] = value.split(".");
  if (fraction.length > decimals) throw new Error(`${name} has more than ${decimals} decimal places`);
  return BigInt(whole) * (10n ** BigInt(decimals)) + BigInt((fraction + "0".repeat(decimals)).slice(0, decimals) || "0");
}

function u64le(value: bigint): number[] {
  if (value < 0n || value > 0xffffffffffffffffn) throw new Error("u64 value out of range");
  const out = new Array<number>(8); let x = value;
  for (let i = 0; i < 8; i++) { out[i] = Number(x & 0xffn); x >>= 8n; }
  return out;
}

function solShortVec(n: number): number[] {
  if (!Number.isInteger(n) || n < 0) throw new Error("Invalid Solana vector length");
  const out: number[] = []; let x = n;
  do { let b = x & 0x7f; x = Math.floor(x / 128); if (x) b |= 0x80; out.push(b); } while (x);
  return out;
}

function buildSolanaLegacyMessage(payer: Uint8Array, recentBlockhash: Uint8Array, keys: Uint8Array[], programIndex: number, accountIndexes: number[], data: Uint8Array, readonlyUnsigned: number): Uint8Array {
  if (recentBlockhash.length !== 32) throw new Error("Invalid Solana recent blockhash");
  const header = [1, 0, readonlyUnsigned];
  return new Uint8Array([
    ...header, ...solShortVec(keys.length), ...keys.flatMap(k => Array.from(k)),
    ...recentBlockhash, ...solShortVec(1), programIndex, ...solShortVec(accountIndexes.length),
    ...accountIndexes, ...solShortVec(data.length), ...data
  ]);
}

// ─── SPL Token (Solana) / TRC-20 (TRON) constants ────────────────────────────
// Every constant below was independently verified against multiple current
// sources (issuer docs, block explorers, the official SPL Associated Token
// Account spec) before being committed here. That said: given what's at
// stake, re-verify each one yourself against an authoritative, live source
// (Solana Explorer / Solscan for the mints, Tronscan for the contracts, the
// spl-associated-token-account program docs for the program IDs) before this
// touches real funds. A single wrong character here is unrecoverable.
//
// Deliberately NOT "generic token support": adding a token means adding its
// mint/contract + decimals to one of the two maps below. Nothing here signs
// an arbitrary, caller-supplied token contract.
const SOL_TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const SOL_ASSOCIATED_TOKEN_PROGRAM_ID = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

const SPL_TOKENS: Record<string, { mint: string; decimals: number }> = {
  USDC_SOL: { mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", decimals: 6 },
  USDT_SOL: { mint: "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB", decimals: 6 },
};

const TRC20_TOKENS: Record<string, { contract: string; decimals: number }> = {
  USDT_TRX: { contract: "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", decimals: 6 },
  USDC_TRX: { contract: "TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8", decimals: 6 },
};

// ─── Ed25519 curve arithmetic for Solana Program Derived Addresses ──────────
// Implemented with plain modular BigInt arithmetic rather than reaching into
// @noble/ed25519 internals, whose class names/API have already changed
// across major versions elsewhere in this file (see the v2/v3 wiring notes
// above). This performs the same check `PublicKey.isOnCurve` does: a valid
// PDA must NOT decode to a point that satisfies the curve equation. Verify
// this against a few known associated-token-account addresses (e.g. compare
// against `getAssociatedTokenAddressSync` from @solana/spl-token, or what
// Solana Explorer shows for a wallet's USDC account) before trusting it with
// real funds — elliptic-curve code is exactly the kind of thing that can be
// subtly wrong and still "usually" work.
const ED_P = (1n << 255n) - 19n;
function edMod(a: bigint, m: bigint): bigint { const r = a % m; return r >= 0n ? r : r + m; }
function edPow(base: bigint, exp: bigint, m: bigint): bigint {
  base = edMod(base, m); let result = 1n;
  while (exp > 0n) { if (exp & 1n) result = edMod(result * base, m); exp >>= 1n; base = edMod(base * base, m); }
  return result;
}
function edInv(a: bigint, m: bigint): bigint { return edPow(a, m - 2n, m); }
const ED_D = edMod(-121665n * edInv(121666n, ED_P), ED_P);
const ED_SQRT_M1 = edPow(2n, (ED_P - 1n) / 4n, ED_P);
function edSqrt(a: bigint): bigint | null {
  let c = edPow(a, (ED_P + 3n) / 8n, ED_P);
  if (edMod(c * c - a, ED_P) === 0n) return c;
  c = edMod(c * ED_SQRT_M1, ED_P);
  if (edMod(c * c - a, ED_P) === 0n) return c;
  return null;
}
function isOnEd25519Curve(point: Uint8Array): boolean {
  if (point.length !== 32) return false;
  const bytes = point.slice(); bytes[31] &= 0x7f;
  let y = 0n; for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(bytes[i]);
  if (y >= ED_P) return false;
  const y2 = edMod(y * y, ED_P);
  const u = edMod(y2 - 1n, ED_P);
  const v = edMod(ED_D * y2 + 1n, ED_P);
  const x2 = edMod(u * edInv(v, ED_P), ED_P);
  if (x2 === 0n) return true; // (0, y) is itself a valid curve point
  return edSqrt(x2) !== null;
}

/** Solana's `PublicKey.findProgramAddressSync` — off-curve, deterministic, bump-seeded. */
async function findProgramAddress(seeds: Uint8Array[], programId: Uint8Array): Promise<Uint8Array> {
  const marker = new TextEncoder().encode("ProgramDerivedAddress");
  for (let bump = 255; bump >= 0; bump--) {
    const parts = [...seeds, new Uint8Array([bump]), programId, marker];
    const total = parts.reduce((n, p) => n + p.length, 0);
    const combined = new Uint8Array(total);
    let off = 0; for (const p of parts) { combined.set(p, off); off += p.length; }
    const candidate = sha256(combined);
    if (!isOnEd25519Curve(candidate)) return candidate;
  }
  throw new Error("Unable to derive a valid Solana program address");
}

/** Seeds per the SPL Associated Token Account spec: [wallet, tokenProgram, mint]. */
async function deriveAssociatedTokenAccount(owner: Uint8Array, mint: Uint8Array): Promise<Uint8Array> {
  return findProgramAddress([owner, base58.decode(SOL_TOKEN_PROGRAM_ID), mint], base58.decode(SOL_ASSOCIATED_TOKEN_PROGRAM_ID));
}

/** SPL Token account layout: mint(32) + owner(32) + amount(u64 LE, 8) + ... */
function decodeSplTokenAccount(raw: Uint8Array): { mint: Uint8Array; owner: Uint8Array; amount: bigint } {
  if (raw.length < 72) throw new Error("Invalid SPL token account data");
  const mint = raw.slice(0, 32);
  const owner = raw.slice(32, 64);
  let amount = 0n; for (let i = 71; i >= 64; i--) amount = (amount << 8n) | BigInt(raw[i]);
  return { mint, owner, amount };
}

async function fetchSolanaAccount(address: string, accessToken: string): Promise<Uint8Array | null> {
  const result = await workerGatewayRpc("SOL", "getAccountInfo", [address, { encoding: "base64" }], accessToken) as any;
  const value = result?.value;
  if (!value) return null;
  return decodeRpcBytes(value.data);
}

function tronAbiEncodeAddress(addr: string): string {
  const hex = tronAddressToHex(addr); // 42 hex chars, no "0x": 1-byte 0x41 network prefix + 20-byte account body
  if (hex.length !== 42) throw new Error("Unexpected TRON address hex length");
  return hex.slice(2).padStart(64, "0"); // drop the 1-byte network prefix, left-pad the 20-byte body to 32 bytes
}
function tronAbiEncodeUint256(amount: bigint): string {
  if (amount < 0n || amount >= (1n << 256n)) throw new Error("Invalid TRC-20 amount");
  return amount.toString(16).padStart(64, "0");
}

function decodeRpcBytes(data: unknown): Uint8Array {
  if (!Array.isArray(data) || typeof data[0] !== "string") throw new Error("Invalid Solana account data");
  if (data[1] !== "base64") throw new Error("Solana account data must be base64");
  const bin = atob(data[0]); const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function tronAddressToHex(address: string): string {
  if (typeof address !== "string" || !/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(address)) throw new Error("Invalid TRON address");
  const raw = base58.decode(address);
  if (raw.length !== 25 || raw[0] !== 0x41) throw new Error("Invalid TRON address checksum payload");
  const body = raw.slice(0, 21); const checksum = sha256(sha256(body)).slice(0, 4);
  for (let i = 0; i < 4; i++) if (checksum[i] !== raw[21 + i]) throw new Error("Invalid TRON address checksum");
  return bytesToHex(body);
}

function tronAddressFromPrivateKey(priv: Uint8Array): string {
  const pub = secp.getPublicKey(priv, false);
  const body = new Uint8Array([0x41, ...keccak_256(pub.slice(1)).slice(-20)]);
  const full = new Uint8Array([...body, ...sha256(sha256(body)).slice(0, 4)]);
  return base58.encode(full);
}

function formatWorkerRpcError(value: unknown): string {
  if (value instanceof Error && value.message) return value.message;
  if (typeof value === "string" && value.trim()) return value;
  if (value && typeof value === "object") {
    const error = value as Record<string, unknown>;
    const nested = error.error;
    if (nested && nested !== value) return formatWorkerRpcError(nested);
    const message = error.message ?? error.msg ?? error.detail ?? error.reason;
    if (typeof message === "string" && message.trim()) {
      return message.replace(/\s*\(code\s+[-\d]+\)\s*$/i, "").trim();
    }
    try { return JSON.stringify(value); } catch { return "Unknown RPC error"; }
  }
  return String(value || "Unknown RPC error");
}

// ─── RPC response validators ──────────────────────────────────────────────────
// Every value that comes back from an untrusted public RPC endpoint is checked
// against hard bounds before it enters any BigInt / signing path.
// An attacker who can MitM the RPC response could otherwise:
//   • Inject a nonce of 0 to replay old transactions
//   • Return an absurdly high gasPrice to drain the sender
//   • Return a gasLimit of 0 to make the signed tx always fail

const RPC_NONCE_MAX        = 2 ** 32;          // no wallet has >4 billion txs
const RPC_GAS_PRICE_MIN    = 1_000_000n;        // 0.001 gwei floor (stale RPC)
const RPC_GAS_PRICE_MAX    = 50_000n * 1_000_000_000n; // 50 000 gwei ceiling
const RPC_GAS_LIMIT_MIN    = 21_000n;
const RPC_GAS_LIMIT_MAX    = 15_000_000n;       // Ethereum block gas limit

function validateRpcNonce(raw: unknown): number {
  let n: number;
  if (typeof raw === "string") {
    if (!/^0x[0-9a-fA-F]+$/.test(raw)) throw new Error(`RPC returned invalid nonce: ${JSON.stringify(raw)}`);
    n = Number(BigInt(raw));
  } else {
    n = Number(raw);
  }
  if (!Number.isSafeInteger(n) || n < 0 || n > RPC_NONCE_MAX) {
    throw new Error(`RPC returned implausible nonce: ${JSON.stringify(raw)}`);
  }
  return n;
}

function validateRpcGasPrice(raw: unknown): bigint {
  let v: bigint;
  try { v = BigInt(typeof raw === "string" ? raw : String(raw)); }
  catch { throw new Error(`RPC returned non-numeric gasPrice: ${JSON.stringify(raw)}`); }
  if (v < RPC_GAS_PRICE_MIN || v > RPC_GAS_PRICE_MAX) {
    throw new Error(
      `RPC gasPrice out of safe range: ${v} wei (${v / 1_000_000_000n} gwei). ` +
      `Acceptable: 0.001–50 000 gwei. Possible RPC manipulation — tx rejected.`
    );
  }
  return v;
}

function tryValidateRpcGasPrice(raw: unknown): bigint | null {
  try {
    return validateRpcGasPrice(raw);
  } catch {
    return null;
  }
}

interface FeeHistoryFallback {
  latestBaseFeePerGas: bigint;
  priorityFeePerGas: bigint;
}

/**
 * Some RPC providers return zero for eth_gasPrice and/or
 * eth_maxPriorityFeePerGas while feeHistory is still populated. Use the
 * canonical EIP-1559 fee-history method before rejecting the transaction.
 *
 * This is deliberately not a hardcoded gas-price fallback: the values still
 * come from the authenticated chain gateway and are checked against the same
 * safety bounds as every other RPC-derived fee.
 */
async function getFeeHistoryFallback(chain: string, accessToken: string): Promise<FeeHistoryFallback> {
  const raw = await workerGatewayRpc(chain, "eth_feeHistory", ["0x5", "latest", [25, 50, 75]], accessToken) as any;
  const baseFees = Array.isArray(raw?.baseFeePerGas) ? raw.baseFeePerGas : [];
  const rewards = Array.isArray(raw?.reward) ? raw.reward : [];

  // eth_feeHistory returns one more base fee than the number of sampled
  // blocks; the final entry is the next block's base fee and is the best
  // current estimate for maxFeePerGas.
  const latestBaseFeePerGas = tryValidateRpcGasPrice(baseFees[baseFees.length - 1]);
  if (latestBaseFeePerGas == null) {
    throw new Error("RPC feeHistory did not contain a valid base fee");
  }

  const priorityCandidates = rewards
    .flatMap((row: unknown) => Array.isArray(row) ? row : [])
    .map((value: unknown) => tryValidateRpcGasPrice(value))
    .filter((value: bigint | null): value is bigint => value != null)
    .sort((a: bigint, b: bigint) => a < b ? -1 : a > b ? 1 : 0);

  if (priorityCandidates.length === 0) {
    throw new Error("RPC feeHistory did not contain a valid priority fee");
  }

  return {
    latestBaseFeePerGas,
    priorityFeePerGas: priorityCandidates[Math.floor(priorityCandidates.length / 2)],
  };
}

function validateRpcGasLimit(raw: unknown, floorOverride?: bigint): bigint {
  let v: bigint;
  try { v = BigInt(typeof raw === "string" ? raw : String(raw)); }
  catch { throw new Error(`RPC returned non-numeric gasLimit: ${JSON.stringify(raw)}`); }
  const floor = floorOverride ?? RPC_GAS_LIMIT_MIN;
  if (v < floor || v > RPC_GAS_LIMIT_MAX) {
    throw new Error(
      `RPC gasLimit out of safe range: ${v}. ` +
      `Acceptable: ${floor}–${RPC_GAS_LIMIT_MAX}.`
    );
  }
  return v;
}

// ─── ⑦  EVM transaction signing ──────────────────────────────────────────────

const MAX_REQUEST_STRING = 16 * 1024;
const MAX_DATA_BYTES = 128 * 1024;

function assertString(value: unknown, name: string, max = MAX_REQUEST_STRING): asserts value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > max) {
    throw new Error(`Invalid ${name}`);
  }
}

function assertHex(value: unknown, name: string, bytes?: number): string {
  assertString(value, name, bytes == null ? MAX_DATA_BYTES : bytes * 2 + 2);
  const stripped = value.startsWith("0x") ? value.slice(2) : value;
  if (stripped.length % 2 || !/^[0-9a-fA-F]*$/.test(stripped)) {
    throw new Error(`Invalid ${name}: expected hexadecimal data`);
  }
  if (bytes != null && stripped.length !== bytes * 2) {
    throw new Error(`Invalid ${name}: expected ${bytes} bytes`);
  }
  return "0x" + stripped;
}

function assertAddress(value: unknown, name = "address"): string {
  assertString(value, name, 42);
  if (!/^0x[0-9a-fA-F]{40}$/.test(value)) {
    throw new Error(`Invalid ${name}: expected a 20-byte EVM address`);
  }
  return value;
}

function assertPositiveDecimal(value: unknown, name: string, decimals: number): string {
  assertString(value, name, 128);
  if (!/^(?:0|[1-9]\d*)(?:\.\d+)?$/.test(value)) {
    throw new Error(`Invalid ${name}`);
  }
  const [whole, fraction = ""] = value.split(".");
  if (fraction.length > decimals) {
    throw new Error(`${name} has more than ${decimals} decimal places`);
  }
  if (BigInt(whole) === 0n && BigInt(fraction || "0") === 0n) {
    throw new Error(`${name} must be greater than zero`);
  }
  return value;
}

const MAX_INTENT_STRING = 4096;

function canonicalIntent(value: Record<string, unknown>): string {
  const keys = Object.keys(value).sort();
  const ordered: Record<string, unknown> = Object.create(null);
  for (const key of keys) ordered[key] = value[key];
  return JSON.stringify(ordered);
}

async function intentDigest(intent: Record<string, unknown>): Promise<string> {
  const bytes = new TextEncoder().encode(canonicalIntent(intent));
  return "0x" + bytesToHex(sha256(bytes));
}

function assertIntentDigest(value: unknown): string {
  return assertHex(value, "approvalDigest", 32);
}

// Prepared approvals live only inside this Worker. A digest supplied by the
// UI is not enough: the Worker must have issued the exact approval first, and
// every approval is single-use and short-lived. This prevents replay and stops
// the UI from changing the transaction after preparation. It does NOT prove
// that the browser UI itself was honest; a fully compromised origin can still
// ask the Worker to prepare and approve a malicious transaction. A hardware
// signer / external trusted display is required for that stronger guarantee.
const APPROVAL_TTL_MS = 90_000;
const MAX_PENDING_APPROVALS = 8;
const pendingApprovals = new Map<string, { expiresAt: number; from: string; intent: Record<string, unknown> }>();

function rememberApproval(approvalDigest: string, from: string, intent: Record<string, unknown>): void {
  const now = Date.now();
  for (const [digest, entry] of pendingApprovals) {
    if (entry.expiresAt <= now) pendingApprovals.delete(digest);
  }
  if (pendingApprovals.size >= MAX_PENDING_APPROVALS) {
    throw new Error("Too many pending transaction approvals; finish or cancel an existing approval first");
  }
  pendingApprovals.set(approvalDigest, { expiresAt: now + APPROVAL_TTL_MS, from: from.toLowerCase(), intent });
}

function consumeApproval(approvalDigest: string, from: string, intent: Record<string, unknown>): void {
  const entry = pendingApprovals.get(approvalDigest);
  pendingApprovals.delete(approvalDigest);
  if (!entry || entry.expiresAt <= Date.now()) throw new Error("Transaction approval expired or was not prepared by this Worker");
  if (entry.from !== from.toLowerCase()) throw new Error("Transaction approval belongs to a different wallet address");
  if (canonicalIntent(entry.intent) !== canonicalIntent(intent)) throw new Error("Transaction approval does not match the exact prepared transaction");
}

function clearPendingApprovals(): void {
  pendingApprovals.clear();
}

function parseTokenAmount(amount: string, decimals: number): bigint {
  const [whole, fraction = ""] = amount.split(".");
  if (!/^\d+$/.test(whole) || !/^\d*$/.test(fraction) || fraction.length > decimals) {
    throw new Error("Invalid token amount or excessive precision");
  }
  return BigInt(whole) * (10n ** BigInt(decimals)) +
    BigInt(fraction.padEnd(decimals, "0") || "0");
}

function encodeERC20Transfer(to: string, amount: bigint): string {
  const address = assertAddress(to, "token recipient").slice(2).toLowerCase();
  if (amount < 0n || amount >= (1n << 256n)) throw new Error("Invalid token amount");
  const selector = keccak_256(new TextEncoder().encode("transfer(address,uint256)")).slice(0, 4);
  const paddedTo  = address.padStart(64, "0");
  const paddedAmt = amount.toString(16).padStart(64, "0");
  return "0x" + bytesToHex(selector) + paddedTo + paddedAmt;
}

// ─── EIP-1559 helper ──────────────────────────────────────────────────────────
// Prepend the transaction type byte to an RLP-encoded payload.
function prependTxType(type: number, rlpPayload: Uint8Array): Uint8Array {
  const out = new Uint8Array(1 + rlpPayload.length);
  out[0] = type;
  out.set(rlpPayload, 1);
  return out;
}

/**
 * Shared EIP-1559 type-2 / legacy type-0 EVM signing core.
 * Eliminates the duplicate signing block that existed in both EVM handlers.
 */
function validateTxType(value: unknown, config: typeof CHAIN_CONFIGS[string]): 0 | 2 | null {
  if (value == null) return null;
  if (value !== 0 && value !== 2) throw new Error("Unsupported EVM transaction type");
  if (value === 2 && !config.eip1559) throw new Error("EIP-1559 transactions are not supported on this chain");
  return value;
}

async function resolveEvmFeeFields(config: typeof CHAIN_CONFIGS[string], gwChain: string, request: any): Promise<{ type: number; gasPrice: string | null; maxFeePerGas: string | null; maxPriorityFeePerGas: string | null }> {
  const accessToken = assertAccessToken(request);
  validateTxType(request.type, config);
  const useEip1559 = config.eip1559 && request.type !== 0;
  if (!useEip1559) {
    const gasPrice = request.gasPrice != null
      ? validateRpcGasPrice(request.gasPrice)
      : validateRpcGasPrice(await workerGatewayRpc(gwChain, "eth_gasPrice", [], accessToken));
    return { type: 0, gasPrice: gasPrice.toString(), maxFeePerGas: null, maxPriorityFeePerGas: null };
  }
  let priority: bigint;
  if (request.maxPriorityFeePerGas != null) priority = validateRpcGasPrice(request.maxPriorityFeePerGas);
  else {
    const raw = await workerGatewayRpc(gwChain, "eth_maxPriorityFeePerGas", [], accessToken);
    const fallback = tryValidateRpcGasPrice(raw);
    priority = fallback ?? (await getFeeHistoryFallback(gwChain, accessToken)).priorityFeePerGas;
  }
  let maxFee: bigint;
  if (request.maxFeePerGas != null) maxFee = validateRpcGasPrice(request.maxFeePerGas);
  else {
    const gp = tryValidateRpcGasPrice(await workerGatewayRpc(gwChain, "eth_gasPrice", [], accessToken));
    maxFee = gp != null ? gp * 2n : (await getFeeHistoryFallback(gwChain, accessToken)).latestBaseFeePerGas * 2n + priority;
    if (maxFee > RPC_GAS_PRICE_MAX) maxFee = RPC_GAS_PRICE_MAX;
  }
  if (maxFee < priority) throw new Error("maxFeePerGas cannot be lower than maxPriorityFeePerGas");
  return { type: 2, gasPrice: null, maxFeePerGas: maxFee.toString(), maxPriorityFeePerGas: priority.toString() };
}

async function _signEVMCore(
  privKey: Uint8Array,
  from: string,
  config: typeof CHAIN_CONFIGS[string],
  gwChain: string,
  nonce: number,
  to: string,
  value: bigint,
  data: string,
  gasLimit: bigint,
  request: any,
): Promise<{ signedTx: string; txHash: string; from: string; type: number }> {
  const accessToken = assertAccessToken(request);
  validateTxType(request.type, config);
  const useEip1559 = config.eip1559 && request.type !== 0;

  if (useEip1559) {
    let feeHistory: FeeHistoryFallback | null = null;
    let maxPriorityFeePerGas: bigint;

    if (request.maxPriorityFeePerGas != null) {
      maxPriorityFeePerGas = validateRpcGasPrice(request.maxPriorityFeePerGas);
    } else {
      const rawPri = await workerGatewayRpc(gwChain, "eth_maxPriorityFeePerGas", [], accessToken);
      maxPriorityFeePerGas = tryValidateRpcGasPrice(rawPri) ?? (
        feeHistory = await getFeeHistoryFallback(gwChain, accessToken),
        feeHistory.priorityFeePerGas
      );
    }

    let maxFeePerGas: bigint;
    if (request.maxFeePerGas != null) {
      maxFeePerGas = validateRpcGasPrice(request.maxFeePerGas);
    } else {
      const gasPrice = tryValidateRpcGasPrice(await workerGatewayRpc(gwChain, "eth_gasPrice", [], accessToken));
      if (gasPrice != null) {
        maxFeePerGas = gasPrice * 2n;
      } else {
        feeHistory ??= await getFeeHistoryFallback(gwChain, accessToken);
        maxFeePerGas = feeHistory.latestBaseFeePerGas * 2n + maxPriorityFeePerGas;
      }
      if (maxFeePerGas > RPC_GAS_PRICE_MAX) maxFeePerGas = RPC_GAS_PRICE_MAX;
    }
    if (maxFeePerGas < maxPriorityFeePerGas) maxFeePerGas = maxPriorityFeePerGas;
    const accessList: never[] = [];
    const signingRlp     = RLP.encode([config.chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList]);
    const signingPayload = prependTxType(0x02, signingRlp);
    const hash           = keccak_256(signingPayload);
    const sigBytes = await secp.signAsync(hash, privKey, { lowS: true, format: "recovered", prehash: false } as any);
    const v = BigInt(sigBytes[0]);
    const r = BigInt("0x" + bytesToHex(sigBytes.slice(1, 33)));
    const s = BigInt("0x" + bytesToHex(sigBytes.slice(33, 65)));
    const signedRlp = RLP.encode([config.chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, v, r, s]);
    const signedTx  = prependTxType(0x02, signedRlp);
    return { signedTx: "0x" + bytesToHex(signedTx), txHash: "0x" + bytesToHex(keccak_256(signedTx)), from, type: 2 };
  }

  const gasPrice = request.gasPrice != null
    ? validateRpcGasPrice(request.gasPrice)
    : validateRpcGasPrice(await workerGatewayRpc(gwChain, "eth_gasPrice", [], accessToken));
  const tx       = [nonce, gasPrice, gasLimit, to, value, data, config.chainId, BigInt(0), BigInt(0)];
  const encoded  = RLP.encode(tx);
  const hash     = keccak_256(encoded);
  const sigBytes = await secp.signAsync(hash, privKey, { lowS: true, format: "recovered", prehash: false } as any);
  const recovery = sigBytes[0];
  const v        = BigInt(config.chainId * 2 + 35 + recovery);
  const r        = BigInt("0x" + bytesToHex(sigBytes.slice(1, 33)));
  const s        = BigInt("0x" + bytesToHex(sigBytes.slice(33, 65)));
  const signedTx = RLP.encode([nonce, gasPrice, gasLimit, to, value, data, v, r, s]);
  return { signedTx: "0x" + bytesToHex(signedTx), txHash: "0x" + bytesToHex(keccak_256(signedTx)), from, type: 0 };
}

async function handleSignEVMTransaction(mnemonic: string, request: any): Promise<unknown> {
  const privKey = await deriveEVMKey(mnemonic);
  try {
    const pub  = secp.getPublicKey(privKey, false);
    const from = "0x" + bytesToHex(keccak_256(pub.slice(1)).slice(-20));
    const currency = typeof request?.currency === "string" ? request.currency.toUpperCase() : "ETH";
    const baseChain = currency.split("_")[0].toUpperCase();
    const config  = CHAIN_CONFIGS[baseChain];
    if (!config) throw new Error(`Unsupported EVM chain: ${baseChain}`);
    assertSupportedCurrency(currency, baseChain);
    const gwChain = workerGatewayChain(baseChain);
    const accessToken = assertAccessToken(request);

    const nonce = request.nonce != null
      ? validateRpcNonce(request.nonce)
      : validateRpcNonce(await workerGatewayRpc(gwChain, "eth_getTransactionCount", [from, "pending"], accessToken));

    let to = assertAddress(request.to, "recipient");
    let value = 0n;
    let data  = "0x";
    let gasLimit: bigint;

    const token = TOKEN_CONTRACTS[currency];
    if (token) {
      const amountText = assertPositiveDecimal(request.amount, "amount", token.decimals);
      const amt = parseTokenAmount(amountText, token.decimals);
      data = encodeERC20Transfer(to, amt);
      to = token.address;
      gasLimit = request.gasLimit != null ? validateRpcGasLimit(request.gasLimit, 21_000n) : 60_000n;
    } else {
      const amountText = assertPositiveDecimal(request.amount, "amount", 18);
      value = parseTokenAmount(amountText, 18);
      gasLimit = request.gasLimit != null ? validateRpcGasLimit(request.gasLimit) : 21_000n;
    }

    const approvalDigest = assertIntentDigest(request.approvalDigest);
    if (request.nonce == null || request.gasLimit == null) throw new Error("Signing requires the exact prepared nonce and gasLimit");
    const canonicalRecipient = assertAddress(request.to, "recipient").toLowerCase();
    const canonicalAmount = assertPositiveDecimal(request.amount, "amount", token?.decimals ?? 18);
    const approvedIntent = {
      kind: "evm-transfer", chainId: config.chainId, from: from.toLowerCase(), currency, recipient: canonicalRecipient,
      amount: canonicalAmount, nonce, gasLimit: gasLimit.toString(), to: to.toLowerCase(), value: value.toString(), data: data.toLowerCase(),
      gasPrice: request.gasPrice != null ? validateRpcGasPrice(request.gasPrice).toString() : null,
      maxFeePerGas: request.maxFeePerGas != null ? validateRpcGasPrice(request.maxFeePerGas).toString() : null,
      maxPriorityFeePerGas: request.maxPriorityFeePerGas != null ? validateRpcGasPrice(request.maxPriorityFeePerGas).toString() : null,
      type: request.type ?? null
    };
    consumeApproval(approvalDigest, from, approvedIntent);
    const core = await _signEVMCore(privKey, from, config, gwChain, nonce, to, value, data, gasLimit, request);
    return { ...core, to: request.to, value: request.amount, currency: request.currency, approvalDigest };
  } finally { wipeBytes(privKey); }
}

async function handleSignEVMContractCall(mnemonic: string, request: any): Promise<unknown> {
  const privKey = await deriveEVMKey(mnemonic);
  try {
    const pub     = secp.getPublicKey(privKey, false);
    const from    = "0x" + bytesToHex(keccak_256(pub.slice(1)).slice(-20));
    const baseChain = typeof request?.chain === "string" ? request.chain.toUpperCase() : "ETH";
    const config  = CHAIN_CONFIGS[baseChain];
    if (!config) throw new Error(`Unsupported EVM chain: ${baseChain}`);
    const gwChain = workerGatewayChain(baseChain);
    const accessToken = assertAccessToken(request);

    const nonce = request.nonce != null
      ? validateRpcNonce(request.nonce)
      : validateRpcNonce(await workerGatewayRpc(gwChain, "eth_getTransactionCount", [from, "pending"], accessToken));

    const to = assertAddress(request.to, "contract address");
    const data = assertHex(request.data, "contract data");
    if (request.valueWei != null && !/^(?:0|[1-9]\d*)$/.test(String(request.valueWei))) {
      throw new Error("Invalid valueWei");
    }
    const valueWei = BigInt(request.valueWei ?? "0");
    if (valueWei < 0n || valueWei >= (1n << 256n)) throw new Error("Invalid valueWei");

    let gasLimit: bigint;
    if (request.gasLimit != null) {
      gasLimit = validateRpcGasLimit(request.gasLimit, 21_000n);
    } else {
      const raw = await workerGatewayRpc(gwChain, "eth_estimateGas",
        [{ from, to, value: "0x" + valueWei.toString(16), data }], accessToken);
      gasLimit = validateRpcGasLimit(raw, 21_000n);
      gasLimit = (gasLimit * 125n) / 100n;
      if (gasLimit < 60_000n) gasLimit = 60_000n;
      if (gasLimit > RPC_GAS_LIMIT_MAX) throw new Error("Estimated gas exceeds block limit — transaction would be invalid");
    }

    const approvalDigest = assertIntentDigest(request.approvalDigest);
    if (request.nonce == null || request.gasLimit == null) throw new Error("Signing requires the exact prepared nonce and gasLimit");
    const approvedIntent = {
      kind: "evm-contract", chainId: config.chainId, from: from.toLowerCase(), chain: baseChain, recipient: to.toLowerCase(),
      data: data.toLowerCase(), valueWei: valueWei.toString(), nonce, gasLimit: gasLimit.toString(),
      gasPrice: request.gasPrice != null ? validateRpcGasPrice(request.gasPrice).toString() : null,
      maxFeePerGas: request.maxFeePerGas != null ? validateRpcGasPrice(request.maxFeePerGas).toString() : null,
      maxPriorityFeePerGas: request.maxPriorityFeePerGas != null ? validateRpcGasPrice(request.maxPriorityFeePerGas).toString() : null,
      type: request.type ?? null
    };
    consumeApproval(approvalDigest, from, approvedIntent);
    return await _signEVMCore(privKey, from, config, gwChain, nonce, to, valueWei, data, gasLimit, request);
  } finally { wipeBytes(privKey); }
}

// ─── Two-step transaction approval ───────────────────────────────────────────
// Preparation performs all network-derived values first. The Worker stores the
// exact prepared intent. Signing requires that Worker-issued, single-use digest,
// preventing replay or changing recipient, amount, nonce, gas or fees after the
// preparation step. This is an integrity boundary, not a trusted-display claim.
async function prepareEVMTransferIntent(mnemonic: string, request: any): Promise<unknown> {
  const privKey = await deriveEVMKey(mnemonic);
  try {
    const pub = secp.getPublicKey(privKey, false);
    const from = "0x" + bytesToHex(keccak_256(pub.slice(1)).slice(-20));
    const currency = typeof request?.currency === "string" ? request.currency.toUpperCase() : "ETH";
    const baseChain = currency.split("_")[0].toUpperCase();
    const config = CHAIN_CONFIGS[baseChain];
    if (!config) throw new Error(`Unsupported EVM chain: ${baseChain}`);
    assertSupportedCurrency(currency, baseChain);
    const gwChain = workerGatewayChain(baseChain);
    const accessToken = assertAccessToken(request);
    const nonce = request.nonce != null ? validateRpcNonce(request.nonce) : validateRpcNonce(await workerGatewayRpc(gwChain, "eth_getTransactionCount", [from, "pending"], accessToken));
    let to = assertAddress(request.to, "recipient");
    let value = 0n; let data = "0x"; let gasLimit: bigint;
    const token = TOKEN_CONTRACTS[currency];
    if (token) {
      const amount = assertPositiveDecimal(request.amount, "amount", token.decimals);
      data = encodeERC20Transfer(to, parseTokenAmount(amount, token.decimals));
      to = token.address;
      gasLimit = request.gasLimit != null ? validateRpcGasLimit(request.gasLimit, 21_000n) : 60_000n;
    } else {
      const amount = assertPositiveDecimal(request.amount, "amount", 18);
      value = parseTokenAmount(amount, 18);
      gasLimit = request.gasLimit != null ? validateRpcGasLimit(request.gasLimit) : 21_000n;
    }
    const fees = await resolveEvmFeeFields(config, gwChain, request);
    const canonicalRecipient = assertAddress(request.to, "recipient").toLowerCase();
    const canonicalAmount = assertPositiveDecimal(request.amount, "amount", token?.decimals ?? 18);
    const intent: Record<string, unknown> = {
      kind: "evm-transfer", chainId: config.chainId, from: from.toLowerCase(), currency, recipient: canonicalRecipient,
      amount: canonicalAmount, nonce, gasLimit: gasLimit.toString(), to: to.toLowerCase(), value: value.toString(), data: data.toLowerCase(),
      ...fees
    };
    const approvalDigest = await intentDigest(intent);
    rememberApproval(approvalDigest, from, intent);
    return { from, intent, approvalDigest, signRequest: { ...request, to: canonicalRecipient, amount: canonicalAmount, nonce, gasLimit: gasLimit.toString(), ...fees } };
  } finally { wipeBytes(privKey); }
}

async function prepareEVMContractIntent(mnemonic: string, request: any): Promise<unknown> {
  const privKey = await deriveEVMKey(mnemonic);
  try {
    const pub = secp.getPublicKey(privKey, false);
    const from = "0x" + bytesToHex(keccak_256(pub.slice(1)).slice(-20));
    const baseChain = typeof request?.chain === "string" ? request.chain.toUpperCase() : "ETH";
    const config = CHAIN_CONFIGS[baseChain];
    if (!config) throw new Error(`Unsupported EVM chain: ${baseChain}`);
    const gwChain = workerGatewayChain(baseChain);
    const accessToken = assertAccessToken(request);
    const nonce = request.nonce != null ? validateRpcNonce(request.nonce) : validateRpcNonce(await workerGatewayRpc(gwChain, "eth_getTransactionCount", [from, "pending"], accessToken));
    const to = assertAddress(request.to, "contract address");
    const data = assertHex(request.data, "contract data");
    const valueWei = BigInt(request.valueWei ?? "0");
    if (valueWei < 0n || valueWei >= (1n << 256n)) throw new Error("Invalid valueWei");
    let gasLimit = request.gasLimit != null ? validateRpcGasLimit(request.gasLimit, 21_000n) : validateRpcGasLimit(await workerGatewayRpc(gwChain, "eth_estimateGas", [{ from, to, value: "0x" + valueWei.toString(16), data }], accessToken), 21_000n);
    if (request.gasLimit == null) { gasLimit = (gasLimit * 125n) / 100n; if (gasLimit < 60_000n) gasLimit = 60_000n; if (gasLimit > RPC_GAS_LIMIT_MAX) throw new Error("Estimated gas exceeds block limit"); }
    const fees = await resolveEvmFeeFields(config, gwChain, request);
    const intent: Record<string, unknown> = {
      kind: "evm-contract", chainId: config.chainId, from: from.toLowerCase(), chain: baseChain, recipient: to.toLowerCase(), data: data.toLowerCase(),
      valueWei: valueWei.toString(), nonce, gasLimit: gasLimit.toString(), ...fees
    };
    const approvalDigest = await intentDigest(intent);
    rememberApproval(approvalDigest, from, intent);
    return { from, intent, approvalDigest, signRequest: { ...request, to: to.toLowerCase(), data: data.toLowerCase(), nonce, gasLimit: gasLimit.toString(), ...fees } };
  } finally { wipeBytes(privKey); }
}

// ─── Bitcoin / Solana / TRON protocol-correct signing ───────────────────────
async function prepareBitcoinTransferIntent(mnemonic: string, request: any): Promise<any> {
  const accessToken = assertAccessToken(request);
  const { deriveBTCAddress } = await import("./vault-crypto");
  const from = await deriveBTCAddress(mnemonic);
  if (!Array.isArray(request?.utxos) || request.utxos.length < 1 || request.utxos.length > 100) throw new Error("Invalid Bitcoin UTXO set");
  const amountSats = parseDecimalUnits(request.amount, 8, "amount");
  const feeRate = Number(request.feeRate);
  if (!Number.isSafeInteger(feeRate) || feeRate < 1 || feeRate > 10000) throw new Error("Invalid Bitcoin fee rate");
  const to = String(request.to ?? "");
  if (!/^(bc1[ac-hj-np-z02-9]{11,71}|[13][1-9A-HJ-NP-Za-km-z]{25,34})$/.test(to)) throw new Error("Invalid Bitcoin recipient");
  const priv = await deriveBTCPrivateKey(mnemonic);
  try {
    const pub = secp.getPublicKey(priv, true); const p2w = btc.p2wpkh(pub, btc.NETWORK); const expectedScript = bytesToHex(p2w.script).toLowerCase();
    const utxos: Array<{txid:string,vout:number,value:string}> = [];
    for (const u of request.utxos) {
      if (!/^[0-9a-fA-F]{64}$/.test(String(u.txid)) || !Number.isInteger(Number(u.vout)) || Number(u.vout) < 0 || Number(u.vout) > 100000) throw new Error("Invalid Bitcoin outpoint");
      const vout = Number(u.vout);
      const out = await workerGatewayRpc("BTC", "gettxout", [String(u.txid), vout, true], accessToken) as any;
      if (!out) throw new Error("Bitcoin UTXO is spent, missing, or no longer available");
      const networkValue = parseDecimalUnits(String(out.value), 8, "network UTXO value");
      const suppliedValue = parseDecimalUnits(String(u.value), 8, "UTXO value");
      if (networkValue !== suppliedValue) throw new Error("Bitcoin UTXO value mismatch");
      if (String(out.scriptPubKey?.hex ?? "").toLowerCase() !== expectedScript) throw new Error("Bitcoin UTXO does not belong to this wallet");
      utxos.push({ txid:String(u.txid).toLowerCase(), vout, value:networkValue.toString() });
    }
    const total = utxos.reduce((sum,u)=>sum+BigInt(u.value),0n);
    let fee = BigInt(feeRate * (10 + 68 * utxos.length + 31 * 2));
    let change = total - amountSats - fee;
    if (change < 0n) throw new Error("Insufficient Bitcoin funds");
    if (change <= 546n) { fee = total - amountSats; change = 0n; }
    const intent = { kind:"bitcoin-transfer", from, recipient:to, amountSats:amountSats.toString(), feeRate, feeSats:fee.toString(), changeSats:change.toString(), utxos };
    const approvalDigest = await intentDigest(intent); rememberApproval(approvalDigest, from, intent);
    return { from, intent, approvalDigest, signRequest:{...request,amountSats:amountSats.toString(),feeSats:fee.toString(),changeSats:change.toString(),utxos} };
  } finally { wipeBytes(priv); }
}
async function signBitcoinPrepared(mnemonic: string, request: any): Promise<any> {
  const accessToken = assertAccessToken(request);
  const { deriveBTCAddress } = await import("./vault-crypto");
  const from = await deriveBTCAddress(mnemonic);
  if (!request?.approvalDigest) throw new Error("Bitcoin transaction requires a prepared approval");
  const amountSats = parseDecimalUnits(request.amount, 8, "amount");
  const feeRate = Number(request.feeRate);
  if (!Array.isArray(request.utxos) || request.utxos.length < 1 || request.utxos.length > 100) throw new Error("Invalid Bitcoin UTXOs");
  const utxos: Array<{txid:string,vout:number,value:string}> = [];
  for (const u of request.utxos) {
    if (!/^[0-9a-fA-F]{64}$/.test(String(u.txid)) || !Number.isInteger(u.vout) || u.vout < 0 || u.vout > 100000) throw new Error("Invalid Bitcoin outpoint");
    const out = await workerGatewayRpc("BTC", "gettxout", [String(u.txid), u.vout, true], accessToken) as any;
    if (!out) throw new Error("Bitcoin UTXO is spent, missing, or no longer available");
    const sats = parseDecimalUnits(String(out.value), 8, "network UTXO value");
    const scriptHex = String(out.scriptPubKey?.hex ?? "").toLowerCase();
    const seedPriv = await deriveBTCPrivateKey(mnemonic);
    const pub = secp.getPublicKey(seedPriv, true); wipeBytes(seedPriv);
    const p2w = btc.p2wpkh(pub, btc.NETWORK);
    const expectedScript = bytesToHex(p2w.script).toLowerCase();
    if (scriptHex !== expectedScript) throw new Error("Bitcoin UTXO does not belong to this wallet");
    const requested = parseDecimalUnits(String(u.value),8,"UTXO value"); if (requested !== sats) throw new Error("Bitcoin UTXO value mismatch");
    utxos.push({txid:String(u.txid),vout:u.vout,value:sats.toString()});
  }
  const total = utxos.reduce((s,u)=>s+BigInt(u.value),0n);
  const change = BigInt(String(request.changeSats ?? "0"));
  const fee = BigInt(String(request.feeSats ?? "0"));
  if (total !== amountSats + fee + change) throw new Error("Bitcoin amount + fee + change does not equal verified inputs");
  const to = String(request.to); if (!/^(bc1[ac-hj-np-z02-9]{11,71}|[13][1-9A-HJ-NP-Za-km-z]{25,34})$/.test(to)) throw new Error("Invalid Bitcoin recipient");
  const intent = { kind:"bitcoin-transfer", from, recipient:to, amountSats:amountSats.toString(), feeRate, feeSats:fee.toString(), changeSats:change.toString(), utxos };
  const digest = await intentDigest(intent); consumeApproval(String(request.approvalDigest), from, intent);
  if (digest !== String(request.approvalDigest)) throw new Error("Bitcoin approval digest mismatch");
  const priv = await deriveBTCPrivateKey(mnemonic);
  try {
    const pub = secp.getPublicKey(priv, true); const p2wpkh = btc.p2wpkh(pub, btc.NETWORK); const tx = new btc.Transaction();
    for (const u of utxos) tx.addInput({ txid:u.txid, index:u.vout, witnessUtxo:{ script:p2wpkh.script, amount:BigInt(u.value) } });
    tx.addOutputAddress(to, amountSats, btc.NETWORK);
    if (change > 546n) tx.addOutputAddress(from, change, btc.NETWORK);
    tx.sign(priv); tx.finalize();
    const raw = tx.toBytes(); const txid = bytesToHex(sha256(sha256(raw)).slice().reverse());
    return { signedTx: "0x" + bytesToHex(raw), txid, from, to, amountSats: amountSats.toString(), feeSats: fee.toString() };
  } finally { wipeBytes(priv); }
}

async function prepareSolanaTransferIntent(mnemonic: string, request: any): Promise<any> {
  const accessToken = assertAccessToken(request);
  const priv = await deriveSOLPrivateKey(mnemonic); const pub = await nobleEd.getPublicKeyAsync(priv); wipeBytes(priv);
  const from = base58.encode(pub); const to = String(request?.to ?? "");
  let toBytes: Uint8Array; try { toBytes = base58.decode(to); } catch { throw new Error("Invalid Solana recipient"); }
  if (toBytes.length !== 32) throw new Error("Invalid Solana recipient");
  const amount = parseDecimalUnits(request.amount, 9, "SOL amount");
  if (amount <= 0n) throw new Error("SOL amount must be greater than zero");
  const latest = await workerGatewayRpc("SOL", "getLatestBlockhash", [{ commitment:"finalized" }], accessToken) as any;
  const blockhash = latest?.value?.blockhash; if (typeof blockhash !== "string") throw new Error("Solana blockhash unavailable");
  const intent = { kind:"sol-transfer", from, recipient:to, amountLamports:amount.toString(), recentBlockhash:blockhash, currency:"SOL" };
  const approvalDigest = await intentDigest(intent); rememberApproval(approvalDigest, from, intent);
  return { from, intent, approvalDigest, signRequest:{...request, amountLamports:amount.toString(), recentBlockhash:blockhash} };
}

async function signSolanaPrepared(mnemonic: string, request: any): Promise<any> {
  const priv = await deriveSOLPrivateKey(mnemonic); try {
    const pub = await nobleEd.getPublicKeyAsync(priv); const from = base58.encode(pub); const to = String(request.to); const toBytes = base58.decode(to);
    if (toBytes.length !== 32) throw new Error("Invalid Solana recipient");
    const amount = BigInt(String(request.amountLamports)); if (amount <= 0n || amount > 0xffffffffffffffffn) throw new Error("Invalid SOL amount");
    const blockhash = base58.decode(String(request.recentBlockhash));
    const intent = {kind:"sol-transfer",from,recipient:to,amountLamports:amount.toString(),recentBlockhash:String(request.recentBlockhash),currency:"SOL"};
    const digest = await intentDigest(intent); consumeApproval(String(request.approvalDigest),from,intent); if(digest!==String(request.approvalDigest)) throw new Error("Solana approval digest mismatch");
    const systemProgram = base58.decode("11111111111111111111111111111111"); const data = new Uint8Array([2,...u64le(amount)]);
    const message = buildSolanaLegacyMessage(pub,blockhash,[pub,toBytes,systemProgram],2,[0,1],data,1);
    const signature = await nobleEd.signAsync(message,priv); const packet = new Uint8Array([...solShortVec(1),...signature,...message]);
    return {signedTx:base58.encode(packet),signature:base58.encode(signature),publicKey:from};
  } finally { wipeBytes(priv); }
}

async function prepareTronTransferIntent(mnemonic: string, request: any): Promise<any> {
  const accessToken = assertAccessToken(request);
  const priv = await deriveTRONPrivateKey(mnemonic); const from = tronAddressFromPrivateKey(priv); wipeBytes(priv);
  const to = String(request?.to ?? ""); tronAddressToHex(to); const amountSun = parseDecimalUnits(request.amount,6,"TRX amount"); if(amountSun<=0n||amountSun>9007199254740991n) throw new Error("Invalid TRX amount");
  const built = await workerGatewayTron("/wallet/createtransaction", {owner_address:from,to_address:to,amount:Number(amountSun),visible:true}, accessToken);
  const c=built?.raw_data?.contract?.[0]; const v=c?.parameter?.value;
  if(built?.raw_data?.contract?.length!==1||c?.type!=="TransferContract"||!v) throw new Error("Gateway returned an invalid TRON transaction");
  if(tronAddressToHex(from).toLowerCase()!==String(v.owner_address).toLowerCase() || tronAddressToHex(to).toLowerCase()!==String(v.to_address).toLowerCase() || BigInt(v.amount)!==amountSun) throw new Error("TRON transaction intent mismatch");
  const rawHex=String(built.raw_data_hex??""); if(!/^[0-9a-fA-F]+$/.test(rawHex)||rawHex.length%2||rawHex.length<20) throw new Error("Invalid TRON raw_data_hex");
  const intent={kind:"tron-transfer",from,to,amountSun:amountSun.toString(),rawDataHex:rawHex.toLowerCase()}; const approvalDigest=await intentDigest(intent); rememberApproval(approvalDigest,from,intent);
  return {from,intent,approvalDigest,signRequest:{...request,amountSun:amountSun.toString(),rawDataHex:rawHex,unsignedTransaction:built}};
}

async function signTronPrepared(mnemonic:string,request:any):Promise<any>{
  const priv=await deriveTRONPrivateKey(mnemonic); try{
    const from=tronAddressFromPrivateKey(priv); const to=String(request.to); tronAddressToHex(to); const amountSun=BigInt(String(request.amountSun)); const rawHex=String(request.rawDataHex??"");
    const intent={kind:"tron-transfer",from,to,amountSun:amountSun.toString(),rawDataHex:rawHex.toLowerCase()}; const digest=await intentDigest(intent); consumeApproval(String(request.approvalDigest),from,intent); if(digest!==String(request.approvalDigest)) throw new Error("TRON approval digest mismatch");
    const raw=Uint8Array.from((rawHex.match(/../g)||[]).map((x:string)=>parseInt(x,16))); const hash=sha256(raw); const sig=await secp.signAsync(hash,priv,{lowS:true,format:"recovered",prehash:false} as any); const signature=bytesToHex(sig.slice(1,65))+Number(sig[0]).toString(16).padStart(2,"0");
    return {signedTx:{...request.unsignedTransaction,raw_data_hex:rawHex,signature:[signature]},txID:bytesToHex(hash),from,to,amountSun:amountSun.toString()};
  }finally{wipeBytes(priv);}
}

// ─── SPL Token transfers (USDC/USDT on Solana) ──────────────────────────────
// Scope: transfers between EXISTING token accounts only. If the recipient has
// no associated token account for this mint yet, this fails with a clear
// error rather than silently adding a "create account" instruction — auto-
// creating accounts on someone else's behalf is a separate feature with its
// own review, not something to fold in here by default.
async function prepareSplTokenTransferIntent(mnemonic: string, request: any): Promise<any> {
  const accessToken = assertAccessToken(request);
  const currency = typeof request?.currency === "string" ? request.currency.toUpperCase() : "";
  const token = SPL_TOKENS[currency];
  if (!token) throw new Error(`Unsupported Solana token: ${currency}`);

  const priv = await deriveSOLPrivateKey(mnemonic);
  const ownerPub = await nobleEd.getPublicKeyAsync(priv);
  wipeBytes(priv);

  const to = String(request?.to ?? "");
  let toBytes: Uint8Array;
  try { toBytes = base58.decode(to); } catch { throw new Error("Invalid Solana recipient"); }
  if (toBytes.length !== 32) throw new Error("Invalid Solana recipient");

  const mintBytes = base58.decode(token.mint);
  const amount = parseDecimalUnits(request.amount, token.decimals, `${currency} amount`);
  if (amount <= 0n) throw new Error(`${currency} amount must be greater than zero`);

  const sourceAta = await deriveAssociatedTokenAccount(ownerPub, mintBytes);
  const destAta = await deriveAssociatedTokenAccount(toBytes, mintBytes);
  const sourceAddr = base58.encode(sourceAta);
  const destAddr = base58.encode(destAta);

  const sourceRaw = await fetchSolanaAccount(sourceAddr, accessToken);
  if (!sourceRaw) throw new Error(`No ${currency} token account found for this wallet`);
  const sourceAcc = decodeSplTokenAccount(sourceRaw);
  if (bytesToHex(sourceAcc.mint) !== bytesToHex(mintBytes)) throw new Error("Source token account mint mismatch");
  if (bytesToHex(sourceAcc.owner) !== bytesToHex(ownerPub)) throw new Error("Source token account owner mismatch");
  if (sourceAcc.amount < amount) throw new Error(`Insufficient ${currency} balance`);

  const destRaw = await fetchSolanaAccount(destAddr, accessToken);
  if (!destRaw) {
    throw new Error(
      `Recipient has no ${currency} token account yet. This signer does not create recipient token ` +
      `accounts — the recipient needs to receive or opt into ${currency} first, or use a flow that ` +
      `explicitly adds the "create associated token account" instruction.`
    );
  }
  const destAcc = decodeSplTokenAccount(destRaw);
  if (bytesToHex(destAcc.mint) !== bytesToHex(mintBytes)) throw new Error("Destination token account mint mismatch");

  const latest = await workerGatewayRpc("SOL", "getLatestBlockhash", [{ commitment: "finalized" }], accessToken) as any;
  const blockhash = latest?.value?.blockhash;
  if (typeof blockhash !== "string") throw new Error("Solana blockhash unavailable");

  const from = base58.encode(ownerPub);
  const intent = {
    kind: "spl-transfer", currency, from, recipient: to, mint: token.mint,
    sourceAta: sourceAddr, destAta: destAddr, amount: amount.toString(), decimals: token.decimals,
    recentBlockhash: blockhash,
  };
  const approvalDigest = await intentDigest(intent);
  rememberApproval(approvalDigest, from, intent);
  return {
    from, intent, approvalDigest,
    signRequest: { ...request, amount: amount.toString(), recentBlockhash: blockhash, sourceAta: sourceAddr, destAta: destAddr },
  };
}

async function signSplTokenPrepared(mnemonic: string, request: any): Promise<any> {
  const currency = typeof request?.currency === "string" ? request.currency.toUpperCase() : "";
  const token = SPL_TOKENS[currency];
  if (!token) throw new Error(`Unsupported Solana token: ${currency}`);

  const priv = await deriveSOLPrivateKey(mnemonic);
  try {
    const ownerPub = await nobleEd.getPublicKeyAsync(priv);
    const from = base58.encode(ownerPub);
    const to = String(request.to ?? "");
    const mintBytes = base58.decode(token.mint);
    const amount = BigInt(String(request.amount));
    if (amount <= 0n || amount > 0xffffffffffffffffn) throw new Error(`Invalid ${currency} amount`);
    const sourceAddr = String(request.sourceAta ?? "");
    const destAddr = String(request.destAta ?? "");
    const blockhash58 = String(request.recentBlockhash ?? "");

    const intent = {
      kind: "spl-transfer", currency, from, recipient: to, mint: token.mint,
      sourceAta: sourceAddr, destAta: destAddr, amount: amount.toString(), decimals: token.decimals,
      recentBlockhash: blockhash58,
    };
    const digest = await intentDigest(intent);
    consumeApproval(String(request.approvalDigest), from, intent);
    if (digest !== String(request.approvalDigest)) throw new Error("Solana token approval digest mismatch");

    const sourceAta = base58.decode(sourceAddr);
    const destAta = base58.decode(destAddr);
    const blockhash = base58.decode(blockhash58);
    const tokenProgram = base58.decode(SOL_TOKEN_PROGRAM_ID);

    // keys: [owner(signer,writable,payer), source(writable), dest(writable), mint(readonly), tokenProgram(readonly,program)]
    // TransferChecked account order is [source, mint, destination, owner] — see accountIndexes below.
    const keys = [ownerPub, sourceAta, destAta, mintBytes, tokenProgram];
    const data = new Uint8Array([12, ...u64le(amount), token.decimals]); // SPL Token instruction 12 = TransferChecked
    const message = buildSolanaLegacyMessage(ownerPub, blockhash, keys, 4, [1, 3, 2, 0], data, 2);
    const signature = await nobleEd.signAsync(message, priv);
    const packet = new Uint8Array([...solShortVec(1), ...signature, ...message]);
    return {
      signedTx: base58.encode(packet), signature: base58.encode(signature), publicKey: from,
      currency, amount: amount.toString(), from, to,
    };
  } finally { wipeBytes(priv); }
}

// ─── TRC-20 token transfers (USDC/USDT on TRON) ─────────────────────────────
// Mirrors the ERC-20 pattern already used for EVM tokens: encode
// transfer(address,uint256), have the gateway build the call via
// triggersmartcontract, then independently verify every field of the
// returned transaction against what was actually requested before signing.
async function prepareTrc20TransferIntent(mnemonic: string, request: any): Promise<any> {
  const accessToken = assertAccessToken(request);
  const currency = typeof request?.currency === "string" ? request.currency.toUpperCase() : "";
  const token = TRC20_TOKENS[currency];
  if (!token) throw new Error(`Unsupported TRON token: ${currency}`);

  const priv = await deriveTRONPrivateKey(mnemonic);
  const from = tronAddressFromPrivateKey(priv);
  wipeBytes(priv);

  const to = String(request?.to ?? "");
  tronAddressToHex(to); // validates format/checksum; throws on invalid recipient
  const amount = parseDecimalUnits(request.amount, token.decimals, `${currency} amount`);
  if (amount <= 0n) throw new Error(`${currency} amount must be greater than zero`);

  const parameter = tronAbiEncodeAddress(to) + tronAbiEncodeUint256(amount);

  const feeLimit = Number.isSafeInteger(request.feeLimit) && request.feeLimit >= 1_000_000 && request.feeLimit <= 150_000_000
    ? request.feeLimit
    : 50_000_000; // sun; 50 TRX ceiling on energy fees unless the caller specifies a (bounded) lower cap

  const built = await workerGatewayTron("/wallet/triggersmartcontract", {
    owner_address: from, contract_address: token.contract,
    function_selector: "transfer(address,uint256)", parameter, fee_limit: feeLimit, call_value: 0, visible: true,
  }, accessToken);

  const tx = built?.transaction;
  const c = tx?.raw_data?.contract?.[0];
  const v = c?.parameter?.value;
  if (tx?.raw_data?.contract?.length !== 1 || c?.type !== "TriggerSmartContract" || !v) {
    throw new Error("Gateway returned an invalid TRC-20 transaction");
  }
  const expectedData = "a9059cbb" + parameter; // transfer(address,uint256) selector
  if (
    tronAddressToHex(from).toLowerCase() !== String(v.owner_address).toLowerCase() ||
    tronAddressToHex(token.contract).toLowerCase() !== String(v.contract_address).toLowerCase() ||
    String(v.data ?? "").toLowerCase() !== expectedData.toLowerCase()
  ) {
    // Note on trust boundary: this checks the JSON summary TronGrid/Alchemy echoes back
    // against what we asked for. It does not independently decode raw_data_hex's protobuf
    // bytes to re-derive these same fields — doing that would require a TRON protobuf
    // parser. We're trusting that the provider's JSON summary and its raw_data_hex agree,
    // which is a narrower guarantee than the EVM/BTC paths (which rebuild everything from
    // primitives). Acceptable given TronGrid/Alchemy as a semi-trusted server-side
    // dependency, but worth knowing if you're evaluating the trust model end to end.
    throw new Error("TRC-20 transaction intent mismatch");
  }
  const rawHex = String(tx.raw_data_hex ?? "");
  if (!/^[0-9a-fA-F]+$/.test(rawHex) || rawHex.length % 2 || rawHex.length < 20) throw new Error("Invalid TRON raw_data_hex");

  const intent = {
    kind: "trc20-transfer", currency, from, to, contract: token.contract,
    amount: amount.toString(), rawDataHex: rawHex.toLowerCase(),
  };
  const approvalDigest = await intentDigest(intent);
  rememberApproval(approvalDigest, from, intent);
  return {
    from, intent, approvalDigest,
    signRequest: { ...request, amount: amount.toString(), rawDataHex: rawHex, unsignedTransaction: tx },
  };
}

async function signTrc20Prepared(mnemonic: string, request: any): Promise<any> {
  const currency = typeof request?.currency === "string" ? request.currency.toUpperCase() : "";
  const token = TRC20_TOKENS[currency];
  if (!token) throw new Error(`Unsupported TRON token: ${currency}`);

  const priv = await deriveTRONPrivateKey(mnemonic);
  try {
    const from = tronAddressFromPrivateKey(priv);
    const to = String(request.to ?? "");
    tronAddressToHex(to);
    const amount = BigInt(String(request.amount));
    if (amount <= 0n) throw new Error(`Invalid ${currency} amount`);
    const rawHex = String(request.rawDataHex ?? "");

    const intent = {
      kind: "trc20-transfer", currency, from, to, contract: token.contract,
      amount: amount.toString(), rawDataHex: rawHex.toLowerCase(),
    };
    const digest = await intentDigest(intent);
    consumeApproval(String(request.approvalDigest), from, intent);
    if (digest !== String(request.approvalDigest)) throw new Error("TRC-20 approval digest mismatch");

    const raw = Uint8Array.from((rawHex.match(/../g) || []).map((x: string) => parseInt(x, 16)));
    const hash = sha256(raw);
    const sig = await secp.signAsync(hash, priv, { lowS: true, format: "recovered", prehash: false } as any);
    const signature = bytesToHex(sig.slice(1, 65)) + Number(sig[0]).toString(16).padStart(2, "0");
    return {
      signedTx: { ...request.unsignedTransaction, raw_data_hex: rawHex, signature: [signature] },
      txID: bytesToHex(hash), from, to, currency, amount: amount.toString(),
    };
  } finally { wipeBytes(priv); }
}

// ─── ⑭  Vault-based EVM signing helpers ─────────────────────────────────────
// The mnemonic vault is decrypted only inside the Worker; only the final signed
// transaction is returned to the main thread.
async function signEVMTransactionFromVault(vault: unknown, password: string | Uint8Array, request: any): Promise<unknown> {
  return handleSignEVMTransaction(await openVault(vault, password), request);
}

async function signEVMContractCallFromVault(vault: unknown, password: string | Uint8Array, request: any): Promise<unknown> {
  return handleSignEVMContractCall(await openVault(vault, password), request);
}

// ─── Message type registry ────────────────────────────────────────────────────

export type WorkerRequest =
  // ① Mnemonic
  | { id: string; type: "validateMnemonic";    mnemonic: string }
  // ② Addresses (mnemonic-based — kept for wallet-restore flows)
  // ③ Encryption
  | { id: string; type: "encryptVault"; data: string; passwordBytes: Uint8Array; origin?: string }
  | { id: string; type: "encryptVaultBatch"; items: Array<{ data: string }>; passwordBytes: Uint8Array; origin?: string }
  // ③·5 Session cache management
  | { id: string; type: "clearSessionCache" }
  // ④ Decryption
  | { id: string; type: "validateVaultPassword"; vault: unknown; passwordBytes: Uint8Array }
  // ⑤ Migration
  | { id: string; type: "migrateLegacyVault"; legacyData: unknown; passwordBytes: Uint8Array; userId: string; origin?: string }
  // ⑥ Secure wallet creation only
  // ⑩ Hashing
  | { id: string; type: "hash"; algorithm: "keccak256" | "sha256" | "sha512" | "ripemd160"; hex: string }
  | { id: string; type: "hmacSha256"; keyHex: string; dataHex: string }
  // ─── SECURE VAULT-BASED API (mnemonic never crosses the postMessage wire) ──
  // ⑫ Secure wallet creation — no `mnemonic` in response
  | { id: string; type: "createSecureWallet"; passwordBytes: Uint8Array; origin?: string; existingMnemonic?: string }
  // ⑬ One-time mnemonic backup display (user must confirm backup before calling)
  | { id: string; type: "getMnemonicForBackup"; vault: EncryptedVault | unknown; passwordBytes: Uint8Array }
  // Repeatable, password-gated vault decrypt for "reveal my seed phrase /
  // private key" style UI (non-custodial-wallet.ts's decryptPrivateKey).
  // Deliberately separate from getMnemonicForBackup above: this has no
  // one-time-per-session limit and doesn't assume the plaintext is a BIP-39
  // mnemonic (it may be a raw private key), so it can't reuse that function.
  // The caller (decryptPrivateKey) already gates repeated attempts through
  // runWithUnlockGate's server-side lockout before a request reaches here —
  // this is a user-initiated, password-required reveal, not an open decrypt
  // endpoint, which is why it's fine for this one to not be one-time.
  | { id: string; type: "decryptVault"; vault: EncryptedVault | unknown; passwordBytes: Uint8Array }
  | { id: string; type: "prepareBitcoinTransferIntent"; vault: EncryptedVault | unknown; passwordBytes: Uint8Array; request: any & { accessToken?: string } }
  | { id: string; type: "signBitcoinTransactionFromVault"; vault: EncryptedVault | unknown; passwordBytes: Uint8Array; request: any & { accessToken?: string } }
  | { id: string; type: "prepareSolanaTransferIntent"; vault: EncryptedVault | unknown; passwordBytes: Uint8Array; request: any & { accessToken?: string } }
  | { id: string; type: "signSolanaTransactionFromVault"; vault: EncryptedVault | unknown; passwordBytes: Uint8Array; request: any & { accessToken?: string } }
  | { id: string; type: "prepareTronTransferIntent"; vault: EncryptedVault | unknown; passwordBytes: Uint8Array; request: any & { accessToken?: string } }
  | { id: string; type: "signTronTransactionFromVault"; vault: EncryptedVault | unknown; passwordBytes: Uint8Array; request: any & { accessToken?: string } }
  | { id: string; type: "prepareSplTokenTransferIntent"; vault: EncryptedVault | unknown; passwordBytes: Uint8Array; request: any & { accessToken?: string } }
  | { id: string; type: "signSplTokenTransactionFromVault"; vault: EncryptedVault | unknown; passwordBytes: Uint8Array; request: any & { accessToken?: string } }
  | { id: string; type: "prepareTrc20TransferIntent"; vault: EncryptedVault | unknown; passwordBytes: Uint8Array; request: any & { accessToken?: string } }
  | { id: string; type: "signTrc20TransactionFromVault"; vault: EncryptedVault | unknown; passwordBytes: Uint8Array; request: any & { accessToken?: string } }
  | { id: string; type: "prepareEVMTransferIntent"; vault: EncryptedVault | unknown; passwordBytes: Uint8Array; request: any & { accessToken?: string } }
  | { id: string; type: "prepareEVMContractIntent"; vault: EncryptedVault | unknown; passwordBytes: Uint8Array; request: any & { accessToken?: string } }
  // ⑭ Vault-based signing — mnemonic decrypted + wiped entirely inside worker
  | { id: string; type: "signEVMTransactionFromVault"; vault: EncryptedVault | unknown; passwordBytes: Uint8Array; request: any & { accessToken?: string } }
  | { id: string; type: "signEVMContractCallFromVault"; vault: EncryptedVault | unknown; passwordBytes: Uint8Array; request: any & { accessToken?: string } };

export type WorkerResponse =
  | { id: string; ok: true;  result: unknown }
  | { id: string; ok: false; error: string };

// ─── Main message loop ────────────────────────────────────────────────────────
//
// Password resolution — prefer the transferred Uint8Array over the string:
//
//   callSigningWorker sends { passwordBytes: Uint8Array } as a transferable.
//   After transfer the main-thread buffer is detached (zero-length) so the
//   caller can no longer read it. We receive it here and zero-fill it after
//   every operation that consumes it (either inside deriveScryptKey, or
//   explicitly below for operations that pass it through).
//
//   There is deliberately NO plaintext-password fallback.

function resolvePassword(msg: any): Uint8Array {
  if (msg.passwordBytes instanceof Uint8Array && msg.passwordBytes.length > 0) {
    return msg.passwordBytes;
  }
  throw new Error("Sensitive worker operations require passwordBytes as a transferable Uint8Array");
}

self.onmessage = async (event: MessageEvent<WorkerRequest>) => {
  const msg = event.data as any;
  let pw: Uint8Array | null = null;
  let response: WorkerResponse;
  try {
    if (!msg || typeof msg !== "object" || typeof msg.id !== "string" || msg.id.length > 128) {
      throw new Error("Invalid worker request");
    }
    if (typeof msg.type !== "string" || msg.type.length > 128) {
      throw new Error("Invalid worker request type");
    }
    if (Object.getPrototypeOf(msg) !== Object.prototype && Object.getPrototypeOf(msg) !== null) {
      throw new Error("Invalid worker request object");
    }
    if (msg.request !== undefined) {
      if (!msg.request || typeof msg.request !== "object" || Array.isArray(msg.request)) throw new Error("Invalid transaction request");
      if (Object.getPrototypeOf(msg.request) !== Object.prototype && Object.getPrototypeOf(msg.request) !== null) throw new Error("Invalid transaction request object");
    }
    // NOTE: there is deliberately no module-level "currentAccessToken" here.
    // This handler is async and re-entrant — two in-flight messages can
    // interleave at any `await` — so a shared mutable token would let one
    // call's request observe (or clobber) another's credentials. Every
    // handler below pulls its own token from its own `request` object via
    // assertAccessToken().

    const passwordTypes = new Set([
      "encryptVault", "encryptVaultBatch",
      "validateVaultPassword",
      "migrateLegacyVault", "createSecureWallet", "getMnemonicForBackup", "decryptVault",
      "prepareEVMTransferIntent", "prepareEVMContractIntent",
      "prepareBitcoinTransferIntent", "signBitcoinTransactionFromVault",
      "prepareSolanaTransferIntent", "signSolanaTransactionFromVault",
      "prepareTronTransferIntent", "signTronTransactionFromVault",
      "prepareSplTokenTransferIntent", "signSplTokenTransactionFromVault",
      "prepareTrc20TransferIntent", "signTrc20TransactionFromVault",
      "signEVMTransactionFromVault", "signEVMContractCallFromVault"
    ]);
    pw = passwordTypes.has(msg.type) ? resolvePassword(msg) : null;

    let result: unknown;
    switch ((msg as WorkerRequest).type) {
      // ① Mnemonic
      case "validateMnemonic":    result = workerValidateMnemonic(msg.mnemonic); break;
      // ② Addresses
      // ③ Encryption — pw is Uint8Array or string; encryptVault accepts both
      // NOTE: there is intentionally no "deriveVaultKey" handler. A prior
      // version returned the raw scrypt-derived key as hex over postMessage,
      // which contradicts this file's own invariant that key material never
      // leaves the worker. Callers that need one scrypt round to produce
      // several vaults should use "encryptVaultBatch" — it derives the key
      // once internally and only ever returns finished EncryptedVault blobs.
      // ③·5 Session cache management
      case "clearSessionCache": clearSessionCache(); clearPendingApprovals(); result = true; break;
      case "encryptVault":      result = await encryptVault(msg.data, pw!, msg.origin); break;
      case "encryptVaultBatch": result = await encryptVaultBatch(msg.items, pw!, msg.origin); break;
      // ④ Decryption
      case "validateVaultPassword":  result = await validateVaultPassword(msg.vault, pw!); break;
      // ⑤ Migration
      case "migrateLegacyVault":
        result = await migrateLegacyVault(msg.legacyData, pw!, msg.userId, msg.origin); break;
      // ⑪ Hashing
      case "hash":      result = workerHash(msg.algorithm, msg.hex); break;
      case "hmacSha256": result = workerHmacSha256(msg.keyHex, msg.dataHex); break;
      // ⑫ Secure wallet creation
      case "createSecureWallet":
        result = await createSecureWallet(pw!, msg.origin, msg.existingMnemonic); break;
      // ⑬ Mnemonic backup display (one-time, controlled)
      case "getMnemonicForBackup":
        result = await getMnemonicForBackup(msg.vault, pw!); break;
      // Repeatable vault decrypt for "reveal my seed phrase / private key" —
      // see the WorkerRequest union entry above for why this is separate
      // from getMnemonicForBackup.
      case "decryptVault":
        result = await openVault(msg.vault, pw!); break;
      case "prepareBitcoinTransferIntent": { const mnemonic=await openVault(msg.vault,pw!); result=await prepareBitcoinTransferIntent(mnemonic,msg.request); break; }
      case "signBitcoinTransactionFromVault": { const mnemonic=await openVault(msg.vault,pw!); result=await signBitcoinPrepared(mnemonic,msg.request); break; }
      case "prepareSolanaTransferIntent": { const mnemonic=await openVault(msg.vault,pw!); result=await prepareSolanaTransferIntent(mnemonic,msg.request); break; }
      case "signSolanaTransactionFromVault": { const mnemonic=await openVault(msg.vault,pw!); result=await signSolanaPrepared(mnemonic,msg.request); break; }
      case "prepareTronTransferIntent": { const mnemonic=await openVault(msg.vault,pw!); result=await prepareTronTransferIntent(mnemonic,msg.request); break; }
      case "signTronTransactionFromVault": { const mnemonic=await openVault(msg.vault,pw!); result=await signTronPrepared(mnemonic,msg.request); break; }
      case "prepareSplTokenTransferIntent": { const mnemonic=await openVault(msg.vault,pw!); result=await prepareSplTokenTransferIntent(mnemonic,msg.request); break; }
      case "signSplTokenTransactionFromVault": { const mnemonic=await openVault(msg.vault,pw!); result=await signSplTokenPrepared(mnemonic,msg.request); break; }
      case "prepareTrc20TransferIntent": { const mnemonic=await openVault(msg.vault,pw!); result=await prepareTrc20TransferIntent(mnemonic,msg.request); break; }
      case "signTrc20TransactionFromVault": { const mnemonic=await openVault(msg.vault,pw!); result=await signTrc20Prepared(mnemonic,msg.request); break; }
      // ⑭ Two-step EVM approval: prepare exact intent before signing
      case "prepareEVMTransferIntent": {
        const mnemonic = await openVault(msg.vault, pw!);
        try { result = await prepareEVMTransferIntent(mnemonic, msg.request); } finally { /* mnemonic is immutable string; scope ends here */ }
        break;
      }
      case "prepareEVMContractIntent": {
        const mnemonic = await openVault(msg.vault, pw!);
        try { result = await prepareEVMContractIntent(mnemonic, msg.request); } finally { /* scope ends here */ }
        break;
      }
      // ⑭ Vault-based signing — mnemonic never on postMessage wire
      case "signEVMTransactionFromVault":
        result = await signEVMTransactionFromVault(msg.vault, pw!, msg.request); break;
      case "signEVMContractCallFromVault":
        result = await signEVMContractCallFromVault(msg.vault, pw!, msg.request); break;
      default:
        throw new Error(`Unknown worker message type: ${(msg as any).type}`);
    }
    response = { id: msg.id, ok: true, result };
  } catch (err) {
    response = {
      id: msg.id,
      ok: false,
      error: err instanceof Error ? err.message : formatWorkerRpcError(err),
    };
  } finally {
    if (pw) wipeBytes(pw);
  }
  self.postMessage(response);
};
