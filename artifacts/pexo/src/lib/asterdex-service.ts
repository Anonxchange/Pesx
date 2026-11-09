import { supabase } from "@/lib/supabase";
import * as secp from "@noble/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex } from "@noble/hashes/utils";
import { mnemonicToSeed } from "@scure/bip39";
import { HDKey } from "@scure/bip32";

// ── Types ──────────────────────────────────────────────

export interface Ticker24h {
  symbol: string;
  priceChange: string;
  priceChangePercent: string;
  lastPrice: string;
  highPrice: string;
  lowPrice: string;
  volume: string;
  quoteVolume: string;
}

export interface TickerPrice {
  symbol: string;
  price: string;
}

export interface OrderBookEntry {
  price: string;
  qty: string;
}

export interface OrderBook {
  bids: [string, string][];
  asks: [string, string][];
  lastUpdateId: number;
}

export interface Kline {
  openTime: number;
  open: string;
  high: string;
  low: string;
  close: string;
  volume: string;
  closeTime: number;
}

export interface SpotBalance {
  asset: string;
  free: string;
  locked: string;
}

export interface FuturesPosition {
  symbol: string;
  positionAmt: string;
  entryPrice: string;
  markPrice: string;
  unRealizedProfit: string;
  liquidationPrice: string;
  leverage: string;
  marginType: string;
  positionSide: string;
  notional: string;
}

export interface FuturesBalance {
  asset: string;
  balance: string;
  availableBalance: string;
  crossUnPnl: string;
}

export interface OrderResult {
  orderId: number;
  symbol: string;
  status: string;
  type: string;
  side: string;
  price: string;
  origQty: string;
  executedQty: string;
  transactTime: number;
}

export interface FundingRate {
  symbol: string;
  fundingRate: string;
  fundingTime: number;
  markPrice: string;
}

export interface DepositAddress {
  address: string;
  coin: string;
  tag: string;
  url: string;
  network: string;
}

// The edge function's public deposit-address branch returns ONLY these three
// fields ({ address, coin, network }) — it never proxies Binance's richer
// DepositAddress shape. Use this type for asterWallet.depositAddress results.
export interface AsterDepositAddress {
  address: string;
  coin?: string;
  network?: string;
}

export interface DepositRecord {
  amount: string;
  coin: string;
  network: string;
  status: number;
  txId: string;
  insertTime: number;
  confirmTimes: string;
}

export interface WithdrawRecord {
  id: string;
  amount: string;
  coin: string;
  network: string;
  status: number;
  txId: string;
  applyTime: string;
}

export interface CoinInfo {
  coin: string;
  name: string;
  free: string;
  locked: string;
  networkList: {
    network: string;
    withdrawEnable: boolean;
    depositEnable: boolean;
    withdrawFee: string;
    withdrawMin: string;
    depositMin: string;
  }[];
  // On-chain metadata returned by the chain-assets endpoint.
  // Present for coins fetched via asterGetChainAssets; absent for the fallback list.
  contractAddress?: string | undefined;
  decimals?: number | undefined;
  isNative?: boolean | undefined;
}

// ── AsterDEX public REST API base URLs ─────────────────
// Spot:    https://sapi.asterdex.com/api/v1/...
// Futures: https://fapi.asterdex.com/fapi/v1/...
// All market data endpoints are public — no API key needed.

const SPOT_BASE    = 'https://sapi.asterdex.com';
const FUTURES_BASE = 'https://fapi.asterdex.com';

// Allowed origins for all AsterDEX fetch helpers.
// Any constructed URL whose origin is not in this set is rejected before the request is sent.
const ASTERDEX_ALLOWED_ORIGINS = new Set([
  'https://sapi.asterdex.com',
  'https://fapi.asterdex.com',
  'https://fapi3.asterdex.com',
  'https://www.asterdex.com',
]);

function assertAsterOrigin(url: string): void {
  let origin: string;
  try {
    origin = new URL(url).origin;
  } catch {
    throw new Error('Blocked: malformed AsterDEX request URL');
  }
  if (!ASTERDEX_ALLOWED_ORIGINS.has(origin)) {
    throw new Error(`Blocked: request to unexpected host "${origin}"`);
  }
}

async function spotFetch(path: string, params: Record<string, string> = {}) {
  const qs = new URLSearchParams(params).toString();
  const url = `${SPOT_BASE}${path}${qs ? '?' + qs : ''}`;
  assertAsterOrigin(url);
  const res = await fetch(url);
  if (!res.ok) throw new Error(`AsterDEX spot API ${res.status}`);
  return res.json();
}

async function futuresFetch(path: string, params: Record<string, string> = {}) {
  const qs = new URLSearchParams(params).toString();
  const url = `${FUTURES_BASE}${path}${qs ? '?' + qs : ''}`;
  assertAsterOrigin(url);
  const res = await fetch(url);
  if (!res.ok) throw new Error(`AsterDEX futures API ${res.status}`);
  return res.json();
}

// ── Supabase edge function proxy (authenticated trading only) ──
// The edge function's toStringParams() accepts string | number | boolean and
// THROWS on any other type, so keep the value union in sync with it.
// Empty strings are stripped too: normalizeV3Params drops '' before signing,
// so sending them would make our local payload differ from the signed one.
type InvokeValue = string | number | boolean | undefined | null;

function formatAsterError(value: unknown): string {
  if (value instanceof Error && value.message) return value.message;
  if (typeof value === 'string' && value.trim()) return value;
  if (value && typeof value === 'object') {
    const error = value as Record<string, unknown>;
    const nested = error.error;
    if (nested && nested !== value) return formatAsterError(nested);
    const message = error.message ?? error.msg ?? error.detail ?? error.reason;
    if (typeof message === 'string' && message.trim()) {
      return message.replace(/\s*\(code\s+[-\d]+\)\s*$/i, '').trim();
    }
    try { return JSON.stringify(value); } catch { return 'Unknown AsterDEX error'; }
  }
  return String(value || 'Unknown AsterDEX error');
}

async function invoke(
  action: string,
  params: Record<string, InvokeValue> = {},
  auth = false,
) {
  const cleanParams = Object.fromEntries(
    Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== ''),
  );

  const options: Record<string, unknown> = { body: { action, ...cleanParams } };

  if (auth) {
    const { data: { session } } = await supabase.auth.getSession();
    if (!session?.access_token) throw new Error('Authentication required. Please sign in.');
    options['headers'] = { Authorization: `Bearer ${session.access_token}` };
  }

  const { data, error } = await supabase.functions.invoke('asterdex', options as never);

  if (error) {
    let message = error.message || 'AsterDEX request failed';
    try {
      // FunctionsHttpError carries the raw Response on `context`. Clone it so
      // callers that inspect the error later still get a readable body.
      const ctx = (error as unknown as { context?: Response }).context;
      const body = ctx && typeof ctx.clone === 'function' ? await ctx.clone().json() : null;
      if (body?.error) message = body.error;
      else if (body?.msg) message = body.msg;
      else if (body?.detail) message = body.detail;
    } catch { /* upstream returned a non-JSON body */ }
    throw new Error(formatAsterError(message));
  }
  if (data?.code && data.code < 0) throw new Error(formatAsterError(data.msg || data));
  if (data?.error) throw new Error(formatAsterError(data.error));
  return data;
}

// ── Public Market Data — calls AsterDEX REST API directly ──────

export const asterMarket = {
  // Spot
  spotTicker: (symbol?: string) =>
    spotFetch('/api/v1/ticker/24hr', symbol ? { symbol } : {}),

  spotTickerPrice: (symbol?: string) =>
    spotFetch('/api/v1/ticker/price', symbol ? { symbol } : {}),

  spotOrderBook: (symbol: string, limit = '20') =>
    spotFetch('/api/v1/depth', { symbol, limit }),

  spotKlines: (symbol: string, interval: string, limit = '100') =>
    spotFetch('/api/v1/klines', { symbol, interval, limit }),

  spotTrades: (symbol: string, limit = '20') =>
    spotFetch('/api/v1/trades', { symbol, limit }),

  spotExchangeInfo: () => spotFetch('/api/v1/exchangeInfo'),

  // Futures / Perpetual
  futuresTicker: (symbol?: string) =>
    futuresFetch('/fapi/v1/ticker/24hr', symbol ? { symbol } : {}),

  futuresTickerPrice: (symbol?: string) =>
    futuresFetch('/fapi/v1/ticker/price', symbol ? { symbol } : {}),

  futuresOrderBook: (symbol: string, limit = '20') =>
    futuresFetch('/fapi/v1/depth', { symbol, limit }),

  futuresKlines: (symbol: string, interval: string, limit = '100') =>
    futuresFetch('/fapi/v1/klines', { symbol, interval, limit }),

  futuresTrades: (symbol: string, limit = '20') =>
    futuresFetch('/fapi/v1/trades', { symbol, limit }),

  futuresExchangeInfo: () => futuresFetch('/fapi/v1/exchangeInfo'),

  futuresFundingRate: (symbol?: string) =>
    futuresFetch('/fapi/v1/fundingRate', symbol ? { symbol } : {}),

  futuresMarkPrice: (symbol?: string) =>
    futuresFetch('/fapi/v1/premiumIndex', symbol ? { symbol } : {}),
};

// ── Authenticated Trading ──────────────────────────────
// Every action name below exists in BOTH V3_ACTIONS and V1_ACTIONS in the edge
// function, so these calls work whether the user has a V3 agent or legacy HMAC
// keys. The edge picks the version — never send version-specific paths here.

export const asterTrading = {
  // Spot
  spotAccount: () => invoke('spot_account', {}, true),

  spotOpenOrders: (symbol?: string) =>
    invoke('spot_open_orders', { symbol }, true),

  spotAllOrders: (symbol: string, limit?: string) =>
    invoke('spot_all_orders', { symbol, limit }, true),

  spotPlaceOrder: (params: {
    symbol: string;
    side: 'BUY' | 'SELL';
    type: 'LIMIT' | 'MARKET' | 'STOP_LOSS' | 'STOP_LOSS_LIMIT' | 'TAKE_PROFIT' | 'TAKE_PROFIT_LIMIT' | 'LIMIT_MAKER';
    quantity: string;
    price?: string;
    stopPrice?: string;
    timeInForce?: string;
  }) => {
    const needsTimeInForce = ['LIMIT', 'STOP_LOSS_LIMIT', 'TAKE_PROFIT_LIMIT'].includes(params.type);
    return invoke('spot_order', {
      ...params,
      timeInForce: needsTimeInForce ? (params.timeInForce || 'GTC') : undefined,
    }, true);
  },

  spotCancelOrder: (symbol: string, orderId: string) =>
    invoke('spot_cancel_order', { symbol, orderId }, true),

  // Edge maps this to /api/v{1,3}/userTrades — /api/v1/myTrades does not exist.
  spotMyTrades: (symbol: string) =>
    invoke('spot_my_trades', { symbol }, true),

  // Futures
  // NOTE: on V3 the edge resolves futures_account to
  // /fapi/v3/accountWithJoinMargin (there is no /fapi/v3/account), and on V1 to
  // /fapi/v4/account. Response shapes differ slightly — read defensively.
  futuresAccount: () => invoke('futures_account', {}, true),
  futuresBalance: () => invoke('futures_balance', {}, true),
  futuresPositions: () => invoke('futures_positions', {}, true),

  futuresOpenOrders: (symbol?: string) =>
    invoke('futures_open_orders', { symbol }, true),

  // Present in both endpoint maps but previously unused by the frontend.
  futuresAllOrders: (symbol: string, limit?: string) =>
    invoke('futures_all_orders', { symbol, limit }, true),

  futuresPlaceOrder: (params: {
    symbol: string;
    side: 'BUY' | 'SELL';
    type: 'LIMIT' | 'MARKET' | 'STOP' | 'STOP_MARKET' | 'TAKE_PROFIT' | 'TAKE_PROFIT_MARKET' | 'LIMIT_MAKER';
    quantity: string;
    price?: string;
    stopPrice?: string;
    timeInForce?: string;
    positionSide?: 'LONG' | 'SHORT' | 'BOTH';
    reduceOnly?: string;
  }) => {
    const needsTimeInForce = ['LIMIT', 'LIMIT_MAKER'].includes(params.type);
    return invoke('futures_order', {
      ...params,
      positionSide: params.positionSide || 'BOTH',
      timeInForce: needsTimeInForce ? (params.timeInForce || 'GTC') : undefined,
    }, true);
  },

  futuresCancelOrder: (symbol: string, orderId: string) =>
    invoke('futures_cancel_order', { symbol, orderId }, true),

  futuresSetLeverage: (symbol: string, leverage: string) =>
    invoke('futures_leverage', { symbol, leverage }, true),

  futuresSetMarginType: (symbol: string, marginType: 'ISOLATED' | 'CROSSED') =>
    invoke('futures_margin_type', { symbol, marginType }, true),

  futuresMyTrades: (symbol: string) =>
    invoke('futures_my_trades', { symbol }, true),

  futuresIncome: (params?: { symbol?: string; incomeType?: string; limit?: string }) =>
    invoke('futures_income', { ...(params ?? {}) }, true),
};

// ── Deposit & Withdraw ─────────────────────────────────

const NETWORK_TO_CHAIN_ID: Record<string, string> = {
  ETH: '1',
  BSC: '56',
  BNB: '56',
  ARB: '42161',
  ARBITRUM: '42161',
  SOL: '101',
  SOLANA: '101',
};

// ── AsterDEX API constants ─────────────────────────────────────────────────────

// Public Spot REST API (official, documented)
const ASTER_SAPI = 'https://sapi.asterdex.com/api/v1';

// Legacy BAPI root — still used for deposit-address and asset-list endpoints
const ASTER_BAPI_ROOT = 'https://www.asterdex.com/bapi/futures/v1/public/future';
const ASTER_BAPI      = `${ASTER_BAPI_ROOT}/web3`;

export interface AsterAsset {
  name: string;
  displayName: string;
  contractAddress: string;
  decimals: number;
  isNative: boolean;
  chainId: number;
  network: string;
  // Solana-specific fields (present when chainId === 101)
  bank?: string;
  solVault?: string;
  tokenMint?: string;
  tokenVault?: string;
}

// Fetch supported assets for a given chainId from the public BAPI.
// - operation='deposit'  → hits /deposit/assets  (coins the exchange accepts for deposit)
// - operation='withdraw' → hits /withdraw/assets (coins the exchange allows for withdrawal)
// Spot and Perpetual accounts list different coins per chain — always pass the correct accountType.
// Maps them to the CoinInfo structure used throughout the modal.
export async function asterGetChainAssets(
  chainId: number,
  accountType: 'spot' | 'perp' = 'perp',
  operation: 'deposit' | 'withdraw' = 'withdraw',
): Promise<CoinInfo[]> {
  if (!Number.isInteger(chainId) || chainId < 0 || chainId > 2147483647) {
    throw new Error('Invalid chainId');
  }
  if (accountType !== 'spot' && accountType !== 'perp') {
    throw new Error('Invalid accountType');
  }
  if (operation !== 'deposit' && operation !== 'withdraw') {
    throw new Error('Invalid operation');
  }
  // Solana is not an EVM chain — it needs networks=SOL in the query
  const networkParam = chainId === 101 ? 'SOL' : 'EVM';
  const endpoint = operation === 'deposit' ? 'deposit' : 'withdraw';
  const requestUrl = `${ASTER_BAPI_ROOT}/aster/${endpoint}/assets?chainIds=${chainId}&networks=${networkParam}&accountType=${accountType}`;
  assertAsterOrigin(requestUrl);
  const res = await fetch(requestUrl);
  const json = await res.json();
  if (!json.success) throw new Error(json.message ?? 'Failed to fetch chain assets');

  const networkKey = chainId === 1 ? 'ETH' : chainId === 56 ? 'BSC' : chainId === 42161 ? 'ARB' : chainId === 101 ? 'SOL' : String(chainId);

  const seen = new Set<string>();
  return (json.data as AsterAsset[])
    .filter(a => {
      if (seen.has(a.name)) return false;
      seen.add(a.name);
      return true;
    })
    .map(a => ({
      coin: a.name,
      name: a.displayName || a.name,
      free: '0',
      locked: '0',
      networkList: [{
        network: networkKey,
        withdrawEnable: true,
        depositEnable: true,
        withdrawFee: '0',
        withdrawMin: '0',
        depositMin: '0',
      }],
      // Carry through the on-chain details so the broadcaster can use the exact
      // contract address and decimals returned by the API instead of a hardcoded table.
      contractAddress: a.contractAddress || undefined,
      decimals: a.decimals ?? undefined,
      isNative: a.isNative ?? undefined,
    }));
}

// ── Registration: get nonce → sign → create API key ──────────────────────────
// Uses the official Spot API (sapi.asterdex.com), not the legacy BAPI.
// No separate "create broker account" step is needed — the Spot API creates
// the sub-account implicitly on first createApiKey call.

export async function asterGetNonce(address: string): Promise<string> {
  // SAPI requires application/x-www-form-urlencoded (not JSON).
  // Response is a plain-text integer, e.g. "180433"
  const body = new URLSearchParams({ address, userOperationType: 'CREATE_API_KEY' });
  const res = await fetch(`${ASTER_SAPI}/getNonce`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  const text = await res.text();
  if (!res.ok) {
    let msg = 'Failed to get nonce';
    try { msg = JSON.parse(text).msg ?? msg; } catch { /* plain-text error */ }
    throw new Error(msg);
  }
  return text.trim();
}

export async function asterCreateApiKey(
  address: string,
  signature: string,
): Promise<{ apiKey: string; apiSecret: string }> {
  // SAPI requires application/x-www-form-urlencoded (not JSON).
  const body = new URLSearchParams({
    address,
    userOperationType: 'CREATE_API_KEY',
    userSignature: signature,
    desc: 'pexly-wallet',
    timestamp: String(Date.now()),
  });
  const res = await fetch(`${ASTER_SAPI}/createApiKey`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  const json = await res.json();
  if (!res.ok || (json.code !== undefined && json.code !== 0 && json.code !== 200)) {
    throw new Error(json.msg ?? 'Failed to create API key');
  }
  return json.data ?? json;
}

// ── V3 Registration ────────────────────────────────────────────────────────────
// V3 uses EIP-712 signed requests instead of HMAC. Authentication requires:
//   user       = the user's main EVM wallet address
//   signer     = a dedicated API signer wallet address (registered with AsterDEX)
//   signerKey  = the private key of the signer wallet
//
// IMPORTANT: the edge function loads these from the service-role-only
// `aster_credentials` table (columns: user_id, aster_user, signer, signer_key,
// api_key, api_secret) and treats auth user_metadata as a read-only legacy
// fallback. After registering, persist credentials into that table — do NOT
// write them with supabase.auth.updateUser().

// Derive an EVM address from a secp256k1 private key (EIP-55 checksum).
function deriveEvmAddress(privateKey: Uint8Array): string {
  const pubKey = secp.getPublicKey(privateKey, false); // uncompressed 65 bytes
  const addressBytes = keccak_256(pubKey.slice(1)).slice(-20);
  const hexAddr = Array.from(addressBytes).map(b => b.toString(16).padStart(2, '0')).join('');
  // EIP-55 checksum
  const hash = keccak_256(new TextEncoder().encode(hexAddr));
  const checksum = hexAddr.split('').map((c, i) =>
    ((hash[Math.floor(i / 2)] ?? 0) >> (4 - (i % 2) * 4) & 0xf) >= 8 ? c.toUpperCase() : c
  ).join('');
  return '0x' + checksum;
}

// Generate a fresh Ethereum keypair to use as the AsterDEX V3 signer wallet.
export function asterGenerateSignerWallet(): { address: string; privateKey: string } {
  const privKey = secp.utils.randomSecretKey();
  const address = deriveEvmAddress(privKey);
  const privateKey = '0x' + Array.from(privKey).map(b => b.toString(16).padStart(2, '0')).join('');
  return { address, privateKey };
}

/**
 * Derive the user's MAIN wallet secp256k1 key from their mnemonic
 * (BIP-44 EVM path m/44'/60'/0'/0/<index>).
 *
 * Needed because V3 withdrawals require a userSignature produced by the MAIN
 * wallet — the agent/signer key only authorises the request envelope.
 * CALLER must wipe the returned key (`key.fill(0)`) once finished.
 */
export async function asterDeriveMainKey(mnemonic: string, index = 0): Promise<Uint8Array> {
  const seed = await mnemonicToSeed(mnemonic);
  const node = HDKey.fromMasterSeed(seed).derive(`m/44'/60'/0'/0/${index}`);
  if (!node.privateKey) throw new Error('Failed to derive main wallet key');
  return node.privateKey;
}

/** Sign an EIP-712 digest with a raw secp256k1 key → 0x + r + s + v (65 bytes). */
export async function asterSignHash(hash: Uint8Array, privKey: Uint8Array): Promise<string> {
  const sigBytes = await secp.signAsync(hash, privKey, { lowS: true, format: 'recovered', prehash: false } as never);
  return '0x'
    + bytesToHex(sigBytes.slice(1, 33))
    + bytesToHex(sigBytes.slice(33, 65))
    + ((sigBytes[0] ?? 0) + 27).toString(16).padStart(2, '0');
}

// V3 version of getNonce — uses /api/v3/getNonce
export async function asterGetNonceV3(
  address: string,
  userOperationType: string = 'CREATE_API_KEY',
): Promise<string> {
  const body = new URLSearchParams({ address, userOperationType });
  const res = await fetch(`https://sapi.asterdex.com/api/v3/getNonce`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  const text = await res.text();
  if (!res.ok) {
    let msg = 'Failed to get nonce';
    try { msg = JSON.parse(text).msg ?? msg; } catch { /* plain-text error */ }
    throw new Error(msg);
  }
  // Server may return plain-text nonce OR JSON { code: 0, data: "nonce_value" }
  try {
    const json = JSON.parse(text);
    if (json.data !== undefined && json.data !== null) return String(json.data).trim();
    if (json.nonce !== undefined)                      return String(json.nonce).trim();
  } catch { /* plain-text nonce */ }
  return text.trim();
}

// Register a V3 signer wallet with AsterDEX via /api/v3/createApiKey.
// The signerAddress is the address we generated locally — AsterDEX links it to the user account.
// Returns the confirmed signer address (may differ from input if AsterDEX normalises it).
// NOTE: this legacy variant accepts a pre-built signature for callers that sign externally.
export async function asterCreateApiKeyV3(
  address: string,
  signature: string,
  signerAddress: string,
): Promise<{ user: string; signer: string }> {
  const ts = Date.now();
  const body = new URLSearchParams({
    address,
    userOperationType: 'CREATE_API_KEY',
    userSignature: signature,
    signerAddress,
    desc: `pexly-${ts}`,
    timestamp: String(ts),
  });
  const res = await fetch(`https://sapi.asterdex.com/api/v3/createApiKey`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  const json = await res.json();
  if (!res.ok || (json.code !== undefined && json.code !== 0 && json.code !== 200)) {
    throw new Error(json.msg ?? 'Failed to register V3 API key');
  }
  const data = json.data ?? json;
  return {
    user: address,
    signer: (data.signer ?? data.signerAddress ?? signerAddress) as string,
  };
}

/**
 * EIP-712 variant of asterCreateApiKeyV3.
 *
 * V3 requires every authenticated request to be signed with EIP-712 typed-data
 * (not EIP-191 personal_sign).  The signed message is the ASCII-sorted
 * `key=value` param string, hashed through _asterEip712Hash, then signed with
 * the MAIN wallet's secp256k1 private key.
 *
 * Params included in the signed string (sorted):
 *   address, desc, nonce (from getNonce), signerAddress, timestamp, userOperationType
 *
 * CALLER must wipe `mainPrivKey` after all operations complete.
 */
export async function asterCreateApiKeyV3WithKey(
  mainPrivKey: Uint8Array,
  address: string,
  nonce: string,
  signerAddress: string,
): Promise<{ user: string; signer: string }> {
  const ts   = Date.now();
  const desc = `pexly-${ts}`;

  const params: Record<string, string> = {
    address,
    desc,
    nonce,
    signerAddress,
    timestamp:          String(ts),
    userOperationType:  'CREATE_API_KEY',
  };

  const paramStr = Object.keys(params)
    .sort()
    .map(k => `${k}=${params[k]}`)
    .join('&');

  const signature = await asterSignHash(_asterEip712Hash(paramStr), mainPrivKey);

  const body = new URLSearchParams({
    address,
    userOperationType: 'CREATE_API_KEY',
    userSignature:     signature,
    signerAddress,
    desc,
    timestamp:         String(ts),
    nonce,
  });

  const res  = await fetch(`https://sapi.asterdex.com/api/v3/createApiKey`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body:    body.toString(),
  });
  const json = await res.json();
  if (!res.ok || (json.code !== undefined && json.code !== 0 && json.code !== 200)) {
    throw new Error(json.msg ?? 'Failed to register V3 API key');
  }
  const data = json.data ?? json;
  return {
    user:   address,
    signer: (data.signer ?? data.signerAddress ?? signerAddress) as string,
  };
}

/**
 * Unified V3 agent registration — POST /fapi/v3/registerAndApproveAgent.
 *
 * Replaces the old two-step createApiKey + approveAgent flow.
 * Signs a single message with the user's MAIN wallet private key (EIP-712).
 *
 * Signed message field order is FIXED per AsterDEX docs — do NOT reorder or sort:
 *   user, nonce, agentName, agentAddress, expired, signatureChainId,
 *   canSpotTrade, canPerpTrade, canWithdraw, ipWhitelist
 *
 * NOTE: canWithdraw is false, which is correct — the edge function's V3
 * withdrawal path signs the request with the agent key but requires a separate
 * MAIN-wallet `userSignature` to authorise the funds movement
 * (see asterSignWithdrawal below).
 *
 * CALLER must wipe `mainPrivKey` after all operations complete.
 */
export async function asterRegisterAndApproveAgent(
  signer: (hash: Uint8Array) => Promise<string>,
  userAddress: string,
  signerAddress: string,
  agentName: string,
): Promise<void> {
  const nonce           = String(Math.trunc(Date.now() * 1000));
  const expired         = String(Date.now() + 90 * 24 * 60 * 60 * 1000);
  const signatureChainId = '56';

  const msg = [
    `user=${userAddress}`,
    `nonce=${nonce}`,
    `agentName=${agentName}`,
    `agentAddress=${signerAddress}`,
    `expired=${expired}`,
    `signatureChainId=${signatureChainId}`,
    `canSpotTrade=true`,
    `canPerpTrade=true`,
    `canWithdraw=false`,
    `ipWhitelist=`,
  ].join('&');

  const hash      = _asterEip712Hash(msg);
  const signature = await signer(hash);

  const body = new URLSearchParams({
    user:              userAddress,
    nonce,
    agentName,
    agentAddress:      signerAddress,
    expired,
    signatureChainId,
    signature,
    canSpotTrade:      'true',
    canPerpTrade:      'true',
    canWithdraw:       'false',
    ipWhitelist:       '',
  });

  const res  = await fetch('https://fapi.asterdex.com/fapi/v3/registerAndApproveAgent', {
    method:  'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body:    body.toString(),
  });
  const json = await res.json();
  if (!res.ok || (json.code !== undefined && json.code !== 0 && json.code !== 200)) {
    throw new Error(json.msg ?? 'Failed to register agent: ' + JSON.stringify(json));
  }
}

// Fetch the AsterDEX deposit address for a given chain and coin.
// - EVM chains (ETH/BSC/ARB): shared treasury contract address from ae/deposit-address.
// - Solana (chainId 101): per-coin program bank address from the deposit/assets endpoint.
//   Each SPL token has its own bank; native SOL uses the shared solVault address.
// This is the direct-from-browser variant; asterWallet.depositAddress() does the
// same lookup through the edge function (which also normalises the response).
export async function asterGetDepositAddress(
  chainId: number,
  coin?: string,
  accountType: 'spot' | 'perp' = 'spot',
): Promise<string> {
  if (!Number.isInteger(chainId) || chainId < 0 || chainId > 2147483647) {
    throw new Error('Invalid chainId');
  }
  if (accountType !== 'spot' && accountType !== 'perp') {
    throw new Error('Invalid accountType');
  }
  if (chainId === 101) {
    // Solana: look up the coin's bank address from the deposit assets list.
    // accountType distinguishes spot vs perpetual bank addresses.
    const networkParam = 'SOL';
    const solUrl = `${ASTER_BAPI_ROOT}/aster/deposit/assets?chainIds=${chainId}&networks=${networkParam}&accountType=${accountType}`;
    assertAsterOrigin(solUrl);
    const res = await fetch(solUrl);
    const json = await res.json();
    if (!json.success) throw new Error(json.message ?? 'Failed to get Solana deposit address');
    const assets: AsterAsset[] = json.data ?? [];

    if (coin) {
      const match = assets.find(a => a.name === coin || a.displayName === coin);
      if (match) {
        // Native SOL uses solVault; SPL tokens use per-coin bank address
        const addr = match.isNative ? match.solVault : match.bank;
        if (addr) return addr;
      }
    }
    // Fallback: use the shared solVault from the first asset that has one
    const vaultAsset = assets.find(a => a.solVault);
    if (vaultAsset) return vaultAsset.solVault!;

    throw new Error('No Solana deposit address available for this coin');
  }

  // EVM chains: shared treasury contract address
  const evmUrl = `${ASTER_BAPI}/ae/deposit-address?chainId=${chainId}`;
  assertAsterOrigin(evmUrl);
  const res = await fetch(evmUrl);
  const json = await res.json();
  if (!json.success) throw new Error(json.message ?? 'Failed to get deposit address');
  return String(json.data);
}

/**
 * Build the MAIN-wallet `userSignature` that the edge function REQUIRES for any
 * V3 withdrawal. Without it normalizeV3Params throws
 * "A V3 withdrawal requires a separate main-wallet userSignature", and the
 * value is validated against /^0x[0-9a-fA-F]{130}$/ (65 bytes: r || s || v).
 *
 * The agent/signer key signs the request envelope; THIS signature authorises
 * moving the funds, which is why the agent is registered with canWithdraw=false.
 */
export async function asterSignWithdrawal(
  signer: (hash: Uint8Array) => Promise<string>,
  p: {
    user: string;      // main wallet address
    asset: string;     // coin symbol, e.g. USDT
    receiver: string;  // destination address
    amount: string;
    chainId: string;
    fee: string;
  },
): Promise<{ userSignature: string; userNonce: string }> {
  const userNonce = String(Math.trunc(Date.now() * 1000));
  const params: Record<string, string> = { ...p, userNonce };
  const paramStr = Object.keys(params).sort().map(k => `${k}=${params[k]}`).join('&');
  const userSignature = await signer(_asterEip712Hash(paramStr));
  if (!/^0x[0-9a-fA-F]{130}$/.test(userSignature)) {
    throw new Error('Withdrawal signature must be a 65-byte hex signature');
  }
  return { userSignature, userNonce };
}

export const asterWallet = {
  // ── Public edge actions ──────────────────────────────────────────────
  // These are in PUBLIC_ACTIONS, so they do NOT need linked AsterDEX
  // credentials — but the handler still 401s without a Supabase Bearer token,
  // hence auth = true.
  //
  // The edge derives BOTH chainId and the SOL/EVM flag from the raw network
  // name via chainDetails(), so always pass a human network name
  // ('BSC' | 'ETH' | 'ARB' | 'SOL' …) and never a pre-resolved chainId.
  // Omitting network silently falls back to BSC/56.
  depositAddress: (coin: string, network = 'BSC'): Promise<AsterDepositAddress> =>
    invoke('spot_deposit_address', { coin, network }, true),

  futuresDepositAddress: (coin: string, network = 'BSC'): Promise<AsterDepositAddress> =>
    invoke('futures_deposit_address', { coin, network }, true),

  // Fee estimate is network-based and the same regardless of account type.
  withdrawFeeEstimate: (coin: string, network: string) =>
    invoke('spot_withdraw_fee_estimate', { coin, network }, true),

  coinInfo: (network = 'BSC') =>
    invoke('spot_coin_info', { network }, true),

  // ── History ──────────────────────────────────────────────────────────
  // Edge renames coin → asset and filters the consolidated
  // /fapi/v3/aster/deposit-withdraw-history feed by type + accountType.
  depositHistory: (coin?: string, opts?: { startTime?: string; endTime?: string; limit?: string }) =>
    invoke('spot_deposit_history', { coin, ...(opts ?? {}) }, true),

  withdrawHistory: (coin?: string, opts?: { startTime?: string; endTime?: string; limit?: string }) =>
    invoke('spot_withdraw_history', { coin, ...(opts ?? {}) }, true),

  futuresDepositHistory: (coin?: string, opts?: { startTime?: string; endTime?: string; limit?: string }) =>
    invoke('futures_deposit_history', { coin, ...(opts ?? {}) }, true),

  futuresWithdrawHistory: (coin?: string, opts?: { startTime?: string; endTime?: string; limit?: string }) =>
    invoke('futures_withdraw_history', { coin, ...(opts ?? {}) }, true),

  // ── Withdraw (spot only) ─────────────────────────────────────────────
  // The edge maps coin → asset and address → receiver, strips network/nonce,
  // and generates its own monotonic request nonce — so do not send `nonce`.
  // `userSignature` + `userNonce` come from asterSignWithdrawal().
  withdraw: (p: {
    coin: string;
    address: string;
    amount: string;
    network: string;
    fee: string;
    userSignature: string;
    userNonce: string;
  }) => invoke('spot_withdraw', {
    coin:          p.coin,
    address:       p.address,
    amount:        p.amount,
    network:       p.network,
    chainId:       NETWORK_TO_CHAIN_ID[p.network.toUpperCase()] ?? '56',
    fee:           p.fee,
    userSignature: p.userSignature,
    userNonce:     p.userNonce,
  }, true),

  // ── Transfers ────────────────────────────────────────────────────────
  // Edge converts type → kindType (SPOT_FUTURE / FUTURE_SPOT) and adds a
  // clientTranId automatically.
  transfer: (asset: string, amount: string, type: 'SPOT_TO_FUTURES' | 'FUTURES_TO_SPOT') =>
    invoke('spot_transfer', { asset, amount, type }, true),

  transferHistory: (asset?: string, limit?: string) =>
    invoke('spot_transfer_history', { asset, limit }, true),
};

/**
 * There is NO perpetual withdrawal endpoint on AsterDEX — the edge function
 * rejects `futures_withdraw` unconditionally. Perp balances must be moved to
 * spot first, then withdrawn. Replaces the old asterWallet.futuresWithdraw().
 */
export async function asterWithdrawFromPerp(p: {
  user: string;
  coin: string;
  address: string;
  amount: string;
  network: string;
  fee: string;
  signer: (hash: Uint8Array) => Promise<string>; // MAIN wallet signer
}) {
  await asterWallet.transfer(p.coin, p.amount, 'FUTURES_TO_SPOT');
  const chainId = NETWORK_TO_CHAIN_ID[p.network.toUpperCase()] ?? '56';
  const { userSignature, userNonce } = await asterSignWithdrawal(p.signer, {
    user:     p.user,
    asset:    p.coin,
    receiver: p.address,
    amount:   p.amount,
    chainId,
    fee:      p.fee,
  });
  return asterWallet.withdraw({
    coin:    p.coin,
    address: p.address,
    amount:  p.amount,
    network: p.network,
    fee:     p.fee,
    userSignature,
    userNonce,
  });
}

// ── V3 Futures Agent Registration ─────────────────────────────────────────────
// AsterDEX V3 requires TWO separate agent registrations:
//   1. sapi.asterdex.com/api/v3/createApiKey  → spot endpoints  (asterCreateApiKeyV3)
//   2. fapi.asterdex.com/fapi/v3/approveAgent → futures endpoints (this function)
// Without step 2, all /fapi/v3 requests return {"code":-1000,"msg":"No agent found"}.
//
// approveAgent signing (per official AsterDEX V3 docs / aster-skills-hub):
//   - EIP-712 domain: name="AsterSignTransaction", version="1", chainId=1666,
//     verifyingContract="0x0000000000000000000000000000000000000000"
//   - Type: Message(string msg), where msg = ASCII-sorted key=value param string
//     (must include nonce, user, signer)
//   - Signed with the SIGNER (API wallet) private key — NOT the main wallet.
//
// This matches the edge function's eip712Hash() byte-for-byte; keep them in sync.

function _asterEip712Hash(paramStr: string): Uint8Array {
  const enc = new TextEncoder();

  function u256(n: bigint): Uint8Array {
    const hex = n.toString(16).padStart(64, '0');
    const b = new Uint8Array(32);
    for (let i = 0; i < 32; i++) b[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return b;
  }
  function addrPad(a: string): Uint8Array {
    const hex = a.toLowerCase().replace('0x', '').padStart(64, '0');
    const b = new Uint8Array(32);
    for (let i = 0; i < 32; i++) b[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return b;
  }

  const domainTypeHash = keccak_256(enc.encode(
    'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)',
  ));
  const msgTypeHash = keccak_256(enc.encode('Message(string msg)'));

  const domainData = new Uint8Array(5 * 32);
  domainData.set(domainTypeHash,                                         0);
  domainData.set(keccak_256(enc.encode('AsterSignTransaction')),        32);
  domainData.set(keccak_256(enc.encode('1')),                           64);
  domainData.set(u256(1666n),                                           96);
  domainData.set(addrPad('0x0000000000000000000000000000000000000000'), 128);
  const domainSeparator = keccak_256(domainData);

  const structData = new Uint8Array(2 * 32);
  structData.set(msgTypeHash,                     0);
  structData.set(keccak_256(enc.encode(paramStr)), 32);
  const structHash = keccak_256(structData);

  const payload = new Uint8Array(66);
  payload[0] = 0x19;
  payload[1] = 0x01;
  payload.set(domainSeparator, 2);
  payload.set(structHash,      34);

  return keccak_256(payload);
}

export function hexToBytes(hex: string): Uint8Array {
  const h = hex.replace('0x', '');
  const padded = h.length % 2 === 0 ? h : '0' + h;
  const b = new Uint8Array(padded.length / 2);
  for (let i = 0; i < padded.length; i += 2) b[i / 2] = parseInt(padded.slice(i, i + 2), 16);
  return b;
}

export async function asterApproveAgentFutures(
  mnemonic: string,
  userAddress: string,
  signerAddress: string,
  signerPrivateKeyHex: string,
): Promise<void> {
  const signerPrivKey = hexToBytes(signerPrivateKeyHex);
  try {
    await asterApproveAgentFuturesWithKey(signerPrivKey, userAddress, signerAddress);
  } finally {
    signerPrivKey.fill(0);
  }
}

/**
 * Approves the signer (API wallet) for futures trading on AsterDEX V3.
 * signerPrivKey must be the SIGNER (API wallet) private key — not the main wallet.
 * CALLER is responsible for wiping the key after all operations complete.
 */
export async function asterApproveAgentFuturesWithKey(
  signerPrivKey: Uint8Array,
  userAddress: string,
  signerAddress: string,
): Promise<void> {
  // Fetch a server-issued nonce for the APPROVE_AGENT operation.
  // AsterDEX validates that the nonce came from their system, so a
  // self-generated timestamp nonce causes "Signature check failed".
  const nonce = await asterGetNonceV3(userAddress, 'APPROVE_AGENT');
  const agentName = `pexly-${nonce}`;

  const params: Record<string, string> = {
    agentAddress: signerAddress,
    agentName,
    canPerpTrade: 'true',
    canSpotTrade: 'false',
    canWithdraw:  'false',
    nonce:        nonce.toString(),
    signer:       signerAddress,
    user:         userAddress,
  };

  const paramStr = Object.keys(params)
    .sort()
    .map(k => `${k}=${params[k]}`)
    .join('&');

  const signature = await asterSignHash(_asterEip712Hash(paramStr), signerPrivKey);

  const body = new URLSearchParams({
    agentAddress: signerAddress,
    user:         userAddress,
    signer:       signerAddress,
    nonce:        nonce.toString(),
    signature,
    agentName,
    canSpotTrade: 'false',
    canPerpTrade: 'true',
    canWithdraw:  'false',
  });

  const res  = await fetch('https://fapi.asterdex.com/fapi/v3/approveAgent', {
    method:  'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body:    body.toString(),
  });
  const json = await res.json();
  if (!res.ok || (json.code !== undefined && json.code !== 0 && json.code !== 200)) {
    throw new Error(json.msg ?? 'Failed to approve futures agent: ' + JSON.stringify(json));
  }
}
