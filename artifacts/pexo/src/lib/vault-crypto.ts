/**
 * ============================================================
 *  PEXLY VAULT CRYPTO — key management half of the signing worker
 * ============================================================
 *
 * This module holds everything about MNEMONICS, KEYS, and VAULTS:
 *   • BIP-39 mnemonic generation / validation
 *   • Per-chain key + address derivation (EVM / BTC / SOL / TRX / XRP)
 *   • Vault encryption / decryption (scrypt + AES-256-GCM)
 *   • Legacy vault migration
 *   • Multi-chain wallet creation (createSecureWallet / createMultiChainWallet)
 *   • One-time mnemonic backup display
 *   • Generic hashing utilities
 *
 * It deliberately has NO knowledge of RPC calls, chain gateways, or
 * transaction building — that all lives in signing.worker.ts, which imports
 * this module. This file is pure "given a mnemonic/vault + password, produce
 * keys/addresses/ciphertext" — nothing here ever talks to the network.
 *
 * signing.worker.ts is still the only Worker entry point (the one file the
 * Worker constructor loads). This file is a plain module it imports from —
 * splitting it out doesn't change the runtime architecture or any of the
 * postMessage security properties described in signing.worker.ts; it's a
 * source-file split for readability/debugging only.
 *
 * ── Side effect on import ─────────────────────────────────────────────────
 * Importing this module patches @noble/ed25519's SHA-512 wiring once (see
 * below). Because module instances are cached by the runtime, this applies
 * to the *same* @noble/ed25519 instance that signing.worker.ts's own
 * `import * as nobleEd from "@noble/ed25519"` resolves to — so signing.worker.ts
 * does not need to repeat this wiring itself, but it DOES need to import this
 * module (for anything) before calling any ed25519 signing function.
 */

// ─── Imports ──────────────────────────────────────────────────────────────────

import { scryptAsync } from "@noble/hashes/scrypt.js";
import * as secp    from "@noble/secp256k1";
import * as btc      from "@scure/btc-signer";
import * as nobleEd  from "@noble/ed25519";

import { generateMnemonic, mnemonicToSeed, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { HDKey }    from "@scure/bip32";
import { base58 }   from "@scure/base";

import { keccak_256 } from "@noble/hashes/sha3.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { ripemd160 }     from "@noble/hashes/legacy.js";
import { bytesToHex }    from "@noble/hashes/utils.js";
import { hmac }          from "@noble/hashes/hmac.js";

// ─── noble-ed25519 SHA-512 wiring (handles v2 and v3 APIs) ───────────────────
{
  const ned = nobleEd as any;
  if (ned.hashes && !ned.hashes.sha512 && !Object.isFrozen(ned.hashes)) {
    ned.hashes.sha512 = sha512;
  }
  if (ned.utils && !ned.utils.sha512Sync && !Object.isFrozen(ned.utils) && typeof ned.utils.concatBytes === "function") {
    const cb = ned.utils.concatBytes;
    ned.utils.sha512Sync = (...m: Uint8Array[]) => sha512(cb(...m));
  }
}

// ─── Secure memory wipe ───────────────────────────────────────────────────────

export function wipeBytes(b: Uint8Array | null | undefined): void {
  if (b instanceof Uint8Array) b.fill(0);
}
export function wipeHDKey(k: any): void {
  if (!k) return;
  // @scure/bip32 >=2.4 returns COPIES from .privateKey/.chainCode getters —
  // filling those copies does NOT zero the live buffer inside the HDKey
  // instance. From 2.4 onward the library exposes wipePrivateData() for
  // exactly this purpose; prefer it. Keep the old manual fill as a fallback
  // for any environment pinned to an older @scure/bip32 that lacks the method
  // (harmless no-op there, but not relied upon as the primary defense).
  if (typeof k.wipePrivateData === "function") {
    try { k.wipePrivateData(); } catch { /**/ }
    return;
  }
  try { if (k.privateKey instanceof Uint8Array) k.privateKey.fill(0); } catch { /**/ }
  try { if (k.chainCode instanceof Uint8Array) k.chainCode.fill(0); } catch { /**/ }
}

// No reusable derived-key session cache is kept in production. Every vault
// open re-runs scrypt, reducing the time a derived AES key remains in memory.
export function clearSessionCache(): void { /* retained for API compatibility */ }

// ─── Vault constants ──────────────────────────────────────────────────────────

const IV_LEN   = 12;
const SALT_LEN = 16;

export interface KdfParams { N: number; r: number; p: number; dkLen: number }

/**
 * Pick scrypt N based on device capability detected inside the worker.
 * Workers have access to navigator.hardwareConcurrency and deviceMemory.
 * The actual params are stored in each EncryptedVault so any device can
 * decrypt a vault without needing to know the original device's profile.
 */
function getAdaptiveKdfParams(): KdfParams {
  const cores  = (typeof navigator !== "undefined" && navigator.hardwareConcurrency) || 2;
  const memGb  = (typeof navigator !== "undefined" && (navigator as any).deviceMemory)  || 0;
  // Low-end: ≤4 logical cores, or device reports ≤4 GB RAM
  const isLowEnd = cores <= 4 || (memGb > 0 && memGb <= 4);
  // Mid-range: ≤8 cores (catches most mid-range Android / iPad)
  const isMid    = !isLowEnd && cores <= 8;
  const N = isLowEnd ? 65_536   // 2¹⁶ — mobile-safe (~0.5–1 s)
          : isMid    ? 131_072  // 2¹⁷ — balanced  (~1–2 s)
          :            262_144; // 2¹⁸ — strong    (~2–3 s)
  return { N, r: 8, p: 1, dkLen: 32 };
}



const MIN_KDF_N = 1 << 15;
const MAX_KDF_N = 1 << 18;
const MIN_KDF_R = 8;
const MAX_KDF_R = 8;
const MIN_KDF_P = 1;
const MAX_KDF_P = 2;
const MAX_DK_LEN = 32;
const MAX_CIPHERTEXT_BYTES = 64 * 1024;

function isPowerOfTwo(n: number): boolean {
  return Number.isInteger(n) && n >= 1 && (n & (n - 1)) === 0;
}

function validateKdfParams(value: unknown): value is KdfParams {
  if (!value || typeof value !== "object") return false;
  const p = value as Partial<KdfParams>;
  return (
    Number.isSafeInteger(p.N) && isPowerOfTwo(p.N) &&
    p.N >= MIN_KDF_N && p.N <= MAX_KDF_N &&
    Number.isSafeInteger(p.r) && p.r >= MIN_KDF_R && p.r <= MAX_KDF_R &&
    Number.isSafeInteger(p.p) && p.p >= MIN_KDF_P && p.p <= MAX_KDF_P &&
    p.dkLen === MAX_DK_LEN
  );
}

export interface EncryptedVault {
  version: number;
  ciphertext: string;
  iv: string;
  salt: string;
  kdf: "scrypt";
  kdfParams: KdfParams;
  origin?: string;
}

export interface PasskeyVault {
  version: 2;
  ciphertext: string;
  iv: string;
}

// ─── Cryptographic helpers ────────────────────────────────────────────────────

/**
 * Derive a scrypt key.
 *
 * Accepts the password as either:
 *   - string  — encoded to UTF-8 bytes here; those bytes are zero-filled after KDF
 *   - Uint8Array — used directly (caller must zero-fill after the entire operation)
 *
 * Uses adaptive KDF params unless an explicit `params` override is supplied
 * (e.g. when re-deriving during vault decryption, where the vault stores the
 * original params and we MUST reproduce the exact same key).
 */
async function deriveScryptKey(
  password: string | Uint8Array,
  salt: Uint8Array,
  params?: KdfParams,
): Promise<Uint8Array> {
  const kdf = params ?? getAdaptiveKdfParams();
  let pwBytes: Uint8Array;
  let ownBytes = false;
  if (password instanceof Uint8Array) {
    pwBytes = password;
  } else {
    pwBytes = new TextEncoder().encode(password.normalize("NFKC"));
    ownBytes = true;
  }
  try {
    return await scryptAsync(pwBytes, salt, {
      N: kdf.N,
      r: kdf.r,
      p: kdf.p,
      dkLen: kdf.dkLen,
    });
  } finally {
    // Zero-fill the encoded password bytes as soon as scrypt is done.
    // If we encoded them ourselves we always wipe; if the caller passed a
    // Uint8Array they are responsible for wiping after the full op completes.
    if (ownBytes) pwBytes.fill(0);
  }
}

function b64encode(u8: Uint8Array): string {
  // Spread-into-btoa crashes on large arrays (call stack limit ~65 K args).
  // Process in 32 KB chunks to stay well under the limit.
  const CHUNK = 0x8000;
  let out = "";
  for (let i = 0; i < u8.length; i += CHUNK) {
    out += String.fromCharCode(...u8.subarray(i, i + CHUNK));
  }
  return btoa(out);
}
function b64decode(s: string): Uint8Array {
  if (typeof s !== "string" || s.length === 0 || s.length > 100_000 || s.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) {
    throw new Error("Invalid base64 data");
  }
  const decoded = atob(s);
  return new Uint8Array(decoded.split("").map(c => c.charCodeAt(0)));
}

/** Parse a vault that may have been serialised as a JSON string */
export function parseVault(v: unknown): EncryptedVault | null {
  let value: unknown = v;
  if (typeof value === "string") {
    try { value = JSON.parse(value); } catch { return null; }
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;

  const x = value as Record<string, unknown>;
  if (x.version !== 1 || x.kdf !== "scrypt") return null;
  if (typeof x.ciphertext !== "string" || x.ciphertext.length === 0) return null;
  if (typeof x.iv !== "string" || x.iv.length === 0) return null;
  if (typeof x.salt !== "string" || x.salt.length === 0) return null;
  if (!validateKdfParams(x.kdfParams)) return null;

  try {
    if (b64decode(x.iv).length !== IV_LEN) return null;
    if (b64decode(x.salt).length !== SALT_LEN) return null;
    if (b64decode(x.ciphertext).length > MAX_CIPHERTEXT_BYTES) return null;
  } catch {
    return null;
  }

  if (
    x.origin !== undefined &&
    (typeof x.origin !== "string" || x.origin.length === 0 || x.origin.length > 2048)
  ) return null;

  return {
    version: 1,
    ciphertext: x.ciphertext,
    iv: x.iv,
    salt: x.salt,
    kdf: "scrypt",
    kdfParams: x.kdfParams,
    ...(typeof x.origin === "string" ? { origin: x.origin } : {}),
  };
}

// ─── ①  Mnemonic generation ───────────────────────────────────────────────────

export function workerGenerateMnemonic(strength: 128 | 256 = 256): string {
  return generateMnemonic(wordlist, strength);
}

export function workerValidateMnemonic(mnemonic: string): boolean {
  if (typeof mnemonic !== "string" || mnemonic.length === 0 || mnemonic.length > 512) return false;
  return validateMnemonic(mnemonic.normalize("NFKD").trim(), wordlist);
}

// ─── ②  Key derivation ────────────────────────────────────────────────────────

export async function deriveEVMKey(mnemonic: string): Promise<Uint8Array> {
  const seed = await mnemonicToSeed(mnemonic);
  const root = HDKey.fromMasterSeed(seed);
  const child = root.derive("m/44'/60'/0'/0/0");
  const priv = child.privateKey!.slice();
  wipeBytes(seed); wipeHDKey(root); wipeHDKey(child);
  return priv;
}

export async function deriveEVMAddress(mnemonic: string): Promise<string> {
  const priv = await deriveEVMKey(mnemonic);
  const pub = secp.getPublicKey(priv, false);
  const hash = keccak_256(pub.slice(1));
  wipeBytes(priv);
  return "0x" + bytesToHex(hash.slice(-20));
}

export async function deriveBTCPrivateKey(mnemonic: string): Promise<Uint8Array> {
  const seed = await mnemonicToSeed(mnemonic);
  const root = HDKey.fromMasterSeed(seed);
  const child = root.derive("m/84'/0'/0'/0/0");
  const priv = child.privateKey!.slice();
  wipeBytes(seed); wipeHDKey(root); wipeHDKey(child);
  return priv;
}

export async function deriveBTCAddress(mnemonic: string): Promise<string> {
  const seed = await mnemonicToSeed(mnemonic);
  const root = HDKey.fromMasterSeed(seed);
  const child = root.derive("m/84'/0'/0'/0/0");
  wipeBytes(seed); wipeHDKey(root);
  const p2wpkh = btc.p2wpkh(child.publicKey!, btc.NETWORK);
  wipeHDKey(child);
  if (!p2wpkh.address) throw new Error("Failed to generate SegWit address");
  return p2wpkh.address;
}

/**
 * Derive the Solana private key via SLIP-0010 hardened path m/44'/501'/0'/0.
 * Matches Phantom, Solflare, and Backpack.
 * Caller MUST wipe the returned Uint8Array after use.
 * Does NOT wipe the input `seed` — caller is responsible.
 */
export async function _deriveSolPriv(seed: Uint8Array): Promise<Uint8Array> {
  let I  = hmac(sha512, new TextEncoder().encode("ed25519 seed"), seed);
  let IL = I.slice(0, 32);
  let IR = I.slice(32);
  for (const index of [44, 501, 0, 0]) {
    const data = new Uint8Array(37);
    data[0] = 0;
    data.set(IL, 1);
    const h = (index + 0x80000000) >>> 0;
    data[33] = (h >>> 24) & 0xff;
    data[34] = (h >>> 16) & 0xff;
    data[35] = (h >>>  8) & 0xff;
    data[36] =  h         & 0xff;
    I = hmac(sha512, IR, data);
    const nextIL = I.slice(0, 32);
    IR.fill(0); IR = I.slice(32);
    IL.fill(0); IL = nextIL;
  }
  IR.fill(0);
  return IL;
}

export async function deriveSOLPrivateKey(mnemonic: string): Promise<Uint8Array> {
  const seed = await mnemonicToSeed(mnemonic);
  const priv = await _deriveSolPriv(seed);
  wipeBytes(seed);
  return priv;
}

export async function deriveSOLAddress(mnemonic: string): Promise<string> {
  const seed = await mnemonicToSeed(mnemonic);
  const priv = await _deriveSolPriv(seed);
  wipeBytes(seed);
  const pub  = await nobleEd.getPublicKeyAsync(priv);
  wipeBytes(priv);
  return base58.encode(pub);
}

export async function deriveTRONPrivateKey(mnemonic: string): Promise<Uint8Array> {
  const seed = await mnemonicToSeed(mnemonic);
  const root = HDKey.fromMasterSeed(seed);
  const account = root.derive("m/44'/195'/0'/0/0");
  const priv = account.privateKey!.slice();
  wipeBytes(seed); wipeHDKey(root); wipeHDKey(account);
  return priv;
}

export async function deriveTRONAddress(mnemonic: string): Promise<string> {
  const seed = await mnemonicToSeed(mnemonic);
  const root = HDKey.fromMasterSeed(seed);
  const account = root.derive("m/44'/195'/0'/0/0");
  wipeBytes(seed); wipeHDKey(root);
  const priv = account.privateKey!.slice();
  wipeHDKey(account);
  try {
    const pub = secp.getPublicKey(priv, false);
    const hash = keccak_256(pub.slice(1));
    const addrBytes = new Uint8Array([0x41, ...hash.slice(-20)]);
    const checksum = sha256(sha256(addrBytes)).slice(0, 4);
    const full = new Uint8Array(addrBytes.length + 4);
    full.set(addrBytes); full.set(checksum, addrBytes.length);
    return base58.encode(full);
  } finally { wipeBytes(priv); }
}

const XRP_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
function b58EncodeXRP(input: Uint8Array): string {
  let digits = [0];
  for (let i = 0; i < input.length; i++) {
    let carry = input[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) { digits.push(carry % 58); carry = (carry / 58) | 0; }
  }
  let result = "";
  for (let i = 0; i < input.length && input[i] === 0; i++) result += XRP_ALPHABET[0];
  for (let i = digits.length - 1; i >= 0; i--) result += XRP_ALPHABET[digits[i]];
  return result;
}

export async function deriveXRPAddress(mnemonic: string): Promise<string> {
  const seed = await mnemonicToSeed(mnemonic);
  const root = HDKey.fromMasterSeed(seed);
  const account = root.derive("m/44'/144'/0'/0/0");
  wipeBytes(seed); wipeHDKey(root);
  const pub = account.publicKey!;
  wipeHDKey(account);
  const accountId = ripemd160(sha256(pub));
  const payload = new Uint8Array(21);
  payload[0] = 0x00; payload.set(accountId, 1);
  const checksum = sha256(sha256(payload)).slice(0, 4);
  const final = new Uint8Array(25);
  final.set(payload); final.set(checksum, 21);
  return b58EncodeXRP(final);
}

/**
 * Derive ALL chain addresses from a single mnemonicToSeed call — avoids
 * repeating that derivation 5× when a caller wants every address at once
 * (e.g. wallet-setup screens). Kept alongside the individual derive*Address
 * functions above since it shares their logic; signing.worker.ts's message
 * loop just calls this directly for the "getAllAddresses" case.
 */
export async function deriveAllAddresses(mnemonic: string): Promise<{
  EVM: string; BTC: string; SOL: string; TRX: string; XRP: string;
}> {
  const seed = await mnemonicToSeed(mnemonic);
  const seedCopy = seed.slice(); // HDKey mutates the buffer, so keep an immutable copy
  const root = HDKey.fromMasterSeed(seed);
  const evmChild = root.derive("m/44'/60'/0'/0/0");
  const btcChild = root.derive("m/84'/0'/0'/0/0");
  const trnChild = root.derive("m/44'/195'/0'/0/0");
  const xrpChild = root.derive("m/44'/144'/0'/0/0");

  // EVM
  const evmPub = secp.getPublicKey(evmChild.privateKey!, false);
  const evmAddr = "0x" + bytesToHex(keccak_256(evmPub.slice(1)).slice(-20));

  // BTC — native SegWit (P2WPKH, "bc1q..."), same construction as
  // deriveBTCAddress() above and the signing path in signing.worker.ts.
  const btcP2wpkh = btc.p2wpkh(btcChild.publicKey!, btc.NETWORK);
  if (!btcP2wpkh.address) throw new Error("Failed to generate SegWit address");
  const btcAddr = btcP2wpkh.address;

  // SOL — SLIP-0010
  const solPriv = await _deriveSolPriv(seedCopy);
  const solPub  = await nobleEd.getPublicKeyAsync(solPriv);
  const solAddr = base58.encode(solPub);
  wipeBytes(solPriv);

  // TRX
  const trnPub  = secp.getPublicKey(trnChild.privateKey!, false);
  const trnHash = keccak_256(trnPub.slice(1));
  const trnAddrBytes = new Uint8Array([0x41, ...trnHash.slice(-20)]);
  const trnCs = sha256(sha256(trnAddrBytes)).slice(0, 4);
  const trnFull = new Uint8Array(25); trnFull.set(trnAddrBytes); trnFull.set(trnCs, 21);
  const trnAddr = base58.encode(trnFull);

  // XRP
  const xrpPub     = xrpChild.publicKey!;
  const xrpPayload = new Uint8Array([0x00, ...ripemd160(sha256(xrpPub))]);
  const xrpCs      = sha256(sha256(xrpPayload)).slice(0, 4);
  const xrpFull    = new Uint8Array(25); xrpFull.set(xrpPayload); xrpFull.set(xrpCs, 21);
  const xrpAddr = base58.encode(xrpFull);

  wipeBytes(seed); wipeBytes(seedCopy);
  wipeHDKey(root); wipeHDKey(evmChild); wipeHDKey(btcChild); wipeHDKey(trnChild); wipeHDKey(xrpChild);

  return { EVM: evmAddr, BTC: btcAddr, SOL: solAddr, TRX: trnAddr, XRP: xrpAddr };
}

// ─── ③  Vault encryption (scrypt + AES-256-GCM) ──────────────────────────────

/**
 * Encrypts a secret string (mnemonic or private key) into an EncryptedVault.
 * scrypt runs HERE in the worker — not on the UI thread — so the 1–3s KDF
 * work does not block React rendering or user interactions.
 *
 * Origin binding: when origin is provided it is used as AES-GCM AAD.
 * A phishing clone on a different domain cannot decrypt vaults created here.
 */
function trustedVaultOrigin(origin?: string): string {
  const actual = (self as any).location?.origin as string | undefined;
  if (!actual || actual === "null") throw new Error("Cannot bind vault: worker origin is unavailable");
  if (origin !== undefined && origin !== actual) throw new Error("Vault origin does not match the current application origin");
  return actual;
}

export async function encryptVault(data: string, password: string | Uint8Array, origin?: string, kdfParamsOverride?: KdfParams): Promise<EncryptedVault> {
  if (typeof data !== "string" || data.length === 0 || data.length > 4096) throw new Error("Invalid vault plaintext size");
  const boundOrigin = trustedVaultOrigin(origin);
  const kdfParams = kdfParamsOverride ?? getAdaptiveKdfParams();
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const iv   = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const keyBuffer = await deriveScryptKey(password, salt, kdfParams);
  // Wipe transferred password bytes after KDF (string path already wiped inside deriveScryptKey)
  if (password instanceof Uint8Array) password.fill(0);
  const cryptoKey = await crypto.subtle.importKey("raw", keyBuffer, { name: "AES-GCM" }, false, ["encrypt"]);
  keyBuffer.fill(0);
  const gcmParams: AesGcmParams = { name: "AES-GCM", iv };
  gcmParams.additionalData = new TextEncoder().encode(boundOrigin);
  const ciphertext = await crypto.subtle.encrypt(gcmParams, cryptoKey, new TextEncoder().encode(data));
  return {
    version: 1,
    ciphertext: b64encode(new Uint8Array(ciphertext)),
    iv: b64encode(iv),
    salt: b64encode(salt),
    kdf: "scrypt",
    kdfParams,
    origin: boundOrigin,
  };
}

/**
 * Encrypts multiple vaults with a SINGLE scrypt round.
 * Use for multi-chain wallet creation (6 chains = 6 vaults, 1× KDF cost).
 */
export async function encryptVaultBatch(
  items: Array<{ data: string }>,
  password: string | Uint8Array,
  origin?: string,
  kdfParamsOverride?: KdfParams,
): Promise<EncryptedVault[]> {
  if (!Array.isArray(items) || items.length < 1 || items.length > 16 || items.some(item => !item || typeof item.data !== "string" || item.data.length === 0 || item.data.length > 4096)) {
    throw new Error("Invalid vault batch");
  }
  const boundOrigin = trustedVaultOrigin(origin);
  const kdfParams = kdfParamsOverride ?? getAdaptiveKdfParams();
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const keyBuffer = await deriveScryptKey(password, salt, kdfParams);
  if (password instanceof Uint8Array) password.fill(0);
  const cryptoKey = await crypto.subtle.importKey("raw", keyBuffer, { name: "AES-GCM" }, false, ["encrypt"]);
  keyBuffer.fill(0);

  return Promise.all(items.map(async ({ data }) => {
    const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
    const gcmParams: AesGcmParams = { name: "AES-GCM", iv };
    gcmParams.additionalData = new TextEncoder().encode(boundOrigin);
    const ciphertext = await crypto.subtle.encrypt(gcmParams, cryptoKey, new TextEncoder().encode(data));
    return {
      version: 1,
      ciphertext: b64encode(new Uint8Array(ciphertext)),
      iv: b64encode(iv),
      salt: b64encode(salt),
      kdf: "scrypt" as const,
      kdfParams,
      origin: boundOrigin,
    };
  }));
}

// ─── ④  Vault decryption ──────────────────────────────────────────────────────

/**
 * Decrypts an EncryptedVault.
 * NEVER returns the plaintext to the UI thread if it is a private key.
 * Callers that need to immediately re-use the key (e.g. sign then return only
 * the signed hex) should call the signing handlers directly rather than
 * round-tripping the plaintext through postMessage.
 */
export async function decryptVault(vault: EncryptedVault, password: string | Uint8Array): Promise<string> {
  if (vault.origin) {
    const workerOrigin = (self as any).location?.origin as string | undefined;
    if (workerOrigin && workerOrigin !== vault.origin) {
      throw new Error(`Vault is bound to ${vault.origin} and cannot be opened on ${workerOrigin}`);
    }
  }
  const salt = b64decode(vault.salt);
  const iv = b64decode(vault.iv);
  const ciphertext = b64decode(vault.ciphertext);
  const keyBuffer = await deriveScryptKey(password, salt, vault.kdfParams);
  if (password instanceof Uint8Array) password.fill(0);
  try {
    const cryptoKey = await crypto.subtle.importKey("raw", keyBuffer, { name: "AES-GCM" }, false, ["decrypt"]);
    const gcmParams: AesGcmParams = { name: "AES-GCM", iv };
    if (vault.origin) gcmParams.additionalData = new TextEncoder().encode(vault.origin);
    try {
      const decrypted = await crypto.subtle.decrypt(gcmParams, cryptoKey, ciphertext);
      return new TextDecoder().decode(decrypted);
    } catch {
      throw new Error("Invalid password or corrupted vault data");
    }
  } finally {
    keyBuffer.fill(0);
  }
}

export async function decryptVaultWithRawKey(vault: PasskeyVault, rawKey: ArrayBuffer): Promise<string> {
  if (!vault || vault.version !== 2 || !(rawKey instanceof ArrayBuffer) || rawKey.byteLength !== 32) {
    throw new Error("Invalid passkey vault or raw key");
  }
  const iv         = b64decode(vault.iv);
  const ciphertext = b64decode(vault.ciphertext);
  const cryptoKey  = await crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["decrypt"]);
  try {
    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, ciphertext);
    return new TextDecoder().decode(decrypted);
  } catch {
    throw new Error("Passkey vault decryption failed — passkey may not match");
  }
}

// ─── ④·5  Shared vault-open helper + brute-force lockout ─────────────────────

const _LOCKOUT_MS = 30_000; // 30-second lockout window
const _MAX_FAILS  = 5;
const _failMap    = new Map<string, { count: number; until: number }>();

function _vaultKey(v: EncryptedVault): string {
  return `${v.salt}:${v.ciphertext?.slice(0, 32) ?? "unknown"}`;
}

function _checkAndBumpFails(vault: EncryptedVault): void {
  const key   = _vaultKey(vault);
  const now   = Date.now();
  const entry = _failMap.get(key) ?? { count: 0, until: 0 };
  if (now < entry.until) {
    const secs = Math.ceil((entry.until - now) / 1000);
    throw new Error(`Too many failed attempts. Try again in ${secs} seconds.`);
  }
  entry.count++;
  if (entry.count >= _MAX_FAILS) {
    entry.until = now + _LOCKOUT_MS;
    entry.count = 0;
  }
  _failMap.set(key, entry);
}

function _clearFails(vault: EncryptedVault): void {
  _failMap.delete(_vaultKey(vault));
}

/**
 * Parse + null-check + brute-force-guard + decrypt in one call.
 * Replaces the repeated three-liner across every *FromVault function in
 * signing.worker.ts.
 */
export async function openVault(vault: unknown, password: string | Uint8Array): Promise<string> {
  const parsed = parseVault(vault);
  if (!parsed) throw new Error("Invalid vault format");
  _checkAndBumpFails(parsed);
  let plaintext: string;
  try {
    plaintext = await decryptVault(parsed, password);
  } catch (err) {
    throw err;
  }
  _clearFails(parsed);
  return plaintext;
}

// ─── ⑤  Legacy vault migration ────────────────────────────────────────────────

export async function migrateLegacyVault(legacyData: any, password: string | Uint8Array, userId: string, origin?: string): Promise<EncryptedVault> {
  if (typeof userId !== "string" || userId.length === 0 || userId.length > 256) throw new Error("Invalid userId");
  let mnemonic: string;
  // deriveScryptKey wipes Uint8Array inputs. Keep a separate copy for the
  // re-encryption step so migration does not accidentally encrypt with zeros.
  const migrationPassword = password instanceof Uint8Array ? password.slice() : password;
  try {
  if (typeof legacyData === "string") {
    if (legacyData.length > 100_000) throw new Error("Legacy vault is too large");
    const combined = b64decode(legacyData);
    if (combined.length < 13 || combined.length > 64 * 1024 + 12) throw new Error("Invalid legacy vault size");
    const saltStr   = `pexly_v1_vault_${userId}`;
    const saltBuf   = new TextEncoder().encode(saltStr);
    const keyBuffer = await deriveScryptKey(migrationPassword, saltBuf);
    const iv        = combined.slice(0, 12);
    const ctxt      = combined.slice(12);
    const cryptoKey = await crypto.subtle.importKey("raw", keyBuffer, { name: "AES-GCM" }, false, ["decrypt"]);
    keyBuffer.fill(0);
    const dec = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, ctxt).catch(() => {
      throw new Error("Legacy vault migration failed — wrong password");
    });
    mnemonic = new TextDecoder().decode(dec);
  } else if (legacyData?.version === 1) {
    return legacyData as EncryptedVault;
  } else {
    throw new Error("Unknown vault format");
  }
  // Always re-encrypt at maximum strength — migration runs once, device tier doesn't matter.
  const MAX_KDF: KdfParams = { N: 262_144, r: 8, p: 1, dkLen: 32 };
  const result = await encryptVault(mnemonic, migrationPassword, origin, MAX_KDF);
  return result;
  } finally {
    if (migrationPassword instanceof Uint8Array) migrationPassword.fill(0);
  }
}

// ─── ⑥  Multi-chain wallet creation ──────────────────────────────────────────

/**
 * Returned by createMultiChainWallet (legacy, mnemonic in response for
 * callers that need to display the seed phrase immediately after generation).
 * Prefer createSecureWallet for production flows — it never returns the
 * mnemonic and uses getMnemonicForBackup for the one-time display path.
 */
export interface MultiChainWalletResult {
  mnemonic: string;
  addresses: { EVM: string; BTC: string; SOL: string; TRX: string; XRP: string };
  encryptedVaults: {
    EVM: EncryptedVault; BTC: EncryptedVault; SOL: EncryptedVault;
    TRX: EncryptedVault; XRP: EncryptedVault; mnemonic: EncryptedVault;
  };
}

/**
 * Returned by createSecureWallet — mnemonic is intentionally absent.
 * The mnemonic was generated, encrypted, and wiped entirely inside the worker.
 * Call getMnemonicForBackup(mnemonicVault, password) once on the backup screen.
 */
export interface SecureWalletResult {
  addresses: { EVM: string; BTC: string; SOL: string; TRX: string; XRP: string };
  encryptedVaults: {
    EVM: EncryptedVault; BTC: EncryptedVault; SOL: EncryptedVault;
    TRX: EncryptedVault; XRP: EncryptedVault; mnemonic: EncryptedVault;
  };
  // No `mnemonic` field — it never left the worker
}

/**
 * Legacy mnemonic-returning wallet creation is intentionally disabled. A
 * production wallet must never expose this API because returning the mnemonic
 * makes accidental logging/storage in the caller possible.
 */
export async function createMultiChainWallet(
  _password: string | Uint8Array,
  _origin?: string,
  _existingMnemonic?: string,
): Promise<MultiChainWalletResult> {
  throw new Error("createMultiChainWallet is disabled; use createSecureWallet");
}

async function createSecureWalletInternal(
  password: string | Uint8Array,
  origin?: string,
  existingMnemonic?: string,
): Promise<SecureWalletResult> {
  let mnemonic: string | undefined;
  let seed: Uint8Array | undefined;
  let root: HDKey | undefined;
  let evmPriv: Uint8Array | undefined;
  let btcPriv: Uint8Array | undefined;
  let trnPriv: Uint8Array | undefined;
  let solPriv: Uint8Array | undefined;
  let xrpPriv: Uint8Array | undefined;

  try {
    if (existingMnemonic !== undefined) {
      if (typeof existingMnemonic !== "string" || existingMnemonic.length === 0 || existingMnemonic.length > 512) {
        throw new Error("Invalid recovery phrase");
      }
      mnemonic = existingMnemonic.normalize("NFKD").trim();
      if (!validateMnemonic(mnemonic, wordlist)) throw new Error("Invalid recovery phrase");
    } else {
      mnemonic = generateMnemonic(wordlist, 256);
    }

    seed = await mnemonicToSeed(mnemonic);
    root = HDKey.fromMasterSeed(seed);

    const evmChild = root.derive("m/44'/60'/0'/0/0");
    const btcChild = root.derive("m/84'/0'/0'/0/0");
    const trnChild = root.derive("m/44'/195'/0'/0/0");
    const xrpChild = root.derive("m/44'/144'/0'/0/0");

    evmPriv = evmChild.privateKey!.slice();
    btcPriv = btcChild.privateKey!.slice();
    trnPriv = trnChild.privateKey!.slice();
    xrpPriv = xrpChild.privateKey!.slice();
    solPriv = await _deriveSolPriv(seed);

    const btcPub = btcChild.publicKey!.slice();
    const xrpPub = xrpChild.publicKey!.slice();

    const evmPub = secp.getPublicKey(evmPriv, false);
    const evmAddress = "0x" + bytesToHex(keccak_256(evmPub.slice(1)).slice(-20));

    const p2wpkh = btc.p2wpkh(btcPub, btc.NETWORK);
    if (!p2wpkh.address) throw new Error("BTC address derivation failed");
    const btcAddress = p2wpkh.address;

    const solPub = await nobleEd.getPublicKeyAsync(solPriv);
    const solAddress = base58.encode(solPub);

    const trnPub = secp.getPublicKey(trnPriv, false);
    const trnHash = keccak_256(trnPub.slice(1));
    const trnAddrBytes = new Uint8Array([0x41, ...trnHash.slice(-20)]);
    const trnChecksum = sha256(sha256(trnAddrBytes)).slice(0, 4);
    const trnFull = new Uint8Array(trnAddrBytes.length + 4);
    trnFull.set(trnAddrBytes); trnFull.set(trnChecksum, trnAddrBytes.length);
    const trnAddress = base58.encode(trnFull);

    const xrpAccountId = ripemd160(sha256(xrpPub));
    const xrpPayload = new Uint8Array(21);
    xrpPayload[0] = 0x00; xrpPayload.set(xrpAccountId, 1);
    const xrpChecksum = sha256(sha256(xrpPayload)).slice(0, 4);
    const xrpFinal = new Uint8Array(25);
    xrpFinal.set(xrpPayload); xrpFinal.set(xrpChecksum, 21);
    const xrpAddress = b58EncodeXRP(xrpFinal);

    const privHex = (b: Uint8Array) => bytesToHex(b);
    const [evmVault, btcVault, solVault, trnVault, xrpVault, mnemVault] =
      await encryptVaultBatch([
        { data: privHex(evmPriv) },
        { data: privHex(btcPriv) },
        { data: privHex(solPriv) },
        { data: privHex(trnPriv) },
        { data: privHex(xrpPriv) },
        { data: mnemonic },
      ], password, origin);

    return {
      addresses: { EVM: evmAddress, BTC: btcAddress, SOL: solAddress, TRX: trnAddress, XRP: xrpAddress },
      encryptedVaults: { EVM: evmVault, BTC: btcVault, SOL: solVault, TRX: trnVault, XRP: xrpVault, mnemonic: mnemVault },
    };
  } finally {
    if (seed) wipeBytes(seed);
    if (root) wipeHDKey(root);
    if (evmPriv) wipeBytes(evmPriv);
    if (btcPriv) wipeBytes(btcPriv);
    if (trnPriv) wipeBytes(trnPriv);
    if (solPriv) wipeBytes(solPriv);
    if (xrpPriv) wipeBytes(xrpPriv);
  }
}

// ─── ⑩  Hashing utilities ─────────────────────────────────────────────────────

function decodeWorkerHex(value: unknown, name: string, maxBytes = 64 * 1024): Uint8Array {
  if (typeof value !== "string" || value.length > maxBytes * 2 + 2) throw new Error(`Invalid ${name}`);
  const stripped = value.startsWith("0x") ? value.slice(2) : value;
  if (stripped.length % 2 || !/^[0-9a-fA-F]*$/.test(stripped)) throw new Error(`Invalid ${name}`);
  if (stripped.length / 2 > maxBytes) throw new Error(`${name} is too large`);
  return new Uint8Array(stripped.match(/.{2}/g)?.map(b => parseInt(b, 16)) ?? []);
}

export function workerHash(algorithm: "keccak256" | "sha256" | "sha512" | "ripemd160", hex: string): string {
  const input = decodeWorkerHex(hex, "hex");
  try {
    switch (algorithm) {
      case "keccak256": return "0x" + bytesToHex(keccak_256(input));
      case "sha256": return "0x" + bytesToHex(sha256(input));
      case "sha512": return "0x" + bytesToHex(sha512(input));
      case "ripemd160": return "0x" + bytesToHex(ripemd160(input));
      default: throw new Error("Unknown hash algorithm");
    }
  } finally { input.fill(0); }
}

export function workerHmacSha256(keyHex: string, dataHex: string): string {
  const key = decodeWorkerHex(keyHex, "HMAC key", 256);
  const data = decodeWorkerHex(dataHex, "HMAC data");
  try { return "0x" + bytesToHex(hmac(sha256, key, data)); }
  finally { key.fill(0); data.fill(0); }
}

// ─── ⑪  Validate a vault password (timing-safe: full scrypt every time) ───────

export async function validateVaultPassword(vault: EncryptedVault | PasskeyVault | unknown, password: string | Uint8Array): Promise<boolean> {
  const parsed = parseVault(vault);
  if (!parsed) return false;
  _checkAndBumpFails(parsed);
  try {
    await decryptVault(parsed, password);
    _clearFails(parsed);
    return true;
  } catch {
    return false;
  }
}

// ─── ⑫  Secure wallet creation (mnemonic NEVER in postMessage response) ───────
//
// Architecture:
//   1. Mnemonic is generated or accepted as existingMnemonic entirely inside worker.
//   2. All private keys and the mnemonic itself are encrypted to vaults.
//   3. Only SecureWalletResult (addresses + vaults) is returned — no `mnemonic` field.
//   4. To show the seed phrase backup screen, call getMnemonicForBackup(vault, pw)
//      exactly once; that is the only controlled crossing of the mnemonic.

export async function createSecureWallet(
  password: string | Uint8Array,
  origin?: string,
  existingMnemonic?: string,
): Promise<SecureWalletResult> {
  return createSecureWalletInternal(password, origin, existingMnemonic);
}

// ─── ⑬  One-time mnemonic backup display ──────────────────────────────────────
//
// Decrypts the mnemonic vault and returns the plaintext phrase.
// This is the ONLY path where the mnemonic crosses the postMessage wire.
// The caller must:
//   • Display it in a non-copyable, screenshot-blocked UI if possible.
//   • Immediately discard it from component state after the user confirms backup.
//   • Never write it to localStorage, a database, or any log.

const _backupConsumed = new Set<string>();
const _backupInProgress = new Set<string>();

function backupVaultId(vault: EncryptedVault): string {
  return bytesToHex(sha256(new TextEncoder().encode(vault.salt + ":" + vault.ciphertext)));
}

export async function getMnemonicForBackup(
  vault: EncryptedVault | unknown,
  password: string | Uint8Array,
): Promise<string> {
  const parsed = parseVault(vault);
  if (!parsed) throw new Error("Invalid mnemonic vault");
  const key = backupVaultId(parsed);
  if (_backupConsumed.has(key) || _backupInProgress.has(key)) {
    throw new Error("Mnemonic backup has already been displayed for this vault in this Worker session");
  }
  _backupInProgress.add(key);
  try {
    const mnemonic = await decryptVault(parsed, password);
    if (!validateMnemonic(mnemonic, wordlist)) {
      throw new Error("Decrypted data is not a valid BIP-39 mnemonic — wrong password or corrupted vault");
    }
    _backupConsumed.add(key);
    return mnemonic;
  } catch (err) {
    _backupConsumed.delete(key);
    throw err;
  } finally {
    _backupInProgress.delete(key);
  }
}
