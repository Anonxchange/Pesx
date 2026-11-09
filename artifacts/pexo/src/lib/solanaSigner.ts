/**
 * solanaSigner.ts — Solana broadcast + supporting read helpers.
 *
 * IMPORTANT: this file does NOT sign anything and never sees a private key
 * or mnemonic. All Solana signing happens exclusively inside
 * signing.worker.ts (handleSignSolanaTransaction), which returns a finished,
 * base58-encoded signed transaction wire packet. This file's job is:
 *   1. Supply the recent blockhash needed to *build* an unsigned transaction
 *      before it's sent to the worker to be signed.
 *   2. Broadcast the worker's already-signed output to the network.
 *   3. Resolve a wallet's existing SPL Associated Token Account for a mint
 *      (needed for the `fromTokenAccount`/`toTokenAccount` fields the
 *      worker's SPL transfer path requires).
 *
 * Reconstructed after the original solanaSigner.ts (which mixed signing and
 * these read/broadcast helpers) was deleted as part of moving all signing
 * into the worker. Only the non-signing pieces are rebuilt here, routed
 * through the chain-gateway edge function instead of a public RPC node.
 */

import { chainRpc, chainBroadcast } from "./chain-gateway";

/**
 * Fetches a recent blockhash — required to build an unsigned Solana
 * transaction message before handing it to the worker to sign.
 */
export async function getLatestBlockhash(): Promise<string> {
  const result = await chainRpc("SOL", "getLatestBlockhash", [{ commitment: "finalized" }]);
  const blockhash = result?.value?.blockhash;
  if (!blockhash || typeof blockhash !== "string") {
    throw new Error("chain-gateway returned no Solana blockhash");
  }
  return blockhash;
}

/**
 * Broadcasts an already-signed Solana transaction to the network.
 *
 * @param signedTx  The base58-encoded signed wire packet — exactly the
 *                   `signedTx` field returned by the worker's
 *                   handleSignSolanaTransaction.
 * @returns          The transaction signature (Solana's equivalent of a tx hash).
 */
export async function broadcastSolanaTransaction(signedTx: string): Promise<{ signature: string }> {
  if (!signedTx) {
    throw new Error("broadcastSolanaTransaction: signedTx is required");
  }

  const response = await chainBroadcast("SOL", "sendTransaction", [
    signedTx,
    { encoding: "base58", skipPreflight: false, preflightCommitment: "confirmed" },
  ]);
  const signature = typeof response === "string" ? response : response?.result;

  if (!signature || typeof signature !== "string") {
    throw new Error("chain-gateway did not return a Solana transaction signature");
  }

  return { signature };
}

/**
 * Resolves `owner`'s existing SPL Associated Token Account for `mint`, by
 * querying the network rather than deriving the PDA address offline. This is
 * deliberate: an ATA address can be *computed* even if the account was never
 * actually created on-chain, and sending to an uninitialized token account
 * fails. Querying confirms the account genuinely exists before the caller
 * tries to use it as a transfer source or destination.
 *
 * @returns The token account's address, or null if the owner has no
 *          initialized token account for this mint (the caller must handle
 *          that case — e.g. by including an ATA-creation instruction, or by
 *          surfacing "recipient has no account for this token yet").
 */
export async function getUserTokenAccount(owner: string, mint: string): Promise<string | null> {
  const result = await chainRpc("SOL", "getTokenAccountsByOwner", [
    owner,
    { mint },
    { encoding: "jsonParsed" },
  ]);
  const accounts = result?.value;
  if (!Array.isArray(accounts) || accounts.length === 0) return null;
  const pubkey = accounts[0]?.pubkey;
  return typeof pubkey === "string" ? pubkey : null;
}
