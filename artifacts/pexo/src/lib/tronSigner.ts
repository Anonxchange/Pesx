/**
 * tronSigner.ts — Tron broadcast helper.
 *
 * IMPORTANT: this file does NOT sign anything and never sees a private key
 * or mnemonic. All Tron signing happens exclusively inside
 * signing.worker.ts (handleSignTronTransaction), which returns a finished,
 * signed transaction as a JSON string (the TransferContract payload plus its
 * signature). This file's only job is to hand that already-signed payload to
 * TronGrid via the chain-gateway edge function instead of calling
 * trongrid.io directly.
 *
 * Reconstructed after the original tronSigner.ts (which mixed signing and
 * broadcasting) was deleted as part of moving all signing into the worker.
 * Only the broadcast piece is rebuilt here.
 */

import { tronBroadcast } from "./chain-gateway";

/**
 * Broadcasts an already-signed Tron transaction to the network.
 *
 * @param signedTx  The signed transaction — accepts either the JSON string
 *                   form returned directly by the worker's
 *                   handleSignTronTransaction (`signedTx` field), or an
 *                   already-parsed object, for callers that parsed it
 *                   themselves upstream.
 * @returns          The broadcast transaction ID.
 */
export async function broadcastTronTransaction(
  signedTx: string | Record<string, unknown>,
): Promise<{ txID: string }> {
  const tx = typeof signedTx === "string" ? JSON.parse(signedTx) : signedTx;

  // TronGrid's /wallet/broadcasttransaction returns
  // { result: true, txid: "..." } on success, or
  // { result: false, code, message } (message is typically hex-encoded) on failure.
  const response = await tronBroadcast(tx);

  if (response?.result === false || response?.code) {
    const reason = typeof response?.message === "string" ? response.message : "Tron broadcast rejected";
    throw new Error(`Tron broadcast failed: ${reason}`);
  }

  const txID = response?.txid ?? response?.txID ?? (tx as Record<string, unknown>)?.txID;
  if (!txID || typeof txID !== "string") {
    throw new Error("Tron broadcast did not return a transaction ID");
  }

  return { txID: txID as string };
}
