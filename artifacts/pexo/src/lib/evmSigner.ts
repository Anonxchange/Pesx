/**
 * evmSigner.ts — EVM broadcast helper.
 *
 * IMPORTANT: this file does NOT sign anything and never sees a private key
 * or mnemonic. All EVM signing now happens exclusively inside
 * signing.worker.ts (handleSignEVMTransaction / handleSignEVMContractCall),
 * which returns a finished, 0x-prefixed signed raw transaction hex string.
 * This file's only job is to hand that already-signed hex to the network via
 * the chain-gateway edge function (Alchemy-backed) instead of calling a
 * public RPC node directly.
 *
 * Reconstructed after the original evmSigner.ts (which mixed signing and
 * broadcasting) was deleted as part of moving all signing into the worker.
 * Only the broadcast piece is rebuilt here — see the code comment history
 * for context. TOKEN_CONTRACTS is duplicated (not imported) from
 * signing.worker.ts deliberately: importing from the worker file would pull
 * the whole crypto worker bundle (scrypt, secp256k1, etc.) into the main
 * thread bundle, which defeats the point of keeping that code worker-isolated.
 */

import { chainBroadcast } from "./chain-gateway";

/**
 * ERC-20 token contract addresses + decimals, keyed the same way the signing
 * worker keys them (e.g. "USDT_ETH", "USDC_BSC"). Keep this in sync with the
 * TOKEN_CONTRACTS constant in signing.worker.ts if new tokens/chains are added.
 */
export const TOKEN_CONTRACTS: Record<string, { address: string; decimals: number }> = {
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

/**
 * Broadcasts an already-signed raw EVM transaction to the network.
 *
 * @param chain       Chain key as used elsewhere in the app (e.g. "ETH",
 *                     "BSC"/"BNB", "ARB", "POL"/"MATIC", "AVAX").
 * @param signedTxHex The 0x-prefixed signed raw tx hex — this is exactly the
 *                     `signedTx` field returned by the worker's
 *                     handleSignEVMTransaction / handleSignEVMContractCall.
 * @returns            The transaction hash the network assigned on broadcast.
 */
export async function broadcastEVMTransaction(
  chain: string,
  signedTxHex: string,
): Promise<{ txHash: string }> {
  if (!signedTxHex || !signedTxHex.startsWith("0x")) {
    throw new Error("broadcastEVMTransaction: signedTxHex must be a 0x-prefixed hex string");
  }

  // chainBroadcast (unlike chainRpc) does not unwrap the JSON-RPC envelope
  // for the caller, so we handle both a bare string and a {result} envelope.
  const response = await chainBroadcast(chain, "eth_sendRawTransaction", [signedTxHex]);
  const txHash =
    typeof response === "string" ? response
    : response?.result ?? response?.txHash;

  if (!txHash || typeof txHash !== "string") {
    throw new Error("chain-gateway did not return a transaction hash for the broadcast");
  }

  return { txHash };
}
