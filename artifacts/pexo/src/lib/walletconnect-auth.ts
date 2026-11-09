import { getSupabase } from "@/lib/supabase";

/**
 * Authenticate with an EIP-4361 message signed through WalletConnect.
 * Supabase verifies the signed message and creates the auth session; no
 * wallet address is trusted by the client on its own.
 */
export async function signInWithWalletConnect(captchaToken: string | null) {
  const projectId = import.meta.env.VITE_WALLETCONNECT_PROJECT_ID?.trim();
  if (!projectId) {
    throw new Error(
      "WalletConnect is not configured yet. Add VITE_WALLETCONNECT_PROJECT_ID to the project environment.",
    );
  }

  if (!import.meta.env.VITE_SUPABASE_URL || !import.meta.env.VITE_SUPABASE_ANON_KEY) {
    throw new Error("Supabase authentication is not configured yet.");
  }

  const { EthereumProvider } = await import("@walletconnect/ethereum-provider");
  const provider = await EthereumProvider.init({
    projectId,
    chains: [1],
    showQrModal: true,
    methods: ["personal_sign"],
    events: ["accountsChanged", "chainChanged"],
    metadata: {
      name: "Pexly",
      description: "Sign in securely to Pexly.",
      url: window.location.origin,
      icons: [],
    },
  });

  try {
    await provider.connect();

    const supabase = await getSupabase();
    const { data, error } = await supabase.auth.signInWithWeb3({
      chain: "ethereum",
      // The Supabase SDK consumes the EIP-1193 request methods below. Its
      // declared provider type also requires an unused `address` property.
      wallet: provider as any,
      statement:
        "Sign in to Pexly with the Ethereum account shown here. This message does not authorize a transaction.",
      options: {
        captchaToken: captchaToken ?? undefined,
        url: `${window.location.origin}${window.location.pathname}`,
      },
    });

    if (error) throw error;
    if (!data.user || !data.session) {
      throw new Error("Wallet sign-in did not create an active session.");
    }

    return data.user;
  } finally {
    // WalletConnect is used only for the authentication signature here; the
    // app does not retain a connected provider after the login attempt.
    try {
      await provider.disconnect();
    } catch {
      // A provider can already be disconnected when the user cancels pairing.
    }
  }
}
