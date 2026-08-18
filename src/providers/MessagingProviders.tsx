"use client";

import { useState, type ReactNode } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { WagmiProvider, createConfig, http, type CreateConnectorFn } from "wagmi";
import {
  arbitrum,
  arbitrumSepolia,
  base,
  baseSepolia,
  mainnet,
  optimism,
  optimismSepolia,
  sepolia,
} from "wagmi/chains";
import { injected } from "@wagmi/core";
import { coinbaseWallet } from "wagmi/connectors/coinbaseWallet";
import { walletConnect } from "wagmi/connectors/walletConnect";

export const SUPPORTED_CHAINS = [
  mainnet,
  optimism,
  base,
  arbitrum,
  sepolia,
  optimismSepolia,
  baseSepolia,
  arbitrumSepolia,
] as const;

function connectors(): CreateConnectorFn[] {
  const list: CreateConnectorFn[] = [injected({ shimDisconnect: true })];
  list.push(
    coinbaseWallet({ appName: "Juicebox Messaging" }),
  );
  const walletConnectProjectId =
    process.env.NEXT_PUBLIC_WALLET_CONNECT_PROJECT_ID;
  if (walletConnectProjectId) {
    list.push(
      walletConnect({
        projectId: walletConnectProjectId,
        metadata: {
          name: "Juicebox Messaging",
          description: "Private project support over Juicebox",
          url:
            typeof window === "undefined"
              ? "https://app-production-bbdd.up.railway.app"
              : window.location.origin,
          icons: [],
        },
        showQrModal: true,
      }),
    );
  }
  return list;
}

const transports = Object.fromEntries(
  SUPPORTED_CHAINS.map((chain) => [chain.id, http()]),
) as Record<(typeof SUPPORTED_CHAINS)[number]["id"], ReturnType<typeof http>>;

export const wagmiConfig = createConfig({
  chains: SUPPORTED_CHAINS,
  transports,
  connectors: connectors(),
  ssr: true,
});

/**
 * Para joins the connector set lazily, exactly like juicebox.money: the
 * SDK loads only when a key is configured and the user picks Para, so
 * the anonymous page never pays for it. Without
 * NEXT_PUBLIC_PARA_API_KEY the option stays hidden.
 */
export async function connectWithPara(): Promise<void> {
  const apiKey = process.env.NEXT_PUBLIC_PARA_API_KEY;
  if (!apiKey) throw new Error("para_not_configured");
  const [{ paraConnector }, { ParaWeb }, core] = await Promise.all([
    import("@getpara/wagmi-v2-connector"),
    import("@getpara/web-sdk"),
    import("@wagmi/core"),
  ]);
  const para = new ParaWeb(
    (process.env.NEXT_PUBLIC_PARA_ENV as never) ?? "BETA",
    apiKey,
  );
  const connector = wagmiConfig._internal.connectors.setup(
    paraConnector({
      para: para as never,
      appName: "Juicebox Messaging",
      options: {},
      transports,
    }) as never,
  );
  await core.connect(wagmiConfig, {
    connector: connector as Parameters<typeof core.connect>[1]["connector"],
  });
}

export function isParaAvailable(): boolean {
  return Boolean(process.env.NEXT_PUBLIC_PARA_API_KEY);
}

export function MessagingProviders({ children }: { children: ReactNode }) {
  const [queryClient] = useState(() => new QueryClient());
  return (
    <WagmiProvider config={wagmiConfig} reconnectOnMount>
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    </WagmiProvider>
  );
}
