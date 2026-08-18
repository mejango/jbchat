import type { NextConfig } from "next";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { loadWebSecurityConfig } from "./src/server/security/config";
import { buildWebSecurityHeaderRules } from "./src/server/security/headers";

const appRoot = dirname(fileURLToPath(import.meta.url));
const webSecurityConfig = loadWebSecurityConfig(process.env);
const allowedDevOrigins = [
  ...(webSecurityConfig.mode === "local-lab"
    ? ["localhost", "127.0.0.1"]
    : []),
  ...parseAllowedPrivateDevHosts(
    process.env.JUICEBOX_MESSAGING_ALLOWED_NEXT_DEV_HOSTS,
  ),
];
const webSecurityHeaderRules = buildWebSecurityHeaderRules(
  webSecurityConfig,
  process.env.NODE_ENV === "development" ? "development" : "production",
);

const nextConfig: NextConfig = {
  ...(allowedDevOrigins.length > 0 ? { allowedDevOrigins } : {}),
  output: "standalone",
  // Para dynamically imports optional peers this deployment never uses;
  // resolve them to empty modules, point Para's wagmi-barrel import at
  // core, and swap Coinbase's HeartbeatWorker for the vendored copy whose
  // final line the classic-worker minifier accepts. Mirrors
  // webclients/juicebox-money/next.config.js - the build must run with
  // --webpack for these to apply.
  webpack: (config, { webpack }) => {
    const empty: string[] = [
      "@farcaster/miniapp-sdk",
      "@farcaster/miniapp-wagmi-connector",
      "@getpara/cosmos-wallet-connectors",
      "@getpara/evm-wallet-connectors",
      "@getpara/solana-wallet-connectors",
      "@x402/core",
      "@x402/evm",
      "@x402/svm",
      "@react-native-async-storage/async-storage",
      "pino-pretty",
      ...[
        "alchemy",
        "biconomy",
        "cdp",
        "gelato",
        "pimlico",
        "porto",
        "rhinestone",
        "safe",
        "thirdweb",
        "zerodev",
      ].map((provider) => `@getpara/aa-${provider}`),
    ];
    for (const specifier of empty) {
      config.resolve.alias[specifier] = false;
    }
    config.resolve.alias["wagmi/connectors$"] = "@wagmi/core";
    config.plugins.push(
      new webpack.NormalModuleReplacementPlugin(
        /[\/]HeartbeatWorker(\.js)?$/,
        `${appRoot}/src/vendor/HeartbeatWorker.js`,
      ),
    );
    return config;
  },
  outputFileTracingRoot: appRoot,
  poweredByHeader: false,
  reactStrictMode: true,
  async headers() {
    return webSecurityHeaderRules.map((rule) => ({
      source: rule.source,
      headers: [...rule.headers],
    }));
  },
};

function parseAllowedPrivateDevHosts(value: string | undefined): string[] {
  if (!value) return [];
  const hosts = value.split(",").map((host) => host.trim());
  if (hosts.some((host) => !isPrivateIpv4(host))) {
    throw new Error(
      "JUICEBOX_MESSAGING_ALLOWED_NEXT_DEV_HOSTS must contain only private IPv4 hosts.",
    );
  }
  return [...new Set(hosts)];
}

function isPrivateIpv4(value: string): boolean {
  const octets = value.split(".");
  if (
    octets.length !== 4 ||
    octets.some(
      (octet) =>
        !/^(0|[1-9]\d{0,2})$/.test(octet) || Number(octet) > 255,
    )
  ) {
    return false;
  }
  const [first, second] = octets.map(Number);
  return (
    first === 10 ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168)
  );
}

export default nextConfig;
