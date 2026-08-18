import { Buffer } from "node:buffer";
import {
  verifyEip191EoaSignature,
} from "../identity/identityCrypto";
import type {
  WalletProofVerdict,
  WalletProofVerificationRequest,
  WalletProofVerifierPort,
} from "../identity/walletProofVerifier";
import type { JsonRpcTransport } from "./jsonRpc";
import { providerQuorumHash, readCodeAtBlock } from "./quorumReads";

export interface RatifiedChainProfile {
  readonly chainId: string;
  readonly finalityProfileId: string;
  readonly finalityProfileRevision: string;
  readonly finalityProfileHash: Buffer;
  readonly transports: readonly JsonRpcTransport[];
  readonly minimumProviderQuorum: number;
}

const HEX_QUANTITY = /^0x(0|[1-9a-f][0-9a-f]*)$/;
const HEX_HASH = /^0x[0-9a-f]{64}$/;

/**
 * The production wallet-proof verifier over ADR 0005 quorum reads. One
 * recorded finalized chain state anchors the method decision: the
 * quorum's lowest finalized head is read with hash agreement at that
 * height, then eth_getCode at that exact block picks the method - empty
 * code dispatches to local EIP-191 EOA recovery; any contract code is
 * unavailable because this deployment has no bounded ERC-1271/6492
 * execution. No method ever falls back to another, and every provider
 * failure or disagreement is unavailable, never a guess.
 */
export function createQuorumWalletProofVerifier(
  profiles: readonly RatifiedChainProfile[],
): WalletProofVerifierPort {
  const byChain = new Map(profiles.map((profile) => [profile.chainId, profile]));
  return Object.freeze({
    async verify(request: WalletProofVerificationRequest): Promise<WalletProofVerdict> {
      const unavailable = Object.freeze({ status: "unavailable" as const });
      const profile = byChain.get(request.chainId);
      if (!profile || profile.transports.length < profile.minimumProviderQuorum) {
        return unavailable;
      }

      let finalizedNumbers: bigint[];
      try {
        finalizedNumbers = await Promise.all(
          profile.transports.map(async (transport) => {
            const block = (await transport.request("eth_getBlockByNumber", [
              "finalized",
              false,
            ])) as Record<string, unknown> | null;
            const number = String(block?.number).toLowerCase();
            if (!HEX_QUANTITY.test(number)) {
              throw new Error("Malformed finalized head.");
            }
            return BigInt(number);
          }),
        );
      } catch {
        return unavailable;
      }
      const lowestFinalized = finalizedNumbers.reduce((lowest, number) =>
        number < lowest ? number : lowest,
      );

      let hashesAtHeight: string[];
      try {
        hashesAtHeight = await Promise.all(
          profile.transports.map(async (transport) => {
            const block = (await transport.request("eth_getBlockByNumber", [
              `0x${lowestFinalized.toString(16)}`,
              false,
            ])) as Record<string, unknown> | null;
            const hash = String(block?.hash).toLowerCase();
            if (!HEX_HASH.test(hash)) {
              throw new Error("Malformed block hash.");
            }
            return hash;
          }),
        );
      } catch {
        return unavailable;
      }
      if (new Set(hashesAtHeight).size !== 1) return unavailable;

      const code = await readCodeAtBlock(
        profile.transports,
        profile.minimumProviderQuorum,
        request.address.toLowerCase(),
        lowestFinalized,
      );
      if (code.status !== "ok") return unavailable;
      if (code.code.byteLength !== 0) {
        // A contract wallet needs bounded ERC-1271/6492 execution.
        return unavailable;
      }

      if (
        !verifyEip191EoaSignature(
          request.message,
          request.signature,
          request.address,
        )
      ) {
        return Object.freeze({ status: "invalid" as const });
      }
      return Object.freeze({
        status: "verified" as const,
        method: "eoa" as const,
        finality: Object.freeze({
          finalityProfileId: profile.finalityProfileId,
          finalityProfileRevision: profile.finalityProfileRevision,
          finalityProfileHash: profile.finalityProfileHash,
          finalizedChainId: profile.chainId,
          finalizedBlock: lowestFinalized.toString(10),
          finalizedBlockHash: Buffer.from(hashesAtHeight[0].slice(2), "hex"),
          providerQuorumHash: providerQuorumHash(
            profile.transports.map((transport) => transport.providerId),
          ),
        }),
      });
    },
  });
}
