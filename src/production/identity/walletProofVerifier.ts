import { verifyEip191EoaSignature } from "./identityCrypto";

/**
 * Wallet proof dispatch (identity-and-entitlement.md section 4.3): the
 * verifier resolves code at one recorded finalized block and dispatches to
 * exactly one method. EOA recovery is local; ERC-1271 and ERC-6492 need
 * bounded chain execution, so any adapter without that capability MUST
 * report unavailable rather than guessing — no method ever falls back to
 * another, and unavailable grants nothing.
 */
export type WalletProofVerdict =
  | {
      readonly status: "verified";
      readonly method: "eoa" | "erc1271" | "erc6492";
      readonly finality: {
        readonly finalityProfileId: string;
        readonly finalityProfileRevision: string;
        readonly finalityProfileHash: Buffer;
        readonly finalizedChainId: string;
        readonly finalizedBlock: string;
        readonly finalizedBlockHash: Buffer;
        readonly providerQuorumHash: Buffer;
      };
    }
  | { readonly status: "invalid" }
  | { readonly status: "unavailable" };

export interface WalletProofVerificationRequest {
  readonly chainId: string;
  readonly address: string;
  readonly message: string;
  readonly signature: unknown;
}

export interface WalletProofVerifierPort {
  readonly verify: (
    request: WalletProofVerificationRequest,
  ) => Promise<WalletProofVerdict>;
}

/** Production default: no chain access is configured, so nothing verifies. */
export function createUnavailableWalletProofVerifier(): WalletProofVerifierPort {
  return Object.freeze({
    verify: async () => Object.freeze({ status: "unavailable" as const }),
  });
}

export interface FictionalChainState {
  /** Addresses treated as having contract code at the recorded block. */
  readonly contractAddresses?: readonly string[];
  readonly finalityProfileId: string;
  readonly finalityProfileRevision: string;
  readonly finalityProfileHash: Buffer;
  readonly finalizedChainId: string;
  readonly finalizedBlock: string;
  readonly finalizedBlockHash: Buffer;
  readonly providerQuorumHash: Buffer;
}

/**
 * Fictional-data verifier for labs: every address is codeless unless listed,
 * EOA signatures verify locally against the exact message, and any contract
 * wallet is reported unavailable because the lab has no bounded ERC-1271 or
 * ERC-6492 execution environment. This mirrors the fail-closed production
 * requirement rather than simulating chain calls it cannot make honestly.
 */
export function createFictionalWalletProofVerifier(
  state: FictionalChainState,
): WalletProofVerifierPort {
  const contracts = new Set(
    (state.contractAddresses ?? []).map((address) => address.toLowerCase()),
  );
  const finality = Object.freeze({
    finalityProfileId: state.finalityProfileId,
    finalityProfileRevision: state.finalityProfileRevision,
    finalityProfileHash: state.finalityProfileHash,
    finalizedChainId: state.finalizedChainId,
    finalizedBlock: state.finalizedBlock,
    finalizedBlockHash: state.finalizedBlockHash,
    providerQuorumHash: state.providerQuorumHash,
  });
  return Object.freeze({
    verify: async (request: WalletProofVerificationRequest) => {
      if (request.chainId !== state.finalizedChainId) {
        return Object.freeze({ status: "unavailable" as const });
      }
      if (contracts.has(request.address.toLowerCase())) {
        return Object.freeze({ status: "unavailable" as const });
      }
      return verifyEip191EoaSignature(
        request.message,
        request.signature,
        request.address,
      )
        ? Object.freeze({ status: "verified" as const, method: "eoa" as const, finality })
        : Object.freeze({ status: "invalid" as const });
    },
  });
}
