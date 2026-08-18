import { Buffer } from "node:buffer";
import {
  buildFanoutEvidence,
  commandTrustMatchesSnapshot,
  convertQuotaCapacity,
  httpIdempotencyScopeKey as httpIdempotencyScope,
  semanticEnvelopeKeyOf as semanticEnvelopeKey,
  signerFenceExpectationFor,
} from "./appendPersistence";
import {
  createFictionalDeliveryCryptoPorts,
  parsePolicyEvidenceForSnapshot,
  verifyFictionalDeliveryLabReceiptSignatureForTesting,
  type DeliveryLabSignerHistoryEntry,
  type FictionalDeliveryCryptoPorts,
} from "./fictionalCryptoPorts.testing";
import {
  applicationEnvelopeSemanticallyEqual,
  enforceApplicationAppendDeliveryLimits,
  enforceStoredEnvelopeDeliveryLimits,
  parseStoredEnvelope,
  type ApplicationEnvelopeSemanticIdentity,
  type StoredApplicationEnvelope,
} from "./envelopes";
import {
  computeEnvelopeLeafHash,
  computeLogHeadHash,
  canonicalLengthPrefixed,
  sha256Bytes,
} from "./hashes";
import { classifyHttpIdempotencyCommitment } from "./idempotency";
import {
  parseApplicationAppendReservationFence,
  parseApplicationAppendSignerFenceResolution,
  parseApplicationAppendSignerFenceVerificationEvidence,
  parseDurableApplicationAppendSignerFenceSignedResolution,
  type ApplicationAppendReservationFence,
  type ApplicationAppendSignerFenceResolution,
  type ApplicationAppendSignerFenceVerificationEvidence,
  type AtomicApplicationAppendCommand,
  type AtomicApplicationAppendReservation,
  type AtomicDeliveryPersistencePort,
  type DeliveryCheckpointSignatureVerificationRequest,
  type DeliveryCheckpointSigningRequest,
  type DeliveryInvocationContext,
  type FinalizeApplicationAppendInput,
  type PrepareUnsignedApplicationAppend,
  type ProductionDeliveryPorts,
  type RetireExpiredApplicationAppendInput,
} from "./ports";
import {
  acceptedApplicationAppendIntentFromPending,
  computeAtomicApplicationAppendCommandDigest,
  parseAtomicApplicationAppendCommand,
  parseMlsApplicationWireInspectionEvidence,
  parsePendingApplicationAppendIntent,
  parsePreparedApplicationAppend,
  receiptFromStoredApplicationEnvelope,
  type AcceptedApplicationAppendIntent,
  type ApplicationEnvelopeReceipt,
  type PendingApplicationAppendIntent,
} from "./service";
import {
  computeApplicationAppendMlsRosterHash,
  computeApplicationAppendRecipientSetHash,
  computeLockedApplicationAppendSnapshotDigest,
  parseApplicationAppendFanoutPlan,
  parseApplicationAppendMlsRosterProjections,
  parseApplicationAppendRecipientProjections,
  parseLockedApplicationAppendSnapshot,
  refreshLockedApplicationAppendAuthorizationSnapshot,
  type ApplicationAppendFanoutEvidence,
  type ApplicationAppendFanoutPlan,
  type ApplicationAppendMlsRosterProjection,
  type ApplicationAppendRecipientProjection,
  type LockedApplicationAppendSnapshot,
  type LockedConversationUsage,
} from "./state";
import {
  parseDeliveryCheckpointSignatureEvidence,
  parseDeliveryRealmId,
  type DeliveryCheckpointSignatureEvidence,
} from "./sync";
import {
  ZERO_HASH32,
  expectExactRecord,
  parseAccountId,
  parseAttachmentId,
  parseConversationId,
  parseEd25519Signature,
  parseEnvelopeId,
  parseHash32,
  parseInstallationId,
  parseRfc3339Millis,
  parseSigningKeyId,
  parseUint63String,
  uint63FromBigInt,
  type AccountId,
  type AttachmentId,
  type ConversationId,
  type Ed25519Signature,
  type EnvelopeId,
  type Hash32,
  type InstallationId,
  type Rfc3339Millis,
  type SigningKeyId,
  type Uint63String,
} from "./valueObjects";

export {
  FICTIONAL_DELIVERY_LAB_ED25519_PUBLIC_KEY_SPKI_BASE64URL,
  verifyFictionalDeliveryLabReceiptSignatureForTesting,
  type DeliveryLabSignerHistoryEntry,
} from "./fictionalCryptoPorts.testing";

const HTTP_IDEMPOTENCY_TTL_MILLISECONDS = 7 * 24 * 60 * 60 * 1_000;
const TRANSACTION_DEADLINE_MARGIN_MILLISECONDS = 250;
const FICTIONAL_FENCE_TOKEN_DOMAIN =
  "jbm-fictional-lab-application-append-fence-token/v1";

export const DELIVERY_LAB_FAILPOINTS = [
  "before-reservation-prepare",
  "after-reservation-prepare",
  "before-reservation-commit",
  "after-reservation-commit-before-response",
  "before-signer-call",
  "after-signer-call",
  "before-signature-verifier-call",
  "after-signature-verifier-call",
  "after-state-write",
  "after-envelope-write",
  "after-mailbox-write",
  "after-outbox-write",
  "after-secondary-write",
  "after-idempotency-write",
  "before-finalization-commit",
  "after-finalization-commit-before-response",
] as const;

export type DeliveryLabFailpoint = (typeof DELIVERY_LAB_FAILPOINTS)[number];

export class DeliveryLabFaultInjectedError extends Error {
  readonly code = "fictional_delivery_lab_fault";

  constructor(readonly failpoint: DeliveryLabFailpoint) {
    super(`Fictional delivery lab fault at ${failpoint}.`);
    this.name = "DeliveryLabFaultInjectedError";
  }
}

export interface InMemoryDeliveryLabAttachmentSeed {
  readonly attachmentId: unknown;
  readonly accountId: unknown;
  readonly byteLength: unknown;
  readonly state: unknown;
  readonly boundEnvelopeId: unknown;
}

export interface InMemoryDeliveryLabSeed {
  readonly snapshot: unknown;
  readonly basePosition: unknown;
  readonly baseHeadHash: unknown;
  readonly now: unknown;
  readonly signingKeyId: unknown;
  readonly signingKeyValidFrom: unknown;
  readonly signingKeyValidUntil: unknown;
  readonly recipientProjections: unknown;
  readonly mlsRosterProjections: unknown;
  readonly attachments: unknown;
}

export interface DeliveryLabMailboxEntry {
  readonly mailboxPosition: Uint63String;
  readonly installationId: InstallationId;
  readonly envelope: StoredApplicationEnvelope;
}

export interface DeliveryLabOutboxRecord {
  readonly conversationId: ConversationId;
  readonly envelopeId: EnvelopeId;
  readonly position: Uint63String;
  readonly headHash: Hash32;
}

export interface DeliveryLabConversationSyncPage {
  readonly events: readonly StoredApplicationEnvelope[];
  readonly nextPosition: Uint63String;
  readonly hasMore: boolean;
}

export interface DeliveryLabInspection {
  readonly basePosition: Uint63String;
  readonly baseHeadHash: Hash32;
  readonly baseUsage: LockedConversationUsage;
  readonly snapshot: LockedApplicationAppendSnapshot;
  readonly pendingIntentDigest: Hash32 | null;
  readonly envelopes: readonly StoredApplicationEnvelope[];
  readonly mailboxes: readonly {
    readonly installationId: InstallationId;
    readonly entries: readonly DeliveryLabMailboxEntry[];
  }[];
  readonly outbox: readonly DeliveryLabOutboxRecord[];
  readonly httpIdempotencyRecordCount: number;
  readonly secondaryEnvelopeRecordCount: number;
  readonly boundAttachmentCount: number;
  readonly signerHistory: readonly DeliveryLabSignerHistoryEntry[];
}

interface LabAttachment {
  readonly attachmentId: AttachmentId;
  readonly accountId: AccountId;
  readonly byteLength: Uint63String;
  readonly state: "finalized" | "bound";
  readonly boundEnvelopeId: EnvelopeId | null;
}

/** Durable acceptance projection; per-invocation replay fields are added per response. */
interface StoredAcceptance {
  readonly receipt: ApplicationEnvelopeReceipt;
  readonly acceptedIntent: AcceptedApplicationAppendIntent;
  readonly envelope: StoredApplicationEnvelope;
  readonly signatureEvidence: DeliveryCheckpointSignatureEvidence;
  readonly signerFenceEvidence: ApplicationAppendSignerFenceVerificationEvidence;
  readonly fanoutEvidence: ApplicationAppendFanoutEvidence;
  readonly finalizedAt: Rfc3339Millis;
}

interface HttpIdempotencyRecord {
  readonly requestCommitment: Hash32;
  readonly acceptance: StoredAcceptance;
  readonly expiresAtMilliseconds: number;
}

interface LabDatabase {
  snapshot: LockedApplicationAppendSnapshot;
  pending: PendingApplicationAppendIntent | null;
  pendingReservedAt: Rfc3339Millis | null;
  envelopes: StoredApplicationEnvelope[];
  mailboxes: Map<InstallationId, DeliveryLabMailboxEntry[]>;
  outbox: DeliveryLabOutboxRecord[];
  httpIdempotency: Map<string, HttpIdempotencyRecord>;
  secondaryEnvelopes: Map<string, StoredAcceptance>;
  attachments: Map<AttachmentId, LabAttachment>;
}

interface ParsedLabSeed {
  readonly snapshot: LockedApplicationAppendSnapshot;
  readonly basePosition: Uint63String;
  readonly baseHeadHash: Hash32;
  readonly now: Rfc3339Millis;
  readonly signingKeyId: SigningKeyId;
  readonly signingKeyValidFrom: Rfc3339Millis;
  readonly signingKeyValidUntil: Rfc3339Millis;
  readonly recipientProjections: readonly ApplicationAppendRecipientProjection[];
  readonly mlsRosterProjections: readonly ApplicationAppendMlsRosterProjection[];
  readonly attachments: readonly LabAttachment[];
}

type ReplayLookup =
  | { readonly kind: "result"; readonly value: unknown }
  | { readonly kind: "miss" };

/**
 * Atomic, fault-injected, in-memory adapter for fictional pre-G1 lab data only.
 * It is not durable, owns only a disclosed deterministic test key, implements
 * no cursor crypto, and is never selected by the production-unavailable path.
 */
export class InMemoryDeliveryLabStore
  implements AtomicDeliveryPersistencePort
{
  readonly productionPorts: ProductionDeliveryPorts;

  private database: LabDatabase;
  private readonly basePosition: Uint63String;
  private readonly baseHeadHash: Hash32;
  private readonly baseUsage: LockedConversationUsage;
  private nowValue: Rfc3339Millis;
  private readonly signingKeyId: SigningKeyId;
  private readonly signingKeyValidFrom: Rfc3339Millis;
  private readonly signingKeyValidUntil: Rfc3339Millis;
  private readonly recipientProjections: readonly ApplicationAppendRecipientProjection[];
  private readonly mlsRosterProjections: readonly ApplicationAppendMlsRosterProjection[];
  private readonly cryptoPorts: FictionalDeliveryCryptoPorts;
  private readonly retiredIntents = new Map<Hash32, Rfc3339Millis>();
  private laneGeneration = 0n;
  private failpoint: DeliveryLabFailpoint | null = null;
  private transactionTail: Promise<void> = Promise.resolve();

  constructor(seedValue: InMemoryDeliveryLabSeed) {
    const seed = parseLabSeed(seedValue);
    if (
      seed.basePosition === "0" ||
      seed.baseHeadHash === ZERO_HASH32 ||
      seed.snapshot.conversation.lastPosition !== seed.basePosition ||
      seed.snapshot.conversation.currentLogHeadHash !== seed.baseHeadHash
    ) {
      throw new TypeError(
        "The fictional lab requires an exact verified nonzero base anchor.",
      );
    }
    this.basePosition = seed.basePosition;
    this.baseHeadHash = seed.baseHeadHash;
    this.baseUsage = Object.freeze({ ...seed.snapshot.usage });
    this.nowValue = seed.now;
    this.signingKeyId = seed.signingKeyId;
    this.signingKeyValidFrom = seed.signingKeyValidFrom;
    this.signingKeyValidUntil = seed.signingKeyValidUntil;
    this.recipientProjections = seed.recipientProjections;
    this.mlsRosterProjections = seed.mlsRosterProjections;
    this.database = {
      snapshot: cloneSnapshot(seed.snapshot),
      pending: null,
      pendingReservedAt: null,
      envelopes: [],
      mailboxes: new Map(
        seed.recipientProjections.map(({ installationId }) => [
          installationId,
          [],
        ]),
      ),
      outbox: [],
      httpIdempotency: new Map(),
      secondaryEnvelopes: new Map(),
      attachments: new Map(
        seed.attachments.map((attachment) => [
          attachment.attachmentId,
          { ...attachment },
        ]),
      ),
    };

    this.cryptoPorts = createFictionalDeliveryCryptoPorts({
      now: () => this.nowValue,
      snapshot: () => this.database.snapshot,
      signingKeyId: seed.signingKeyId,
      signingKeyValidFrom: seed.signingKeyValidFrom,
      signingKeyValidUntil: seed.signingKeyValidUntil,
      hooks: {
        beforeSignerCall: () => this.maybeFail("before-signer-call"),
        afterSignerCall: () => this.maybeFail("after-signer-call"),
        beforeSignatureVerifierCall: () =>
          this.maybeFail("before-signature-verifier-call"),
        afterSignatureVerifierCall: () =>
          this.maybeFail("after-signature-verifier-call"),
      },
    });
    this.productionPorts = Object.freeze({
      mlsWireInspector: this.cryptoPorts.mlsWireInspector,
      mlsCommitProjectionVerifier: {
        verify: () => Promise.resolve(unavailable()),
      },
      mlsExternalProposalVerifier: {
        verify: () => Promise.resolve(unavailable()),
      },
      policyHeadProofVerifier: this.cryptoPorts.policyHeadProofVerifier,
      conversationPolicyReplayVerifier: {
        // Private lab mailbox sync below does not call production sync.
        verify: () => Promise.resolve(unavailable()),
      },
      checkpointSigner: this.cryptoPorts.checkpointSigner,
      signerFenceEvidenceVerifier: this.cryptoPorts.signerFenceEvidenceVerifier,
      checkpointSignatureVerifier: this.cryptoPorts.checkpointSignatureVerifier,
      conversationPageProofVerifier: {
        // Private lab mailbox sync below does not call production sync.
        verify: () => Promise.resolve(unavailable()),
      },
      conversationLogHeadProofVerifier: {
        // Private lab mailbox sync below does not call production sync.
        verify: () => Promise.resolve(unavailable()),
      },
      applicationAppendPreflight: {
        read: (
          command: AtomicApplicationAppendCommand,
          invocation: DeliveryInvocationContext,
        ) => this.readPreflight(command, invocation),
      },
      atomicPersistence: this,
      clock: {
        now: () => this.nowValue,
      },
      conversationCursorCodec: {
        decode: () => Promise.resolve(unavailable()),
        encode: () => Promise.resolve(unavailable()),
      },
      invariantIncident: {
        record: () => Promise.resolve({ status: "recorded-in-fictional-lab" }),
      },
    });
  }

  setFailpointForTesting(failpoint: DeliveryLabFailpoint | null): void {
    this.failpoint = failpoint;
  }

  setNowForTesting(value: unknown): void {
    this.nowValue = parseRfc3339Millis(value, "fictional lab now");
  }

  inspectForTesting(): DeliveryLabInspection {
    this.assertInternalInvariants(this.database);
    return Object.freeze({
      basePosition: this.basePosition,
      baseHeadHash: this.baseHeadHash,
      baseUsage: Object.freeze({ ...this.baseUsage }),
      snapshot: cloneSnapshot(this.database.snapshot),
      pendingIntentDigest: this.database.pending?.intentDigest ?? null,
      envelopes: Object.freeze([...this.database.envelopes]),
      mailboxes: Object.freeze(
        [...this.database.mailboxes]
          .sort(([left], [right]) => left.localeCompare(right))
          .map(([installationId, entries]) =>
            Object.freeze({
              installationId,
              entries: Object.freeze([...entries]),
            }),
          ),
      ),
      outbox: Object.freeze([...this.database.outbox]),
      httpIdempotencyRecordCount: this.database.httpIdempotency.size,
      secondaryEnvelopeRecordCount: this.database.secondaryEnvelopes.size,
      boundAttachmentCount: [...this.database.attachments.values()].filter(
        ({ state }) => state === "bound",
      ).length,
      signerHistory: this.cryptoPorts.signerHistoryForTesting(),
    });
  }

  /** Reads only the eligible installation mailbox projection. */
  syncConversationForInstallation(
    conversationIdValue: unknown,
    installationIdValue: unknown,
    afterPositionValue: unknown,
    limitValue: unknown,
  ): DeliveryLabConversationSyncPage {
    const conversationId = parseConversationId(conversationIdValue);
    const installationId = parseInstallationId(installationIdValue);
    const afterPosition = parseUint63String(afterPositionValue);
    const limit = parseUint63String(limitValue);
    if (limit === "0") throw new TypeError("Fictional sync limit must be positive.");
    if (conversationId !== this.database.snapshot.conversation.conversationId) {
      throw new TypeError("Fictional lab conversation is unavailable.");
    }
    const mailbox = this.database.mailboxes.get(installationId);
    if (!mailbox) throw new TypeError("Fictional lab mailbox is unavailable.");
    this.assertInternalInvariants(this.database);
    const eligible = mailbox
      .filter(({ envelope }) =>
        BigInt(envelope.position) > BigInt(afterPosition),
      )
      .slice(0, Number(limit));
    const events = eligible.map(({ envelope }) => envelope);
    const nextPosition = events.at(-1)?.position ?? afterPosition;
    return Object.freeze({
      events: Object.freeze(events),
      nextPosition,
      hasMore: mailbox.some(
        ({ envelope }) => BigInt(envelope.position) > BigInt(nextPosition),
      ),
    });
  }

  /** Separate global transcript helper for invariant-only fictional tests. */
  readGlobalTranscriptForTesting(): readonly StoredApplicationEnvelope[] {
    this.assertInternalInvariants(this.database);
    return Object.freeze([...this.database.envelopes]);
  }

  reserveApplicationAppendAtomically(
    reservationValue: AtomicApplicationAppendReservation,
    prepareUnsigned: PrepareUnsignedApplicationAppend,
    invocation: DeliveryInvocationContext,
  ): Promise<unknown> {
    return this.withTransactionLock(() => {
      if (!this.invocationIsLive(invocation)) return unavailable("timeout");
      const command = parseAtomicApplicationAppendCommand(
        reservationValue.command,
      );
      const admissionStartedAt = parseRfc3339Millis(
        reservationValue.admissionStartedAt,
        "reservation admission start",
      );
      const replay = this.lookupReplay(command);
      if (replay.kind === "result") return replay.value;
      if (
        command.semanticIdentity.conversationId !==
        this.database.snapshot.conversation.conversationId
      ) {
        return rejected("conversation-not-found");
      }
      if (!commandTrustMatchesSnapshot(command, this.database.snapshot)) {
        return rejected("conversation-state-changed");
      }
      if (
        parseHash32(reservationValue.expectedSnapshotDigest) !==
        computeLockedApplicationAppendSnapshotDigest(this.database.snapshot)
      ) {
        return retry();
      }
      try {
        enforceApplicationAppendDeliveryLimits(
          command.semanticIdentity.append,
          command.deliveryLimits,
        );
      } catch {
        return rejected("delivery-limit-exceeded");
      }
      const attachmentByteLength = this.measureAttachments(
        this.database,
        command.semanticIdentity,
      );
      if (attachmentByteLength === null) return rejected("attachment-invalid");

      const wireEvidence = parseMlsApplicationWireInspectionEvidence(
        reservationValue.wireInspectionEvidence,
      );
      const policyEvidence = parsePolicyEvidenceForSnapshot(
        reservationValue.policyHeadProofEvidence,
        this.database.snapshot,
      );
      const authorizationSnapshot =
        refreshLockedApplicationAppendAuthorizationSnapshot({
          persistedSnapshot: this.database.snapshot,
          policyHeadProofEvidence: policyEvidence,
        });
      const expectedAuthorizationSnapshotDigest = parseHash32(
        reservationValue.expectedAuthorizationSnapshotDigest,
      );
      if (
        expectedAuthorizationSnapshotDigest !==
        computeLockedApplicationAppendSnapshotDigest(authorizationSnapshot)
      ) {
        return retry();
      }
      const reservationFence = this.allocateReservationFence(
        command.semanticIdentity.conversationId,
      );
      this.maybeFail("before-reservation-prepare");
      const preparedValue = prepareUnsigned({
        lockedSnapshot: cloneSnapshot(authorizationSnapshot),
        authoritativeReceivedAt: this.nowValue,
        previousHeadHash: this.database.snapshot.conversation.currentLogHeadHash,
        attachmentByteLength,
        activeSigningKeyId: this.signingKeyId,
        activeSigningKeyValidUntil: this.signingKeyValidUntil,
        reservationFence: {
          generation: reservationFence.generation,
          token: reservationFence.token,
        },
        mlsRosterProjections: this.mlsRosterProjections.map((row) => ({
          ...row,
        })),
        recipientProjections: this.recipientProjections.map((row) => ({
          ...row,
        })),
        transactionDeadline: transactionDeadline(
          this.nowValue,
          invocation.deadline,
        ),
      });
      if (isThenable(preparedValue)) {
        throw new TypeError("Reservation callback must be synchronous and local-only.");
      }
      const prepared = parsePreparedApplicationAppend(preparedValue);
      this.maybeFail("after-reservation-prepare");
      if (prepared.status !== "ready") return prepared;
      const pending = prepared.pendingIntent;
      if (
        pending.admissionCommandDigest !==
          computeAtomicApplicationAppendCommandDigest(command) ||
        pending.expectedSnapshotDigest !==
          parseHash32(reservationValue.expectedSnapshotDigest) ||
        pending.expectedAuthorizationSnapshotDigest !==
          expectedAuthorizationSnapshotDigest ||
        pending.admissionStartedAt !== admissionStartedAt ||
        pending.reservationFence.generation !== reservationFence.generation ||
        pending.reservationFence.token !== reservationFence.token ||
        pending.wireInspectionEvidence.evidenceDigest !==
          wireEvidence.evidenceDigest ||
        pending.policyHeadProofEvidence.evidenceDigest !==
          policyEvidence.evidenceDigest
      ) {
        throw new TypeError("Reservation callback substituted command or proof facts.");
      }
      const draft = cloneDatabase(this.database);
      draft.pending = pending;
      draft.pendingReservedAt = this.nowValue;
      this.maybeFail("before-reservation-commit");
      this.assertInternalInvariants(draft);
      this.database = draft;
      this.maybeFail("after-reservation-commit-before-response");
      return this.pendingResultFor(command, pending, "none");
    });
  }

  finalizeApplicationAppendAtomically(
    inputValue: FinalizeApplicationAppendInput,
    invocation: DeliveryInvocationContext,
  ): Promise<unknown> {
    return this.withTransactionLock(() => {
      if (!this.invocationIsLive(invocation)) return unavailable("timeout");
      const command = parseAtomicApplicationAppendCommand(inputValue.command);
      const acceptedReplay = this.lookupAcceptedReplay(command);
      if (acceptedReplay !== null) return acceptedReplay;
      const pending = parsePendingApplicationAppendIntent(
        inputValue.pendingIntent,
      );
      if (
        !this.database.pending ||
        this.database.pending.intentDigest !== pending.intentDigest
      ) {
        const admitted = pending.admissionCommand;
        const finalizedAcceptance = this.database.secondaryEnvelopes.get(
          semanticEnvelopeKey(
            admitted.realmId,
            admitted.semanticIdentity.conversationId,
            admitted.semanticIdentity.append.envelopeId,
          ),
        );
        if (
          finalizedAcceptance &&
          finalizedAcceptance.acceptedIntent.intentDigest ===
            pending.intentDigest
        ) {
          const replayForPending =
            computeAtomicApplicationAppendCommandDigest(command) ===
            pending.admissionCommandDigest
              ? "none"
              : applicationEnvelopeSemanticallyEqual(
                    admitted.semanticIdentity,
                    command.semanticIdentity,
                  )
                ? "envelope"
                : "blocked";
          return this.acceptedResultFor(
            command,
            finalizedAcceptance,
            replayForPending,
          );
        }
        return retry();
      }
      const inputFence = parseApplicationAppendReservationFence(
        inputValue.reservationFence,
      );
      const fanoutPlan = parseApplicationAppendFanoutPlan(
        inputValue.fanoutPlan,
        pending.admissionCommand.deliveryLimits
          .conversationRecipientInstallationsMax,
      );
      if (
        parseHash32(inputValue.pendingIntentDigest) !== pending.intentDigest ||
        inputFence.generation !== pending.reservationFence.generation ||
        inputFence.token !== pending.reservationFence.token ||
        parseRfc3339Millis(inputValue.pendingExpiresAt) !==
          pending.pendingExpiresAt ||
        fanoutPlan.planDigest !== pending.fanoutPlan.planDigest
      ) {
        return unavailable("malformed-dependency-response");
      }
      const signature = parseEd25519Signature(inputValue.signature);
      const signedResolution =
        parseDurableApplicationAppendSignerFenceSignedResolution(
          inputValue.signedFenceResolution,
          signerFenceExpectationFor(pending),
        );
      if (signedResolution.checkpointSignature !== signature) {
        return unavailable("malformed-dependency-response");
      }
      const fenceEvidence = parseApplicationAppendSignerFenceVerificationEvidence(
        inputValue.verifiedSignerFenceEvidence,
        signedResolution,
        parseRfc3339Millis(
          dataValue(inputValue.verifiedSignerFenceEvidence, "verifiedAt"),
        ),
      );
      const signedEnvelope = parseStoredEnvelope({
        ...pending.envelope,
        logHeadSignature: signature,
      });
      if (signedEnvelope.envelopeClass !== "application") {
        throw new TypeError("Pending application finalized as another class.");
      }
      enforceStoredEnvelopeDeliveryLimits(
        signedEnvelope,
        pending.admissionCommand.deliveryLimits,
      );
      const signatureEvidence = parseDeliveryCheckpointSignatureEvidence(
        {
          status: "verified",
          ...(inputValue.verifiedSignatureEvidence as Record<string, unknown>),
        },
        checkpointVerificationRequest(
          signedEnvelope,
          pending,
          signature,
          parseRfc3339Millis(
            dataValue(inputValue.verifiedSignatureEvidence, "verifiedAt"),
          ),
          invocation,
        ),
      );
      if (
        !verifyFictionalDeliveryLabReceiptSignatureForTesting(
          receiptFromStoredApplicationEnvelope(signedEnvelope),
        )
      ) {
        throw new TypeError("Finalized checkpoint signature is invalid.");
      }
      if (
        computeLockedApplicationAppendSnapshotDigest(this.database.snapshot) !==
          pending.expectedSnapshotDigest ||
        this.signingKeyId !== signedEnvelope.logSigningKeyId
      ) {
        return retry();
      }
      if (
        this.measureAttachments(
          this.database,
          pending.admissionCommand.semanticIdentity,
        ) !== pending.attachmentByteLength
      ) {
        return rejected("attachment-invalid");
      }
      this.assertRecipientProjectionsCurrent();
      const quotaConversion = convertQuotaCapacity(pending, "finalize");

      const receipt = receiptFromStoredApplicationEnvelope(signedEnvelope);
      const acceptedIntent = acceptedApplicationAppendIntentFromPending(
        pending,
        signedResolution,
      );
      const fanoutEvidence = buildFanoutEvidence(
        pending.fanoutPlan,
        signedEnvelope,
      );
      const acceptance: StoredAcceptance = Object.freeze({
        receipt,
        acceptedIntent,
        envelope: signedEnvelope,
        signatureEvidence,
        signerFenceEvidence: fenceEvidence,
        fanoutEvidence,
        finalizedAt: this.nowValue,
      });
      const semanticallyEqual = applicationEnvelopeSemanticallyEqual(
        pending.admissionCommand.semanticIdentity,
        command.semanticIdentity,
      );
      const draft = cloneDatabase(this.database);
      draft.snapshot = parseLockedApplicationAppendSnapshot({
        conversation: { ...pending.commitProjection.conversation },
        membership: { ...this.database.snapshot.membership },
        policyHead: { ...this.database.snapshot.policyHead },
        sendGrant: { ...this.database.snapshot.sendGrant },
        pendingRemovalCount: this.database.snapshot.pendingRemovalCount,
        usage: { ...pending.commitProjection.usage },
        quotaBindings: this.database.snapshot.quotaBindings.map((binding) => ({
          ...binding,
        })),
        quotas: quotaConversion.map((quota) => ({ ...quota })),
      });
      this.maybeFail("after-state-write");
      draft.envelopes.push(signedEnvelope);
      this.maybeFail("after-envelope-write");
      this.bindAttachments(
        draft,
        pending.admissionCommand.semanticIdentity,
        signedEnvelope.envelopeId,
      );
      this.fanOutPlannedRecipients(draft, pending.fanoutPlan, signedEnvelope);
      this.maybeFail("after-mailbox-write");
      draft.outbox.push(
        Object.freeze({
          conversationId: signedEnvelope.conversationId,
          envelopeId: signedEnvelope.envelopeId,
          position: signedEnvelope.position,
          headHash: signedEnvelope.headHash,
        }),
      );
      this.maybeFail("after-outbox-write");
      draft.secondaryEnvelopes.set(
        semanticEnvelopeKey(
          pending.admissionCommand.realmId,
          signedEnvelope.conversationId,
          signedEnvelope.envelopeId,
        ),
        acceptance,
      );
      this.maybeFail("after-secondary-write");
      const expiresAtMilliseconds =
        Date.parse(this.nowValue) + HTTP_IDEMPOTENCY_TTL_MILLISECONDS;
      const idempotencyCommands = semanticallyEqual
        ? [pending.admissionCommand, command]
        : [pending.admissionCommand];
      for (const idempotencyCommand of idempotencyCommands) {
        draft.httpIdempotency.set(httpIdempotencyScope(idempotencyCommand), {
          requestCommitment: idempotencyCommand.requestCommitment,
          acceptance,
          expiresAtMilliseconds,
        });
      }
      this.maybeFail("after-idempotency-write");
      draft.pending = null;
      draft.pendingReservedAt = null;
      this.maybeFail("before-finalization-commit");
      this.assertInternalInvariants(draft);
      this.database = draft;
      this.maybeFail("after-finalization-commit-before-response");
      const replay =
        computeAtomicApplicationAppendCommandDigest(command) ===
        pending.admissionCommandDigest
          ? "none"
          : semanticallyEqual
            ? "envelope"
            : "blocked";
      return this.acceptedResultFor(command, acceptance, replay);
    });
  }

  retireExpiredApplicationAppendAtomically(
    inputValue: RetireExpiredApplicationAppendInput,
    invocation: DeliveryInvocationContext,
  ): Promise<unknown> {
    return this.withTransactionLock(() => {
      if (!this.invocationIsLive(invocation)) return unavailable("timeout");
      const command = parseAtomicApplicationAppendCommand(inputValue.command);
      const pendingIntentDigest = parseHash32(inputValue.pendingIntentDigest);
      const tombstone = this.retiredIntents.get(pendingIntentDigest);
      if (tombstone !== undefined) {
        return this.retiredResultFor(command, pendingIntentDigest, tombstone);
      }
      const current = this.database.pending;
      if (!current || current.intentDigest !== pendingIntentDigest) {
        return current
          ? this.blockedByPendingResultFor(command, current)
          : unavailable("malformed-dependency-response");
      }
      const pending = parsePendingApplicationAppendIntent(
        inputValue.pendingIntent,
      );
      const inputFence = parseApplicationAppendReservationFence(
        inputValue.reservationFence,
      );
      if (
        pending.intentDigest !== current.intentDigest ||
        inputFence.generation !== pending.reservationFence.generation ||
        inputFence.token !== pending.reservationFence.token ||
        parseRfc3339Millis(inputValue.pendingExpiresAt) !==
          pending.pendingExpiresAt ||
        this.nowValue < pending.pendingExpiresAt
      ) {
        return unavailable("malformed-dependency-response");
      }
      let resolution: ApplicationAppendSignerFenceResolution;
      try {
        resolution = parseApplicationAppendSignerFenceResolution(
          inputValue.cancellationResolution,
          this.signingRequestFor(pending, invocation),
        );
      } catch {
        return unavailable("malformed-dependency-response");
      }
      if (
        resolution.status !== "cancelled" ||
        resolution.fenceRecordSigningKeyId !== this.signingKeyId
      ) {
        return unavailable("malformed-dependency-response");
      }
      try {
        parseApplicationAppendSignerFenceVerificationEvidence(
          inputValue.verifiedCancellationEvidence,
          resolution,
          parseRfc3339Millis(
            dataValue(inputValue.verifiedCancellationEvidence, "verifiedAt"),
          ),
        );
      } catch {
        return unavailable("malformed-dependency-response");
      }
      convertQuotaCapacity(pending, "release");
      const draft = cloneDatabase(this.database);
      draft.pending = null;
      draft.pendingReservedAt = null;
      this.assertInternalInvariants(draft);
      this.database = draft;
      this.retiredIntents.set(pendingIntentDigest, this.nowValue);
      return this.retiredResultFor(command, pendingIntentDigest, this.nowValue);
    });
  }

  private readPreflight(
    commandValue: AtomicApplicationAppendCommand,
    invocation: DeliveryInvocationContext,
  ): Promise<unknown> {
    return this.withTransactionLock(() => {
      if (!this.invocationIsLive(invocation)) return unavailable("timeout");
      const command = parseAtomicApplicationAppendCommand(commandValue);
      const replay = this.lookupReplay(command);
      if (replay.kind === "result") return replay.value;
      if (
        command.semanticIdentity.conversationId !==
        this.database.snapshot.conversation.conversationId
      ) {
        return rejected("conversation-not-found");
      }
      if (!commandTrustMatchesSnapshot(command, this.database.snapshot)) {
        return rejected("conversation-state-changed");
      }
      const attachmentByteLength = this.measureAttachments(
        this.database,
        command.semanticIdentity,
      );
      if (attachmentByteLength === null) return rejected("attachment-invalid");
      const snapshot = cloneSnapshot(this.database.snapshot);
      return Object.freeze({
        status: "miss",
        invocationCommandDigest:
          computeAtomicApplicationAppendCommandDigest(command),
        lockedSnapshot: snapshot,
        snapshotDigest: computeLockedApplicationAppendSnapshotDigest(snapshot),
        previousHeadHash: snapshot.conversation.currentLogHeadHash,
        attachmentByteLength,
        observedAt: this.nowValue,
      });
    });
  }

  private lookupReplay(command: AtomicApplicationAppendCommand): ReplayLookup {
    const accepted = this.lookupAcceptedReplay(command);
    if (accepted !== null) return { kind: "result", value: accepted };
    const pending = this.database.pending;
    if (!pending) return { kind: "miss" };
    const admitted = pending.admissionCommand;
    if (httpIdempotencyScope(admitted) === httpIdempotencyScope(command)) {
      const classification = classifyHttpIdempotencyCommitment(
        admitted.requestCommitment,
        command.requestCommitment,
      );
      return {
        kind: "result",
        value:
          classification.kind === "conflict"
            ? conflict()
            : this.pendingResultFor(command, pending, "http"),
      };
    }
    if (
      admitted.realmId === command.realmId &&
      admitted.semanticIdentity.conversationId ===
        command.semanticIdentity.conversationId &&
      admitted.semanticIdentity.append.envelopeId ===
        command.semanticIdentity.append.envelopeId
    ) {
      return {
        kind: "result",
        value: applicationEnvelopeSemanticallyEqual(
          admitted.semanticIdentity,
          command.semanticIdentity,
        )
          ? this.pendingResultFor(command, pending, "envelope")
          : conflict(),
      };
    }
    if (
      admitted.realmId === command.realmId &&
      admitted.semanticIdentity.conversationId ===
        command.semanticIdentity.conversationId
    ) {
      return {
        kind: "result",
        value: this.blockedByPendingResultFor(command, pending),
      };
    }
    return { kind: "miss" };
  }

  private lookupAcceptedReplay(
    command: AtomicApplicationAppendCommand,
  ): unknown | null {
    const http = this.database.httpIdempotency.get(
      httpIdempotencyScope(command),
    );
    if (http && http.expiresAtMilliseconds > Date.parse(this.nowValue)) {
      const classification = classifyHttpIdempotencyCommitment(
        http.requestCommitment,
        command.requestCommitment,
      );
      return classification.kind === "conflict"
        ? conflict()
        : this.acceptedResultFor(command, http.acceptance, "http");
    }
    const identity = command.semanticIdentity;
    const acceptance = this.database.secondaryEnvelopes.get(
      semanticEnvelopeKey(
        command.realmId,
        identity.conversationId,
        identity.append.envelopeId,
      ),
    );
    if (!acceptance) return null;
    return applicationEnvelopeSemanticallyEqual(
      acceptance.acceptedIntent.admissionCommand.semanticIdentity,
      identity,
    )
      ? this.acceptedResultFor(command, acceptance, "envelope")
      : conflict();
  }

  private allocateReservationFence(
    conversationId: ConversationId,
  ): ApplicationAppendReservationFence {
    this.laneGeneration += 1n;
    const generation = uint63FromBigInt(this.laneGeneration);
    const token = sha256Bytes(
      utf8(FICTIONAL_FENCE_TOKEN_DOMAIN),
      canonicalLengthPrefixed(utf8(generation), utf8(conversationId)),
    );
    return parseApplicationAppendReservationFence({ generation, token });
  }

  private signingRequestFor(
    pending: PendingApplicationAppendIntent,
    invocation: DeliveryInvocationContext,
  ): DeliveryCheckpointSigningRequest {
    const envelope = pending.envelope;
    return Object.freeze({
      profile: "delivery-log-checkpoint.v1" as const,
      realmId: parseDeliveryRealmId(pending.admissionCommand.realmId),
      conversationGeneration: pending.priorSnapshot.conversation.generation,
      releaseProfileId: pending.admissionCommand.releaseProfileId,
      releaseTrustRootDigest: pending.admissionCommand.releaseTrustRootDigest,
      conversationId: envelope.conversationId,
      position: envelope.position,
      previousHeadHash: envelope.previousHeadHash,
      headHash: envelope.headHash,
      signingKeyId: envelope.logSigningKeyId,
      checkpointDigest: envelope.logCheckpointDigest,
      checkpointReceivedAt: envelope.receivedAt,
      pendingIntentDigest: pending.intentDigest,
      reservationFence: pending.reservationFence,
      pendingExpiresAt: pending.pendingExpiresAt,
      admissionStartedAt: pending.admissionStartedAt,
      invocationStartedAt: invocation.invocationStartedAt,
      deadline: invocation.deadline,
      signal: invocation.signal,
    });
  }

  private measureAttachments(
    database: LabDatabase,
    identity: ApplicationEnvelopeSemanticIdentity,
  ): Uint63String | null {
    let total = 0n;
    for (const attachmentId of identity.append.attachmentIds) {
      const attachment = database.attachments.get(attachmentId);
      if (
        !attachment ||
        attachment.accountId !== identity.authenticatedSender.accountId ||
        attachment.state !== "finalized" ||
        attachment.boundEnvelopeId !== null
      ) {
        return null;
      }
      total += BigInt(attachment.byteLength);
    }
    try {
      return uint63FromBigInt(total);
    } catch {
      return null;
    }
  }

  private bindAttachments(
    database: LabDatabase,
    identity: ApplicationEnvelopeSemanticIdentity,
    envelopeId: EnvelopeId,
  ): void {
    for (const attachmentId of identity.append.attachmentIds) {
      const attachment = database.attachments.get(attachmentId);
      if (!attachment) throw new TypeError("Locked attachment disappeared.");
      database.attachments.set(
        attachmentId,
        Object.freeze({
          ...attachment,
          state: "bound",
          boundEnvelopeId: envelopeId,
        }),
      );
    }
  }

  private fanOutPlannedRecipients(
    database: LabDatabase,
    plan: ApplicationAppendFanoutPlan,
    envelope: StoredApplicationEnvelope,
  ): void {
    for (const installationId of plan.recipientInstallationIds) {
      const entries = database.mailboxes.get(installationId);
      if (!entries) throw new TypeError("Authoritative mailbox disappeared.");
      entries.push(
        Object.freeze({
          mailboxPosition: uint63FromBigInt(BigInt(entries.length + 1)),
          installationId,
          envelope,
        }),
      );
    }
  }

  private assertRecipientProjectionsCurrent(): void {
    const conversation = this.database.snapshot.conversation;
    if (
      this.recipientProjections.some(
        (projection) =>
          projection.conversationId !== conversation.conversationId ||
          projection.recipientSetVersion !== conversation.recipientSetVersion,
      )
    ) {
      throw new TypeError("Recipient projections are not the current roster.");
    }
  }

  private assertInternalInvariants(database: LabDatabase): void {
    let previousHeadHash = this.baseHeadHash;
    for (let index = 0; index < database.envelopes.length; index += 1) {
      const envelope = parseStoredEnvelope(database.envelopes[index]);
      if (envelope.envelopeClass !== "application") {
        throw new TypeError("Fictional lab contains a non-application item.");
      }
      const expectedPosition = uint63FromBigInt(
        BigInt(this.basePosition) + BigInt(index + 1),
      );
      const leafHash = computeEnvelopeLeafHash({
        conversationId: envelope.conversationId,
        position: envelope.position,
        envelopeId: envelope.envelopeId,
        envelopeClass: envelope.envelopeClass,
        sender: envelope.sender,
        epoch: envelope.epoch,
        rosterVersion: envelope.rosterVersion,
        contentType: envelope.contentType,
        envelopeSha256: envelope.envelopeSha256,
        receivedAt: envelope.receivedAt,
      });
      if (
        envelope.position !== expectedPosition ||
        envelope.previousHeadHash !== previousHeadHash ||
        envelope.leafHash !== leafHash ||
        envelope.headHash !== computeLogHeadHash(previousHeadHash, leafHash) ||
        !verifyFictionalDeliveryLabReceiptSignatureForTesting(
          receiptFromStoredApplicationEnvelope(envelope),
        )
      ) {
        throw new TypeError("Fictional lab log has a gap, fork, or bad signature.");
      }
      previousHeadHash = envelope.headHash;
    }
    if (
      database.snapshot.conversation.lastPosition !==
        uint63FromBigInt(
          BigInt(this.basePosition) + BigInt(database.envelopes.length),
        ) ||
      database.snapshot.conversation.currentLogHeadHash !== previousHeadHash
    ) {
      throw new TypeError("Fictional lab committed state diverged from its log.");
    }
    const suffixEnvelopeBytes = database.envelopes.reduce(
      (total, envelope) =>
        total + BigInt(Buffer.from(envelope.envelopeBytes, "base64url").byteLength),
      0n,
    );
    const suffixEnvelopeIds = new Set(
      database.envelopes.map(({ envelopeId }) => envelopeId),
    );
    const suffixAttachmentBytes = [...database.attachments.values()].reduce(
      (total, attachment) =>
        attachment.state === "bound" &&
        attachment.boundEnvelopeId !== null &&
        suffixEnvelopeIds.has(attachment.boundEnvelopeId)
          ? total + BigInt(attachment.byteLength)
          : total,
      0n,
    );
    if (
      database.snapshot.usage.envelopeCount !==
        uint63FromBigInt(
          BigInt(this.baseUsage.envelopeCount) +
            BigInt(database.envelopes.length),
        ) ||
      database.snapshot.usage.envelopeBytes !==
        uint63FromBigInt(
          BigInt(this.baseUsage.envelopeBytes) + suffixEnvelopeBytes,
        ) ||
      database.snapshot.usage.attachmentBytes !==
        uint63FromBigInt(
          BigInt(this.baseUsage.attachmentBytes) + suffixAttachmentBytes,
        )
    ) {
      throw new TypeError("Fictional lab usage lost its verified base anchor.");
    }
    if (database.pending) {
      const pending = parsePendingApplicationAppendIntent(database.pending);
      if (
        pending.expectedSnapshotDigest !==
          computeLockedApplicationAppendSnapshotDigest(database.snapshot) ||
        pending.expectedAuthorizationSnapshotDigest !==
          computeLockedApplicationAppendSnapshotDigest(
            pending.priorSnapshot,
          ) ||
        BigInt(pending.envelope.position) !==
          BigInt(database.snapshot.conversation.lastPosition) + 1n ||
        database.envelopes.some(
          ({ position }) => position === pending.envelope.position,
        )
      ) {
        throw new TypeError("Fictional pending fence is reused or visible.");
      }
    }
    for (const [installationId, entries] of database.mailboxes) {
      const projection = this.recipientProjections.find(
        (candidate) => candidate.installationId === installationId,
      );
      if (!projection) throw new TypeError("Mailbox lacks a roster projection.");
      entries.forEach((entry, index) => {
        if (
          entry.installationId !== installationId ||
          entry.mailboxPosition !== uint63FromBigInt(BigInt(index + 1)) ||
          !recipientEligibleAt(projection, entry.envelope.position) ||
          !database.envelopes.includes(entry.envelope)
        ) {
          throw new TypeError("Fictional mailbox has a gap or phantom.");
        }
      });
    }
    for (const record of database.outbox) {
      if (
        !database.envelopes.some(
          (envelope) =>
            envelope.envelopeId === record.envelopeId &&
            envelope.position === record.position &&
            envelope.headHash === record.headHash,
        )
      ) {
        throw new TypeError("Fictional outbox contains a phantom.");
      }
    }
    if (
      database.secondaryEnvelopes.size !== database.envelopes.length ||
      database.outbox.length !== database.envelopes.length
    ) {
      throw new TypeError("Fictional atomic projections diverged.");
    }
  }

  private invocationIsLive(input: {
    readonly deadline: Rfc3339Millis;
    readonly signal: AbortSignal;
  }): boolean {
    return !input.signal.aborted && input.deadline > this.nowValue;
  }

  private maybeFail(failpoint: DeliveryLabFailpoint): void {
    if (this.failpoint !== failpoint) return;
    this.failpoint = null;
    throw new DeliveryLabFaultInjectedError(failpoint);
  }

  private async withTransactionLock<T>(operation: () => T | Promise<T>): Promise<T> {
    const predecessor = this.transactionTail;
    let release!: () => void;
    this.transactionTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await predecessor;
    try {
      return await operation();
    } finally {
      release();
    }
  }

  private pendingResultFor(
    command: AtomicApplicationAppendCommand,
    pendingIntent: PendingApplicationAppendIntent,
    replay: "none" | "http" | "envelope",
  ) {
    return Object.freeze({
      status: "pending",
      replay,
      invocationCommandDigest:
        computeAtomicApplicationAppendCommandDigest(command),
      pendingIntent,
      reservedAt: this.database.pendingReservedAt ?? this.nowValue,
      observedAt: this.nowValue,
    });
  }

  private blockedByPendingResultFor(
    command: AtomicApplicationAppendCommand,
    pendingIntent: PendingApplicationAppendIntent,
  ) {
    return Object.freeze({
      status: "blocked-by-pending",
      invocationCommandDigest:
        computeAtomicApplicationAppendCommandDigest(command),
      pendingIntent,
      reservedAt: this.database.pendingReservedAt ?? this.nowValue,
      observedAt: this.nowValue,
    });
  }

  private retiredResultFor(
    command: AtomicApplicationAppendCommand,
    pendingIntentDigest: Hash32,
    retiredAt: Rfc3339Millis,
  ) {
    return Object.freeze({
      status: "retired",
      invocationCommandDigest:
        computeAtomicApplicationAppendCommandDigest(command),
      pendingIntentDigest,
      retiredAt,
      observedAt: this.nowValue,
    });
  }

  private acceptedResultFor(
    command: AtomicApplicationAppendCommand,
    acceptance: StoredAcceptance,
    replay: "none" | "http" | "envelope" | "blocked",
  ) {
    return Object.freeze({
      status: "accepted",
      replay,
      invocationCommandDigest:
        computeAtomicApplicationAppendCommandDigest(command),
      acceptedIntent: acceptance.acceptedIntent,
      envelope: acceptance.envelope,
      receipt: acceptance.receipt,
      signatureEvidence: acceptance.signatureEvidence,
      signerFenceEvidence: acceptance.signerFenceEvidence,
      fanoutEvidence: acceptance.fanoutEvidence,
      finalizedAt: acceptance.finalizedAt,
      observedAt: this.nowValue,
    });
  }
}

function parseLabSeed(value: unknown): ParsedLabSeed {
  const record = expectExactRecord(
    value,
    [
      "snapshot",
      "basePosition",
      "baseHeadHash",
      "now",
      "signingKeyId",
      "signingKeyValidFrom",
      "signingKeyValidUntil",
      "recipientProjections",
      "mlsRosterProjections",
      "attachments",
    ],
    "fictional in-memory delivery lab seed",
  );
  const snapshot = parseLockedApplicationAppendSnapshot(record.snapshot);
  const basePosition = parseUint63String(record.basePosition);
  const baseHeadHash = parseHash32(record.baseHeadHash);
  const signingKeyValidFrom = parseRfc3339Millis(
    record.signingKeyValidFrom,
  );
  const signingKeyValidUntil = parseRfc3339Millis(
    record.signingKeyValidUntil,
  );
  if (signingKeyValidUntil <= signingKeyValidFrom) {
    throw new TypeError("Fictional signing-key window is invalid.");
  }
  const recipientProjections = parseApplicationAppendRecipientProjections(
    record.recipientProjections,
    seedArrayCeiling(record.recipientProjections, "recipientProjections"),
  );
  const mlsRosterProjections = parseApplicationAppendMlsRosterProjections(
    record.mlsRosterProjections,
    seedArrayCeiling(record.mlsRosterProjections, "mlsRosterProjections"),
  );
  const conversation = snapshot.conversation;
  if (
    computeApplicationAppendRecipientSetHash(recipientProjections) !==
      conversation.recipientSetHash ||
    computeApplicationAppendMlsRosterHash(mlsRosterProjections) !==
      conversation.rosterHash ||
    recipientProjections.some(
      (projection) =>
        projection.conversationId !== conversation.conversationId ||
        projection.conversationGeneration !== conversation.generation ||
        projection.recipientSetVersion !== conversation.recipientSetVersion,
    ) ||
    mlsRosterProjections.some(
      (projection) =>
        projection.conversationId !== conversation.conversationId ||
        projection.conversationGeneration !== conversation.generation ||
        projection.rosterVersion !== conversation.rosterVersion,
    )
  ) {
    throw new TypeError("Fictional recipient roster is duplicated or stale.");
  }
  const membership = snapshot.membership;
  const senderProjection = recipientProjections.find(
    ({ installationId }) => installationId === membership.installationId,
  );
  if (
    !senderProjection ||
    senderProjection.conversationId !== membership.conversationId ||
    senderProjection.accountId !== membership.accountId ||
    senderProjection.credentialId !== membership.credentialId ||
    senderProjection.credentialFingerprint !==
      membership.credentialFingerprint ||
    senderProjection.credentialRevocationVersion !==
      membership.credentialRevocationVersion ||
    senderProjection.credentialState !== membership.credentialState ||
    senderProjection.credentialExpiresAt !== membership.credentialExpiresAt ||
    senderProjection.installationState !==
      membership.installationState ||
    senderProjection.joinedPosition !== membership.joinedPosition ||
    senderProjection.removedPosition !== membership.removedPosition
  ) {
    throw new TypeError(
      "Fictional recipient roster must exactly project the locked sender membership.",
    );
  }
  const attachments = parseDataArray(record.attachments, "attachments").map(
    (entry, index) => parseLabAttachment(entry, index),
  );
  if (
    new Set(attachments.map(({ attachmentId }) => attachmentId)).size !==
    attachments.length
  ) {
    throw new TypeError("Fictional lab attachment IDs must be unique.");
  }
  return Object.freeze({
    snapshot,
    basePosition,
    baseHeadHash,
    now: parseRfc3339Millis(record.now),
    signingKeyId: parseSigningKeyId(record.signingKeyId),
    signingKeyValidFrom,
    signingKeyValidUntil,
    recipientProjections,
    mlsRosterProjections,
    attachments: Object.freeze(attachments),
  });
}

function seedArrayCeiling(value: unknown, label: string): Uint63String {
  const entries = parseDataArray(value, label);
  if (entries.length === 0) {
    throw new TypeError(`Fictional recipient roster ${label} cannot be empty.`);
  }
  return parseUint63String(String(entries.length));
}

function parseLabAttachment(value: unknown, index: number): LabAttachment {
  const record = expectExactRecord(
    value,
    ["attachmentId", "accountId", "byteLength", "state", "boundEnvelopeId"],
    `fictional lab attachment ${index}`,
  );
  if (record.state !== "finalized" && record.state !== "bound") {
    throw new TypeError("Fictional attachment state is unsupported.");
  }
  const boundEnvelopeId =
    record.boundEnvelopeId === null
      ? null
      : parseEnvelopeId(record.boundEnvelopeId);
  if (
    (record.state === "finalized" && boundEnvelopeId !== null) ||
    (record.state === "bound" && boundEnvelopeId === null)
  ) {
    throw new TypeError("Fictional attachment binding is inconsistent.");
  }
  return Object.freeze({
    attachmentId: parseAttachmentId(record.attachmentId),
    accountId: parseAccountId(record.accountId),
    byteLength: parseUint63String(record.byteLength),
    state: record.state,
    boundEnvelopeId,
  });
}

function parseDataArray(value: unknown, label: string): readonly unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    throw new TypeError(`${label} must be a data-only array.`);
  }
  if (
    Reflect.ownKeys(value).length !== value.length + 1 ||
    Reflect.ownKeys(value).at(-1) !== "length"
  ) {
    throw new TypeError(`${label} must be a dense data-only array.`);
  }
  return value.map((entry) => entry);
}

function checkpointVerificationRequest(
  envelope: StoredApplicationEnvelope,
  pending: PendingApplicationAppendIntent,
  signature: Ed25519Signature,
  verifiedAt: Rfc3339Millis,
  invocation: DeliveryInvocationContext,
): DeliveryCheckpointSignatureVerificationRequest {
  return Object.freeze({
    profile: "delivery-log-checkpoint.v1",
    realmId: pending.admissionCommand.realmId,
    conversationId: envelope.conversationId,
    conversationGeneration: pending.priorSnapshot.conversation.generation,
    releaseProfileId: pending.admissionCommand.releaseProfileId,
    releaseTrustRootDigest:
      pending.admissionCommand.releaseTrustRootDigest,
    position: envelope.position,
    previousHeadHash: envelope.previousHeadHash,
    headHash: envelope.headHash,
    signingKeyId: envelope.logSigningKeyId,
    checkpointDigest: envelope.logCheckpointDigest,
    signature,
    checkpointReceivedAt: envelope.receivedAt,
    verifiedAt,
    ...invocation,
  });
}

function rejected(
  reasonCode:
    | "conversation-not-found"
    | "conversation-state-changed"
    | "attachment-invalid"
    | "delivery-limit-exceeded",
) {
  return Object.freeze({ status: "rejected", reasonCode });
}

function retry() {
  return Object.freeze({ status: "retry", reasonCode: "snapshot-changed" });
}

function conflict() {
  return Object.freeze({
    status: "conflict",
    reasonCode: "idempotency-conflict",
  });
}

function unavailable(
  reasonCode:
    | "not-configured"
    | "dependency-unavailable"
    | "timeout"
    | "malformed-dependency-response" = "not-configured",
) {
  return Object.freeze({ status: "unavailable", reasonCode });
}

function recipientEligibleAt(
  projection: ApplicationAppendRecipientProjection,
  position: Uint63String,
): boolean {
  return (
    projection.installationState === "active" &&
    BigInt(projection.joinedPosition) <= BigInt(position) &&
    (projection.removedPosition === null ||
      BigInt(position) <= BigInt(projection.removedPosition))
  );
}

function transactionDeadline(
  now: Rfc3339Millis,
  invocationDeadline: Rfc3339Millis,
): Rfc3339Millis {
  const candidate = new Date(
    Date.parse(now) + TRANSACTION_DEADLINE_MARGIN_MILLISECONDS,
  ).toISOString();
  return parseRfc3339Millis(
    candidate < invocationDeadline ? candidate : invocationDeadline,
  );
}

function cloneDatabase(database: LabDatabase): LabDatabase {
  return {
    snapshot: cloneSnapshot(database.snapshot),
    pending: database.pending,
    pendingReservedAt: database.pendingReservedAt,
    envelopes: [...database.envelopes],
    mailboxes: new Map(
      [...database.mailboxes].map(([installationId, entries]) => [
        installationId,
        [...entries],
      ]),
    ),
    outbox: [...database.outbox],
    httpIdempotency: new Map(database.httpIdempotency),
    secondaryEnvelopes: new Map(database.secondaryEnvelopes),
    attachments: new Map(
      [...database.attachments].map(([attachmentId, attachment]) => [
        attachmentId,
        { ...attachment },
      ]),
    ),
  };
}

function cloneSnapshot(
  snapshot: LockedApplicationAppendSnapshot,
): LockedApplicationAppendSnapshot {
  return parseLockedApplicationAppendSnapshot({
    conversation: { ...snapshot.conversation },
    membership: { ...snapshot.membership },
    policyHead: { ...snapshot.policyHead },
    sendGrant: { ...snapshot.sendGrant },
    pendingRemovalCount: snapshot.pendingRemovalCount,
    usage: { ...snapshot.usage },
    quotaBindings: snapshot.quotaBindings.map((binding) => ({ ...binding })),
    quotas: snapshot.quotas.map((quota) => ({ ...quota })),
  });
}

function dataValue(value: unknown, key: string): unknown {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${key} is unavailable on a data record.`);
  }
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor || !("value" in descriptor)) {
    throw new TypeError(`${key} must be an own data property.`);
  }
  return descriptor.value;
}

function isThenable(value: unknown): boolean {
  if (!value || (typeof value !== "object" && typeof value !== "function")) {
    return false;
  }
  let current: object | null = value;
  while (current !== null) {
    const descriptor = Object.getOwnPropertyDescriptor(current, "then");
    if (descriptor) {
      return (
        !("value" in descriptor) ||
        typeof descriptor.value === "function"
      );
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  return false;
}

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}
