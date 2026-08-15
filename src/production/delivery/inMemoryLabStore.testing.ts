import { Buffer } from "node:buffer";
import {
  createPrivateKey,
  createPublicKey,
  sign as signEd25519,
  verify as verifyEd25519,
} from "node:crypto";
import {
  applicationEnvelopeSemanticallyEqual,
  enforceApplicationAppendDeliveryLimits,
  enforceStoredEnvelopeDeliveryLimits,
  parseStoredEnvelope,
  type ApplicationEnvelopeSemanticIdentity,
  type StoredApplicationEnvelope,
} from "./envelopes";
import {
  computeDeliveryLogCheckpointDigest,
  computeEnvelopeLeafHash,
  computeEnvelopeSha256,
  computeLogHeadHash,
  sha256Bytes,
} from "./hashes";
import { classifyHttpIdempotencyCommitment } from "./idempotency";
import type {
  AtomicApplicationAppendCommand,
  AtomicDeliveryPersistencePort,
  DeliveryCheckpointSignatureVerificationRequest,
  DeliveryCheckpointSigningRequest,
  DeliveryInvocationContext,
  FinalizeApplicationAppendInput,
  MlsWireInspectionRequest,
  PolicyHeadProofVerificationRequest,
  PrepareUnsignedApplicationAppend,
  ProductionDeliveryPorts,
} from "./ports";
import {
  computeAtomicApplicationAppendCommandDigest,
  computeMlsApplicationWireInspectionEvidenceDigest,
  parseApplicationEnvelopeReceipt,
  parseAtomicApplicationAppendCommand,
  parseMlsApplicationWireInspectionEvidence,
  parsePendingApplicationAppendIntent,
  parsePreparedApplicationAppend,
  receiptFromStoredApplicationEnvelope,
  type PendingApplicationAppendIntent,
  type PersistedApplicationAppendAcceptance,
} from "./service";
import {
  computeLockedApplicationAppendSnapshotDigest,
  computePolicyHeadProofEvidenceDigest,
  parseLockedApplicationAppendSnapshot,
  parsePolicyHeadProofEvidence,
  refreshLockedApplicationAppendAuthorizationSnapshot,
  validateLockedApplicationAppendStateTransition,
  type LockedApplicationAppendSnapshot,
  type LockedConversationUsage,
  type PolicyHeadProofEvidence,
} from "./state";
import {
  computeDeliveryCheckpointSignatureEvidenceDigest,
  parseDeliveryRealmId,
  parseDeliveryCheckpointSignatureEvidence,
} from "./sync";
import {
  MLS_PRIVATE_MESSAGE_MEDIA_TYPE,
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

const HTTP_IDEMPOTENCY_TTL_MILLISECONDS = 7 * 24 * 60 * 60 * 1_000;
const TRANSACTION_DEADLINE_MARGIN_MILLISECONDS = 250;
const FICTIONAL_ED25519_PKCS8_PREFIX = Buffer.from(
  "302e020100300506032b657004220420",
  "hex",
);
const FICTIONAL_ED25519_SEED = Buffer.from(
  Array.from({ length: 32 }, (_, index) => index + 1),
);
const FICTIONAL_DELIVERY_LAB_PRIVATE_KEY = createPrivateKey({
  key: Buffer.concat([FICTIONAL_ED25519_PKCS8_PREFIX, FICTIONAL_ED25519_SEED]),
  format: "der",
  type: "pkcs8",
});
const FICTIONAL_DELIVERY_LAB_PUBLIC_KEY = createPublicKey(
  FICTIONAL_DELIVERY_LAB_PRIVATE_KEY,
);

/** Paired only with the deterministic private key in this testing module. */
export const FICTIONAL_DELIVERY_LAB_ED25519_PUBLIC_KEY_SPKI_BASE64URL =
  FICTIONAL_DELIVERY_LAB_PUBLIC_KEY.export({
    format: "der",
    type: "spki",
  }).toString("base64url");

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

export interface InMemoryDeliveryLabRecipientProjectionSeed {
  readonly conversationId: unknown;
  readonly installationId: unknown;
  readonly rosterVersion: unknown;
  readonly installationState: unknown;
  readonly joinedPosition: unknown;
  readonly removedPosition: unknown;
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

export interface DeliveryLabSignerHistoryEntry {
  readonly conversationId: ConversationId;
  readonly position: Uint63String;
  readonly checkpointDigest: Hash32;
  readonly signature: Ed25519Signature;
  readonly callCount: number;
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

interface LabRecipientProjection {
  readonly conversationId: ConversationId;
  readonly installationId: InstallationId;
  readonly rosterVersion: Uint63String;
  readonly installationState: "active" | "suspended" | "revoked";
  readonly joinedPosition: Uint63String;
  readonly removedPosition: Uint63String | null;
}

type StoredAcceptance = PersistedApplicationAppendAcceptance;

interface HttpIdempotencyRecord {
  readonly requestCommitment: Hash32;
  readonly acceptance: StoredAcceptance;
  readonly expiresAtMilliseconds: number;
}

interface SignerFence {
  readonly conversationId: ConversationId;
  readonly position: Uint63String;
  readonly checkpointDigest: Hash32;
  readonly signature: Ed25519Signature;
  callCount: number;
}

interface LabDatabase {
  snapshot: LockedApplicationAppendSnapshot;
  pending: PendingApplicationAppendIntent | null;
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
  readonly recipientProjections: readonly LabRecipientProjection[];
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
  private readonly recipientProjections: readonly LabRecipientProjection[];
  private readonly signerFences = new Map<string, SignerFence>();
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
    this.database = {
      snapshot: cloneSnapshot(seed.snapshot),
      pending: null,
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

    this.productionPorts = Object.freeze({
      mlsWireInspector: {
        inspect: (request: MlsWireInspectionRequest) =>
          this.inspectMlsWire(request),
      },
      mlsCommitProjectionVerifier: {
        verify: () => Promise.resolve(unavailable()),
      },
      mlsExternalProposalVerifier: {
        verify: () => Promise.resolve(unavailable()),
      },
      policyHeadProofVerifier: {
        verify: (request: PolicyHeadProofVerificationRequest) =>
          this.verifyPolicyHead(request),
      },
      conversationPolicyReplayVerifier: {
        // Private lab mailbox sync below does not call production sync.
        verify: () => Promise.resolve(unavailable()),
      },
      checkpointSigner: {
        sign: (request: DeliveryCheckpointSigningRequest) =>
          this.signCheckpointForLab(request),
      },
      checkpointSignatureVerifier: {
        verify: (request: DeliveryCheckpointSignatureVerificationRequest) =>
          this.verifyCheckpointSignature(request),
      },
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
      signerHistory: Object.freeze(
        [...this.signerFences.values()]
          .sort((left, right) =>
            `${left.conversationId}\u0000${left.position}`.localeCompare(
              `${right.conversationId}\u0000${right.position}`,
            ),
          )
          .map((entry) => Object.freeze({ ...entry })),
      ),
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
    reservationValue: {
      command: AtomicApplicationAppendCommand;
      expectedSnapshotDigest: Hash32;
      expectedAuthorizationSnapshotDigest: Hash32;
      wireInspectionEvidence: unknown;
      policyHeadProofEvidence: unknown;
    },
    prepareUnsigned: PrepareUnsignedApplicationAppend,
    invocation: DeliveryInvocationContext,
  ): Promise<unknown> {
    return this.withTransactionLock(() => {
      if (!this.invocationIsLive(invocation)) return unavailable("timeout");
      const command = parseAtomicApplicationAppendCommand(
        reservationValue.command,
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
        return retry("snapshot-changed");
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
        return retry("snapshot-changed");
      }
      this.maybeFail("before-reservation-prepare");
      const preparedValue = prepareUnsigned({
        lockedSnapshot: cloneSnapshot(authorizationSnapshot),
        authoritativeReceivedAt: this.nowValue,
        previousHeadHash: this.database.snapshot.conversation.currentLogHeadHash,
        attachmentByteLength,
        activeSigningKeyId: this.signingKeyId,
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
        pending.wireInspectionEvidence.evidenceDigest !==
          wireEvidence.evidenceDigest ||
        pending.policyHeadProofEvidence.evidenceDigest !==
          policyEvidence.evidenceDigest
      ) {
        throw new TypeError("Reservation callback substituted command or proof facts.");
      }
      validateLockedApplicationAppendStateTransition({
        priorSnapshot: authorizationSnapshot,
        expectation: pending.expectation,
        authoritativeReceivedAt: pending.envelope.receivedAt,
        nextHeadHash: pending.envelope.headHash,
        preparedNextSnapshot: pending.nextSnapshot,
      });
      const draft = cloneDatabase(this.database);
      draft.pending = pending;
      this.maybeFail("before-reservation-commit");
      this.assertInternalInvariants(draft);
      this.database = draft;
      this.maybeFail("after-reservation-commit-before-response");
      return pendingResult(command, pending, "none");
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
        return retry("pending-other");
      }
      if (
        !applicationEnvelopeSemanticallyEqual(
          pending.admissionCommand.semanticIdentity,
          command.semanticIdentity,
        )
      ) {
        return conflict();
      }
      const signature = parseEd25519Signature(inputValue.signature);
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
        inputValue.verifiedSignatureEvidence,
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
        return retry("snapshot-changed");
      }
      if (
        this.measureAttachments(
          this.database,
          pending.admissionCommand.semanticIdentity,
        ) !== pending.attachmentByteLength
      ) {
        return rejected("attachment-invalid");
      }
      validateLockedApplicationAppendStateTransition({
        priorSnapshot: pending.priorSnapshot,
        expectation: pending.expectation,
        authoritativeReceivedAt: pending.envelope.receivedAt,
        nextHeadHash: pending.envelope.headHash,
        preparedNextSnapshot: pending.nextSnapshot,
      });
      this.assertRecipientProjectionsCurrent();

      const receipt = receiptFromStoredApplicationEnvelope(signedEnvelope);
      const acceptance: StoredAcceptance = Object.freeze({
        receipt,
        replay: "none",
        invocationCommandDigest:
          computeAtomicApplicationAppendCommandDigest(command),
        pendingIntent: pending,
        envelope: signedEnvelope,
        signatureEvidence,
      });
      const draft = cloneDatabase(this.database);
      draft.snapshot = cloneSnapshot(pending.nextSnapshot);
      this.maybeFail("after-state-write");
      draft.envelopes.push(signedEnvelope);
      this.maybeFail("after-envelope-write");
      this.bindAttachments(
        draft,
        pending.admissionCommand.semanticIdentity,
        signedEnvelope.envelopeId,
      );
      this.fanOutEligibleRecipients(draft, signedEnvelope);
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
      for (const idempotencyCommand of [
        pending.admissionCommand,
        command,
      ]) {
        draft.httpIdempotency.set(httpIdempotencyScope(idempotencyCommand), {
          requestCommitment: idempotencyCommand.requestCommitment,
          acceptance,
          expiresAtMilliseconds,
        });
      }
      this.maybeFail("after-idempotency-write");
      draft.pending = null;
      this.maybeFail("before-finalization-commit");
      this.assertInternalInvariants(draft);
      this.database = draft;
      this.maybeFail("after-finalization-commit-before-response");
      const replay =
        computeAtomicApplicationAppendCommandDigest(command) ===
        pending.admissionCommandDigest
          ? "none"
          : "envelope";
      return acceptedResult(command, acceptance, replay);
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
            : pendingResult(command, pending, "http"),
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
          ? pendingResult(command, pending, "envelope")
          : conflict(),
      };
    }
    return { kind: "result", value: retry("pending-other") };
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
        : acceptedResult(command, http.acceptance, "http");
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
      acceptance.pendingIntent.admissionCommand.semanticIdentity,
      identity,
    )
      ? acceptedResult(command, acceptance, "envelope")
      : conflict();
  }

  private async inspectMlsWire(
    request: MlsWireInspectionRequest,
  ): Promise<unknown> {
    if (!this.invocationIsLive(request)) return unavailable("timeout");
    const snapshot = this.database.snapshot;
    if (
      request.releaseProfileId !== snapshot.conversation.releaseProfileId ||
      request.expectedGroupIdHash !== snapshot.conversation.groupIdHash ||
      request.expectedEpoch !== snapshot.conversation.epoch ||
      request.contentType !== MLS_PRIVATE_MESSAGE_MEDIA_TYPE ||
      computeEnvelopeSha256(request.envelopeBytes) !== request.envelopeSha256
    ) {
      return unavailable("malformed-dependency-response");
    }
    const evidence = {
      releaseProfileId: request.releaseProfileId,
      expectedGroupIdHash: request.expectedGroupIdHash,
      expectedEpoch: request.expectedEpoch,
      wireKind: request.expectedWireKind,
      contentType: MLS_PRIVATE_MESSAGE_MEDIA_TYPE,
      envelopeSha256: request.envelopeSha256,
      inspectionStatus: "verified" as const,
    };
    return Object.freeze({
      status: "verified",
      profile: "mls-application-wire-inspection.v1",
      ...evidence,
      evidenceDigest:
        computeMlsApplicationWireInspectionEvidenceDigest(evidence),
    });
  }

  private async verifyPolicyHead(
    request: PolicyHeadProofVerificationRequest,
  ): Promise<unknown> {
    if (!this.invocationIsLive(request)) return unavailable("timeout");
    const snapshot = this.database.snapshot;
    const policy = snapshot.policyHead;
    const expected = policyExpectation(snapshot, request.verifiedAt);
    for (const key of Object.keys(expected) as (keyof typeof expected)[]) {
      if (request[key] !== expected[key]) {
        return unavailable("malformed-dependency-response");
      }
    }
    const evidence = {
      ...expected,
      signedBodySha256: policy.signedBodySha256,
      signerKeyId: policy.signerKeyId,
      signatureSha256: policy.signatureSha256,
      witnessCheckpointId: policy.witnessCheckpointId!,
      witnessedPolicyHeadHash: policy.witnessedPolicyHeadHash!,
      witnessEvidenceDigest: policy.witnessEvidenceDigest,
      issuedAt: policy.issuedAt,
      expiresAt: policy.expiresAt,
      signatureStatus: "verified" as const,
      keyStatus: "valid-for-checkpoint" as const,
      witnessStatus: "verified" as const,
      freshnessStatus: "fresh" as const,
      currentStatus: "current" as const,
      policyConsistencyStatus: "verified" as const,
      sendGrantInclusionStatus: "verified" as const,
      policyConsistencyEvidenceDigest:
        policy.policyConsistencyEvidenceDigest,
    };
    return Object.freeze({
      status: "verified",
      profile: "conversation-policy-head-proof.v1",
      ...evidence,
      evidenceDigest: computePolicyHeadProofEvidenceDigest(evidence),
    });
  }

  private async signCheckpointForLab(
    request: DeliveryCheckpointSigningRequest,
  ): Promise<unknown> {
    if (!this.invocationIsLive(request)) return unavailable("timeout");
    this.maybeFail("before-signer-call");
    if (
      request.profile !== "delivery-log-checkpoint.v1" ||
      request.signingKeyId !== this.signingKeyId ||
      request.checkpointDigest !==
        computeDeliveryLogCheckpointDigest({
          conversationId: request.conversationId,
          position: request.position,
          previousHeadHash: request.previousHeadHash,
          headHash: request.headHash,
          signingKeyId: request.signingKeyId,
        })
    ) {
      return unavailable("malformed-dependency-response");
    }
    const fenceKey = signerFenceKey(request.conversationId, request.position);
    const existing = this.signerFences.get(fenceKey);
    if (existing && existing.checkpointDigest !== request.checkpointDigest) {
      return unavailable("malformed-dependency-response");
    }
    const signature =
      existing?.signature ??
      parseEd25519Signature(
        signEd25519(
          null,
          Buffer.from(request.checkpointDigest, "base64url"),
          FICTIONAL_DELIVERY_LAB_PRIVATE_KEY,
        ).toString("base64url"),
      );
    if (existing) {
      existing.callCount += 1;
    } else {
      this.signerFences.set(fenceKey, {
        conversationId: request.conversationId,
        position: request.position,
        checkpointDigest: request.checkpointDigest,
        signature,
        callCount: 1,
      });
    }
    this.maybeFail("after-signer-call");
    return Object.freeze({
      status: "signed",
      profile: "delivery-log-checkpoint.v1",
      conversationId: request.conversationId,
      position: request.position,
      previousHeadHash: request.previousHeadHash,
      headHash: request.headHash,
      signingKeyId: request.signingKeyId,
      checkpointDigest: request.checkpointDigest,
      signature,
    });
  }

  private async verifyCheckpointSignature(
    request: DeliveryCheckpointSignatureVerificationRequest,
  ): Promise<unknown> {
    if (!this.invocationIsLive(request)) return unavailable("timeout");
    this.maybeFail("before-signature-verifier-call");
    const snapshot = this.database.snapshot;
    const valid =
      request.profile === "delivery-log-checkpoint.v1" &&
      request.realmId === snapshot.conversation.realmId &&
      request.conversationGeneration === snapshot.conversation.generation &&
      request.releaseProfileId === snapshot.conversation.releaseProfileId &&
      request.releaseTrustRootDigest ===
        snapshot.conversation.releaseTrustRootDigest &&
      request.signingKeyId === this.signingKeyId &&
      request.checkpointDigest ===
        computeDeliveryLogCheckpointDigest({
          conversationId: request.conversationId,
          position: request.position,
          previousHeadHash: request.previousHeadHash,
          headHash: request.headHash,
          signingKeyId: request.signingKeyId,
        }) &&
      request.checkpointReceivedAt >= this.signingKeyValidFrom &&
      request.checkpointReceivedAt < this.signingKeyValidUntil &&
      request.verifiedAt >= request.checkpointReceivedAt &&
      verifyEd25519(
        null,
        Buffer.from(request.checkpointDigest, "base64url"),
        FICTIONAL_DELIVERY_LAB_PUBLIC_KEY,
        Buffer.from(request.signature, "base64url"),
      );
    if (!valid) return unavailable("malformed-dependency-response");
    const signatureSha256 = sha256Bytes(
      Buffer.from(request.signature, "base64url"),
    );
    const evidence = {
      realmId: request.realmId,
      conversationId: request.conversationId,
      conversationGeneration: request.conversationGeneration,
      releaseProfileId: request.releaseProfileId,
      releaseTrustRootDigest: request.releaseTrustRootDigest,
      position: request.position,
      previousHeadHash: request.previousHeadHash,
      headHash: request.headHash,
      signingKeyId: request.signingKeyId,
      checkpointDigest: request.checkpointDigest,
      signatureSha256,
      checkpointReceivedAt: request.checkpointReceivedAt,
      verifiedAt: request.verifiedAt,
      keyState: "active" as const,
      validFrom: this.signingKeyValidFrom,
      validUntil: this.signingKeyValidUntil,
    };
    this.maybeFail("after-signature-verifier-call");
    return Object.freeze({
      status: "verified",
      profile: "delivery-log-checkpoint.v1",
      ...evidence,
      evidenceDigest:
        computeDeliveryCheckpointSignatureEvidenceDigest(evidence),
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

  private fanOutEligibleRecipients(
    database: LabDatabase,
    envelope: StoredApplicationEnvelope,
  ): void {
    for (const projection of [...this.recipientProjections].sort((left, right) =>
      left.installationId.localeCompare(right.installationId),
    )) {
      if (!recipientEligibleAt(projection, envelope.position)) continue;
      const entries = database.mailboxes.get(projection.installationId);
      if (!entries) throw new TypeError("Authoritative mailbox disappeared.");
      entries.push(
        Object.freeze({
          mailboxPosition: uint63FromBigInt(BigInt(entries.length + 1)),
          installationId: projection.installationId,
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
          projection.rosterVersion !== conversation.rosterVersion,
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
  const recipientProjections = parseDataArray(
    record.recipientProjections,
    "recipientProjections",
  ).map((entry, index) => parseRecipientProjection(entry, index));
  if (
    new Set(recipientProjections.map(({ installationId }) => installationId))
      .size !== recipientProjections.length ||
    recipientProjections.some(
      (projection) =>
        projection.conversationId !== snapshot.conversation.conversationId ||
        projection.rosterVersion !== snapshot.conversation.rosterVersion,
    )
  ) {
    throw new TypeError("Fictional recipient roster is duplicated or stale.");
  }
  const senderProjection = recipientProjections.find(
    ({ installationId }) =>
      installationId === snapshot.membership.installationId,
  );
  if (
    !senderProjection ||
    senderProjection.conversationId !== snapshot.membership.conversationId ||
    senderProjection.rosterVersion !== snapshot.conversation.rosterVersion ||
    senderProjection.installationState !==
      snapshot.membership.installationState ||
    senderProjection.joinedPosition !== snapshot.membership.joinedPosition ||
    senderProjection.removedPosition !== snapshot.membership.removedPosition
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
    recipientProjections: Object.freeze(recipientProjections),
    attachments: Object.freeze(attachments),
  });
}

function parseRecipientProjection(
  value: unknown,
  index: number,
): LabRecipientProjection {
  const record = expectExactRecord(
    value,
    [
      "conversationId",
      "installationId",
      "rosterVersion",
      "installationState",
      "joinedPosition",
      "removedPosition",
    ],
    `fictional recipient projection ${index}`,
  );
  if (
    record.installationState !== "active" &&
    record.installationState !== "suspended" &&
    record.installationState !== "revoked"
  ) {
    throw new TypeError("Fictional recipient state is unsupported.");
  }
  const joinedPosition = parseUint63String(record.joinedPosition);
  if (joinedPosition === "0") {
    throw new TypeError("Fictional recipient join position must be positive.");
  }
  const removedPosition =
    record.removedPosition === null
      ? null
      : parseUint63String(record.removedPosition);
  if (
    removedPosition !== null &&
    BigInt(removedPosition) < BigInt(joinedPosition)
  ) {
    throw new TypeError("Fictional recipient removal predates its join.");
  }
  return Object.freeze({
    conversationId: parseConversationId(record.conversationId),
    installationId: parseInstallationId(record.installationId),
    rosterVersion: parseUint63String(record.rosterVersion),
    installationState: record.installationState,
    joinedPosition,
    removedPosition,
  });
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

function policyExpectation(
  snapshot: LockedApplicationAppendSnapshot,
  verifiedAt: Rfc3339Millis,
) {
  const conversation = snapshot.conversation;
  const policy = snapshot.policyHead;
  return Object.freeze({
    realmId: parseDeliveryRealmId(conversation.realmId),
    conversationGeneration: conversation.generation,
    releaseTrustRootDigest: conversation.releaseTrustRootDigest,
    purpose: "append-authorization" as const,
    releaseProfileId: conversation.releaseProfileId,
    deliveryLimitsDigest: conversation.deliveryLimitsDigest,
    conversationId: conversation.conversationId,
    policyHeadId: policy.policyHeadId,
    policyHeadSequence: policy.policyHeadSequence,
    policyHeadHash: policy.policyHeadHash,
    deliveryLogPosition: policy.deliveryLogPosition,
    deliveryLogHeadHash: policy.deliveryLogHeadHash,
    evaluationLogPosition: conversation.lastPosition,
    evaluationLogHeadHash: conversation.currentLogHeadHash,
    epoch: policy.epoch,
    rosterVersion: policy.rosterVersion,
    confirmedTranscriptHash: policy.confirmedTranscriptHash,
    policyRevision: policy.policyRevision,
    mandatoryProposalCount: policy.mandatoryProposalCount,
    mandatoryProposalSetHash: policy.mandatoryProposalSetHash,
    authorizedSendGrantSetHash: policy.authorizedSendGrantSetHash,
    selectedSendGrantEvidenceDigest:
      policy.selectedSendGrantEvidenceDigest,
    selectedSendGrantInclusionEvidenceDigest:
      policy.selectedSendGrantInclusionEvidenceDigest,
    authorizedQuotaPolicyDigest: policy.authorizedQuotaPolicyDigest,
    priorPolicyHeadSequence: policy.priorPolicyHeadSequence,
    priorPolicyHeadHash: policy.priorPolicyHeadHash,
    priorPolicyWitnessCheckpointId:
      policy.priorPolicyWitnessCheckpointId,
    priorPolicyWitnessEvidenceDigest:
      policy.priorPolicyWitnessEvidenceDigest,
    verifiedAt,
  });
}

function parsePolicyEvidenceForSnapshot(
  value: unknown,
  snapshot: LockedApplicationAppendSnapshot,
): PolicyHeadProofEvidence {
  const verifiedAt = parseRfc3339Millis(dataValue(value, "verifiedAt"));
  return parsePolicyHeadProofEvidence(
    value,
    policyExpectation(snapshot, verifiedAt),
  );
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

function acceptedResult(
  command: AtomicApplicationAppendCommand,
  acceptance: StoredAcceptance,
  replay: "none" | "http" | "envelope",
) {
  return Object.freeze({
    status: "accepted",
    replay,
    invocationCommandDigest:
      computeAtomicApplicationAppendCommandDigest(command),
    pendingIntent: acceptance.pendingIntent,
    envelope: acceptance.envelope,
    receipt: acceptance.receipt,
    signatureEvidence: acceptance.signatureEvidence,
  });
}

function commandTrustMatchesSnapshot(
  command: AtomicApplicationAppendCommand,
  snapshot: LockedApplicationAppendSnapshot,
): boolean {
  const conversation = snapshot.conversation;
  return (
    command.realmId === conversation.realmId &&
    command.releaseProfileId === conversation.releaseProfileId &&
    command.deliveryLimitsDigest === conversation.deliveryLimitsDigest &&
    command.releaseTrustRootDigest === conversation.releaseTrustRootDigest
  );
}

function pendingResult(
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

function retry(reasonCode: "pending-other" | "snapshot-changed") {
  return Object.freeze({ status: "retry", reasonCode });
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

function httpIdempotencyScope(command: AtomicApplicationAppendCommand): string {
  const identity = command.semanticIdentity;
  return [
    command.realmId,
    identity.authenticatedSender.accountId,
    identity.authenticatedSender.installationId,
    "POST",
    "/v1/conversations/{conversationId}/envelopes",
    identity.conversationId,
    command.idempotencyKey,
  ].join("\u0000");
}

function semanticEnvelopeKey(
  realmId: string,
  conversationId: ConversationId,
  envelopeId: EnvelopeId,
): string {
  return `${realmId}\u0000${conversationId}\u0000${envelopeId}`;
}

function signerFenceKey(
  conversationId: ConversationId,
  position: Uint63String,
): string {
  return `${conversationId}\u0000${position}`;
}

function recipientEligibleAt(
  projection: LabRecipientProjection,
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

export function verifyFictionalDeliveryLabReceiptSignatureForTesting(
  value: unknown,
): boolean {
  try {
    const receipt = parseApplicationEnvelopeReceipt(value);
    const digest = computeDeliveryLogCheckpointDigest({
      conversationId: receipt.conversationId,
      position: receipt.position,
      previousHeadHash: receipt.logHead.previousHeadHash,
      headHash: receipt.logHead.headHash,
      signingKeyId: receipt.logHead.signingKeyId,
    });
    return (
      digest === receipt.logHead.checkpointDigest &&
      verifyEd25519(
        null,
        Buffer.from(digest, "base64url"),
        FICTIONAL_DELIVERY_LAB_PUBLIC_KEY,
        Buffer.from(receipt.logHead.signature, "base64url"),
      )
    );
  } catch {
    return false;
  }
}
