import { Buffer } from "node:buffer";
import {
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  randomUUID,
  sign as signNode,
} from "node:crypto";
import type { Sql, TransactionSql } from "postgres";
import {
  computeApplicationAppendQuotaScopeHash,
  computeConversationSendGrantEvidenceDigest,
} from "../delivery/state";
import { ZERO_HASH32 } from "../delivery/valueObjects";
import type { PolicyHeadSignerPort } from "../delivery/policyHeadIssuance";
import { createPolicyHeadIssuanceStore } from "./policyHeadIssuanceStore";
import { leafHash as merkleLeafHash, merkleRoot } from "../witness/merkleLog";

/**
 * The append-authority graph shared by conversation activation (genesis
 * head, sequence 1) and the membership-Add commit (re-issued head,
 * sequence N+1): signed policy head, its append-lane anchor row, the
 * global policy-log leaf + checkpoint, and one send grant per member whose
 * evidence digest is computed over exactly the row values the append
 * lane's reconstruction re-reads.
 *
 * Bootstrap order the kernel admits: grants are digested against the ZERO
 * head hash, that set is what the head signs, then every grant row is
 * re-anchored at the issued head hash. A re-issue rewrites EVERY existing
 * grant the same way, because admission requires grant.policyHeadSequence/
 * policyHeadHash to equal the conversation's current head.
 */

export const SERVICE_TENANT_ID = "00000000-0000-4000-8000-00000000a001";
export const SERVICE_REALM_ID = "00000000-0000-4000-8000-00000000a002";
const POLICY_LOG_SIGNER_KEY_ID = "jbm-policy-log-2026q3";

export function authorityDerivations(provisioningSeed: Buffer) {
  const deriveSeed = (purpose: string, scope: string): Buffer =>
    createHmac("sha256", provisioningSeed)
      .update(`${purpose}\n${scope}`, "utf8")
      .digest();

  const ed25519 = (seed: Buffer) => {
    const privateKey = createPrivateKey({
      key: Buffer.concat([
        Buffer.from("302e020100300506032b657004220420", "hex"),
        seed,
      ]),
      format: "der",
      type: "pkcs8",
    });
    const publicRaw = Buffer.from(
      createPublicKey(privateKey).export({ format: "jwk" }).x as string,
      "base64url",
    );
    return { privateKey, publicRaw };
  };

  const stableUuid = (purpose: string, scope: string): string => {
    const bytes = deriveSeed(`uuid:${purpose}`, scope).subarray(0, 16);
    const copy = Buffer.from(bytes);
    copy[6] = (copy[6] & 0x0f) | 0x40;
    copy[8] = (copy[8] & 0x3f) | 0x80;
    const hex = copy.toString("hex");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  };

  const roleCredentialId = (
    installationId: string,
    conversationId: string,
  ): string =>
    stableUuid("role-credential", `${conversationId}:${installationId}`);

  // The signer id comes from the PROVISION row, never recomputed — an
  // already-provisioned project keeps whatever id it was provisioned
  // under (the pre-fix 8-char form included).
  const policyHeadSignerFor = (
    projectRefId: string,
    signerKeyId: string,
  ): PolicyHeadSignerPort => {
    const keys = ed25519(deriveSeed("policy-head-signer", projectRefId));
    return Object.freeze({
      signerKeyId,
      sign: (digest: Buffer) => signNode(null, digest, keys.privateKey),
    });
  };

  return Object.freeze({
    deriveSeed,
    ed25519,
    stableUuid,
    roleCredentialId,
    policyHeadSignerFor,
  });
}

export function zeroSetHash(domain: string): Buffer {
  return createHash("sha256").update(domain, "utf8").digest();
}

export function b64ToUrl(value: unknown): string {
  return Buffer.from(String(value).replace(/\s/g, ""), "base64").toString(
    "base64url",
  );
}

export async function readProjectProvision(
  tx: TransactionSql,
  projectRefId: string,
): Promise<Record<string, unknown> | null> {
  const rows = await tx`
    SELECT * FROM project_messaging_provisions
    WHERE project_ref_id = ${projectRefId}`;
  return rows.length === 1 ? rows[0] : null;
}

export function quotaBindingsFor(
  conversationId: string,
  accountId: string,
  installationId: string,
  projectRefId: string,
  windowStartedAt: string,
  realmId: string = SERVICE_REALM_ID,
) {
  const windowStart = new Date(
    Math.floor(Date.parse(windowStartedAt) / 86_400_000) * 86_400_000,
  ).toISOString();
  // Subjects must equal the conversation row's locked scope IDs exactly
  // (state.ts quotaSubjectId): project/tenant use the prefixed scope form.
  const subjects = {
    installation: installationId,
    account: accountId,
    project: `project:${projectRefId}`,
    conversation: conversationId,
    tenant: `tenant:${SERVICE_TENANT_ID}`,
  } as const;
  return (
    ["installation", "account", "project", "conversation", "tenant"] as const
  ).map((scope) => ({
    scope,
    scopeHash: computeApplicationAppendQuotaScopeHash({
      realmId,
      scope,
      subjectId: subjects[scope],
    }),
    subjectId: subjects[scope],
    quotaName: "application-append",
    windowStartedAt: windowStart,
    windowSeconds: "86400",
    operationLimit: "1000",
    byteLimit: "1048576",
  }));
}

export type QuotaBinding = ReturnType<typeof quotaBindingsFor>[number];

/** quota_scopes + quota_counters rows for a binding (idempotent). */
export async function insertQuotaScopeAndCounter(
  tx: TransactionSql,
  binding: QuotaBinding,
  realmId: string,
  now: string,
): Promise<void> {
  await tx`
    INSERT INTO quota_scopes (
      scope_type, scope_hash, realm_id, subject_id, created_at
    ) VALUES (
      ${binding.scope}, ${Buffer.from(binding.scopeHash, "base64url")},
      ${realmId}, ${binding.subjectId}, ${now}::timestamptz
    ) ON CONFLICT DO NOTHING`;
  await tx`
    INSERT INTO quota_counters (
      scope_type, scope_hash, quota_name, window_started_at,
      window_seconds, operation_count, byte_count,
      reserved_operation_count, reserved_byte_count, row_version,
      updated_at
    ) VALUES (
      ${binding.scope}, ${Buffer.from(binding.scopeHash, "base64url")},
      ${binding.quotaName}, ${binding.windowStartedAt}::timestamptz,
      ${binding.windowSeconds}, 0, 0, 0, 0, 0, ${now}::timestamptz
    ) ON CONFLICT DO NOTHING`;
}

/**
 * A member added after genesis gets its own installation/account-scoped
 * binding rows (the project/conversation/tenant rows are shared); each
 * sender's reconstruction selects exactly its five. Two devices on one
 * account share the account row, so an existing binding is kept as-is.
 * The quota policy digest covers neither scope hash nor window start, so
 * appending rows at max(ordinal)+1 leaves the signed policy intact.
 */
export async function ensureMemberQuotaBindings(
  tx: TransactionSql,
  input: {
    conversationId: string;
    accountId: string;
    installationId: string;
    projectRefId: string;
    /** The conversation row's realm: the scope hash commits to it. */
    realmId: string;
    quotaPolicyDigest: Buffer;
    windowStartedAt: string;
    now: string;
  },
): Promise<void> {
  const bindings = quotaBindingsFor(
    input.conversationId,
    input.accountId,
    input.installationId,
    input.projectRefId,
    input.windowStartedAt,
    input.realmId,
  ).filter(
    (binding) =>
      binding.scope === "installation" || binding.scope === "account",
  );
  for (const binding of bindings) {
    await insertQuotaScopeAndCounter(tx, binding, input.realmId, input.now);
    const existing = await tx`
      SELECT 1 FROM conversation_quota_bindings
      WHERE conversation_id = ${input.conversationId}
        AND scope_type = ${binding.scope}
        AND scope_hash = ${Buffer.from(binding.scopeHash, "base64url")}
        AND quota_name = ${binding.quotaName}`;
    if (existing.length > 0) continue;
    const ordinalRows = await tx`
      SELECT COALESCE(MAX(ordinal), -1)::int AS max_ordinal
      FROM conversation_quota_bindings
      WHERE conversation_id = ${input.conversationId}`;
    const ordinal = Number(ordinalRows[0].max_ordinal) + 1;
    await tx`
      INSERT INTO conversation_quota_bindings (
        conversation_id, quota_policy_digest, scope_type, scope_hash,
        quota_name, window_seconds, operation_limit, byte_limit,
        ordinal, window_started_at
      ) VALUES (
        ${input.conversationId}, ${input.quotaPolicyDigest},
        ${binding.scope}, ${Buffer.from(binding.scopeHash, "base64url")},
        ${binding.quotaName}, ${binding.windowSeconds},
        ${binding.operationLimit}, ${binding.byteLimit}, ${ordinal},
        ${binding.windowStartedAt}::timestamptz
      )`;
  }
}

/** The digest-covered send-grant values that do not depend on the head. */
export interface GrantMaterial {
  readonly installationId: string;
  readonly accountId: string;
  readonly credentialId: string;
  readonly role: string;
  /** base64url, 32 bytes */
  readonly credentialFingerprint: string;
  readonly validFrom: string;
  readonly validUntil: string;
  readonly expiresAt: string;
}

export interface IssueConversationPolicyHeadInput {
  readonly provisioningSeed: Buffer;
  readonly conversationId: string;
  readonly projectRefId: string;
  readonly provision: Record<string, unknown>;
  readonly conversationKind: string;
  readonly conversationGeneration: string;
  readonly quotaPolicyDigest: Buffer;
  readonly grants: readonly GrantMaterial[];
  readonly selectedInstallationId: string;
  /**
   * Genesis inserts the anchor before the position-one envelope exists
   * (log positions zero, epoch 1, roster 0); a re-issue updates the single
   * per-conversation anchor row from the locked conversation row.
   */
  readonly anchor:
    | {
        readonly mode: "insert";
        readonly confirmedTranscriptHash: string;
      }
    | { readonly mode: "update" };
  readonly now: string;
}

export type IssuedConversationPolicyHead =
  | {
      readonly status: "issued";
      readonly policyHeadId: string;
      readonly policyHeadSequence: string;
      readonly policyHeadHash: string;
    }
  | { readonly status: "unavailable" };

export async function issueConversationPolicyHead(
  tx: TransactionSql,
  input: IssueConversationPolicyHeadInput,
): Promise<IssuedConversationPolicyHead> {
  const {
    conversationId,
    projectRefId,
    provision,
    now,
    conversationGeneration: generation,
  } = input;
  const { deriveSeed, ed25519, stableUuid, policyHeadSignerFor } =
    authorityDerivations(input.provisioningSeed);

  const issuance = createPolicyHeadIssuanceStore({
    sql: tx as unknown as Sql,
    signer: policyHeadSignerFor(
      projectRefId,
      String(provision.policy_head_signing_key_id),
    ),
  });
  const currentSender = await tx`
    SELECT encode(credential_fingerprint, 'base64') AS fp,
           signer_generation
    FROM external_sender_credentials
    WHERE external_sender_credential_id =
          ${String(provision.current_external_sender_credential_id)}`;
  if (currentSender.length !== 1) {
    return Object.freeze({ status: "unavailable" as const });
  }
  const sequenceRows = await tx`
    SELECT last_policy_head_sequence FROM conversations
    WHERE conversation_id = ${conversationId}`;
  const issuedSequence = String(
    BigInt(String(sequenceRows[0].last_policy_head_sequence)) + 1n,
  );
  const policyRevision = String(provision.policy_revision);

  // EVERY member gets a send grant with its REAL evidence digest over the
  // exact row values the reconstruction re-reads, so every member has a
  // per-sender custody fence and can append. Grants anchor to the zero
  // head first: the digests must exist BEFORE the head that carries them
  // is signed.
  const memberGrants = input.grants.map((member) => {
    const grantWithoutDigests = {
      conversationId,
      installationId: member.installationId,
      credentialId: member.credentialId,
      conversationKind: input.conversationKind,
      conversationGeneration: generation,
      role: member.role,
      roleCredentialId: member.credentialId,
      roleCredentialFingerprint: member.credentialFingerprint,
      roleCredentialSubjectAccountId: member.accountId,
      roleCredentialSubjectInstallationId: member.installationId,
      roleCredentialValidFrom: member.validFrom,
      roleCredentialValidUntil: member.validUntil,
      capability: "send_application",
      state: "active",
      policyRevision,
      policyHeadSequence: issuedSequence,
      policyHeadHash: ZERO_HASH32,
      expiresAt: member.expiresAt,
    };
    return {
      member,
      grantWithoutDigests,
      grantEvidenceDigest: computeConversationSendGrantEvidenceDigest(
        grantWithoutDigests as never,
      ),
      grantInclusionEvidenceDigest: deriveSeed(
        "send-grant-inclusion",
        `${conversationId}:${member.installationId}`,
      ).toString("base64url"),
    };
  });
  const selectedGrant = memberGrants.find(
    (grant) => grant.member.installationId === input.selectedInstallationId,
  );
  if (!selectedGrant) {
    throw new Error("Selected send grant is not among the issued grants.");
  }
  const sendGrantSetMembers = memberGrants.map((grant) => ({
    grantEvidenceDigest: grant.grantEvidenceDigest,
    grantInclusionEvidenceDigest: grant.grantInclusionEvidenceDigest,
    installationId: grant.member.installationId,
    credentialId: grant.member.credentialId,
    role: grant.member.role,
  }));
  const issued = await issuance.issuePolicyHead({
    conversationId,
    policyId: String(provision.policy_id),
    policyRevision,
    policyHash: deriveSeed("policy-hash", projectRefId).toString("base64url"),
    authorizedQuotaPolicyDigest: input.quotaPolicyDigest.toString("base64url"),
    evaluatedChainId: await projectChainId(tx, projectRefId),
    evaluatedBlock: "0",
    evaluatedBlockHash: deriveSeed("evaluated-block", conversationId).toString(
      "base64url",
    ),
    activeExternalSenderCredentialId: String(
      provision.current_external_sender_credential_id,
    ),
    activeExternalSenderFingerprint: b64ToUrl(String(currentSender[0].fp)),
    activeSignerGeneration: String(currentSender[0].signer_generation),
    directoryCheckpointId: String(provision.directory_checkpoint_id),
    policyLogCheckpointId: String(provision.policy_log_checkpoint_id),
    mandatoryProposals: [],
    sendGrantSetMembers,
  });
  if (issued.policyHeadSequence !== issuedSequence) {
    throw new Error("Policy head sequence diverged from the issued grants.");
  }
  // Re-anchor every grant at the issued head. The grant digest commits the
  // head hash, and the head's signed body committed the zero-anchored
  // digests - the bootstrap order the kernel admits: rows carry the
  // post-issuance digests the append path recomputes.
  for (const grant of memberGrants) {
    grant.grantEvidenceDigest = computeConversationSendGrantEvidenceDigest({
      ...grant.grantWithoutDigests,
      policyHeadHash: issued.policyHeadHash,
    } as never);
  }
  const served = await issuance.readNewestPolicyHead(conversationId);
  if (!served) {
    return Object.freeze({ status: "unavailable" as const });
  }
  const signedBodySha = createHash("sha256")
    .update(Buffer.from(served.canonicalSignedBody, "base64url"))
    .digest();
  const signatureSha = createHash("sha256")
    .update(Buffer.from(served.signature, "base64url"))
    .digest();
  const headExpiry = served.expiresAt;
  const headHashBytes = Buffer.from(issued.policyHeadHash, "base64url");
  const priorSequence =
    issued.policyHeadSequence === "1" ? 0 : Number(issued.policyHeadSequence) - 1;
  const priorHash =
    issued.previousPolicyHeadHash === ZERO_HASH32
      ? Buffer.alloc(32)
      : Buffer.from(issued.previousPolicyHeadHash, "base64url");

  if (input.anchor.mode === "insert") {
    await tx`
      INSERT INTO delivery_policy_head_anchors (
        conversation_id, policy_head_id, policy_head_sequence,
        policy_head_hash, delivery_log_position, delivery_log_head_hash,
        evaluation_log_position, evaluation_log_head_hash, epoch,
        roster_version, confirmed_transcript_hash, policy_revision,
        signed_body_sha256, signer_key_id, signature_sha256,
        witness_evidence_digest, proof_evidence_digest,
        policy_consistency_evidence_digest, proof_verified_at, issued_at,
        expires_at, witness_state, witness_checkpoint_id,
        witnessed_policy_head_hash, mandatory_proposal_count,
        mandatory_proposal_set_hash, authorized_send_grant_set_hash,
        selected_send_grant_evidence_digest,
        selected_send_grant_inclusion_evidence_digest,
        authorized_quota_policy_digest, prior_policy_head_sequence,
        prior_policy_head_hash, prior_policy_witness_checkpoint_id,
        prior_policy_witness_evidence_digest, updated_at
      ) VALUES (
        ${conversationId}, ${issued.policyHeadId},
        ${issued.policyHeadSequence},
        ${headHashBytes}, 0,
        ${Buffer.alloc(32)}, 0, ${Buffer.alloc(32)}, 1, 0,
        ${Buffer.from(input.anchor.confirmedTranscriptHash, "base64url")},
        ${policyRevision},
        ${signedBodySha}, ${served.signerKeyId}, ${signatureSha},
        ${deriveSeed("witness-evidence", conversationId)},
        ${deriveSeed("proof-evidence", conversationId)},
        ${deriveSeed("policy-consistency", conversationId)},
        ${now}::timestamptz, ${issued.issuedAt}::timestamptz,
        ${headExpiry}::timestamptz, 'missing', ${null}, ${null},
        0, ${zeroSetHash("jb-msg-policy-mandatory-proposal-set/v1")},
        ${zeroSetHash("jb-msg-send-grant-set/v1")},
        ${Buffer.from(selectedGrant.grantEvidenceDigest, "base64url")},
        ${Buffer.from(selectedGrant.grantInclusionEvidenceDigest, "base64url")},
        ${input.quotaPolicyDigest},
        ${priorSequence}, ${priorHash},
        ${stableUuid("prior-witness-checkpoint", conversationId)},
        ${deriveSeed("prior-witness", conversationId)},
        ${now}::timestamptz
      )`;
  } else {
    // The previous head's witness evidence becomes this head's prior
    // evidence when it was cosigned; an unwitnessed predecessor carries
    // its own prior placeholders forward.
    const previous = await tx`
      SELECT policy_head_sequence, witness_state, witness_checkpoint_id,
             witness_evidence_digest, prior_policy_witness_checkpoint_id,
             prior_policy_witness_evidence_digest
      FROM delivery_policy_head_anchors
      WHERE conversation_id = ${conversationId} FOR UPDATE`;
    if (previous.length !== 1) {
      return Object.freeze({ status: "unavailable" as const });
    }
    if (String(previous[0].policy_head_sequence) !== String(priorSequence)) {
      throw new Error("Policy head anchor is not at the previous sequence.");
    }
    const witnessed =
      String(previous[0].witness_state) === "verified" &&
      previous[0].witness_checkpoint_id !== null;
    const priorWitnessCheckpointId = witnessed
      ? String(previous[0].witness_checkpoint_id)
      : String(previous[0].prior_policy_witness_checkpoint_id);
    const priorWitnessEvidence = witnessed
      ? Buffer.from(previous[0].witness_evidence_digest as Uint8Array)
      : Buffer.from(
          previous[0].prior_policy_witness_evidence_digest as Uint8Array,
        );
    const conversation = await tx`
      SELECT last_position, current_log_head_hash, epoch, roster_version,
             confirmed_transcript_hash
      FROM conversations WHERE conversation_id = ${conversationId}`;
    const c = conversation[0];
    const headScope = `${conversationId}:${issued.policyHeadSequence}`;
    await tx`
      UPDATE delivery_policy_head_anchors SET
        policy_head_id = ${issued.policyHeadId},
        policy_head_sequence = ${issued.policyHeadSequence},
        policy_head_hash = ${headHashBytes},
        delivery_log_position = ${String(c.last_position)},
        delivery_log_head_hash = ${Buffer.from(c.current_log_head_hash as Uint8Array)},
        evaluation_log_position = ${String(c.last_position)},
        evaluation_log_head_hash = ${Buffer.from(c.current_log_head_hash as Uint8Array)},
        epoch = ${String(c.epoch)},
        roster_version = ${String(c.roster_version)},
        confirmed_transcript_hash = ${Buffer.from(c.confirmed_transcript_hash as Uint8Array)},
        policy_revision = ${policyRevision},
        signed_body_sha256 = ${signedBodySha},
        signer_key_id = ${served.signerKeyId},
        signature_sha256 = ${signatureSha},
        witness_evidence_digest = ${deriveSeed("witness-evidence", headScope)},
        proof_evidence_digest = ${deriveSeed("proof-evidence", headScope)},
        policy_consistency_evidence_digest =
          ${deriveSeed("policy-consistency", headScope)},
        proof_verified_at = ${now}::timestamptz,
        issued_at = ${issued.issuedAt}::timestamptz,
        expires_at = ${headExpiry}::timestamptz,
        witness_state = 'missing',
        witness_checkpoint_id = ${null},
        witnessed_policy_head_hash = ${null},
        mandatory_proposal_count = 0,
        mandatory_proposal_set_hash =
          ${zeroSetHash("jb-msg-policy-mandatory-proposal-set/v1")},
        authorized_send_grant_set_hash = ${zeroSetHash("jb-msg-send-grant-set/v1")},
        selected_send_grant_evidence_digest =
          ${Buffer.from(selectedGrant.grantEvidenceDigest, "base64url")},
        selected_send_grant_inclusion_evidence_digest =
          ${Buffer.from(selectedGrant.grantInclusionEvidenceDigest, "base64url")},
        authorized_quota_policy_digest = ${input.quotaPolicyDigest},
        prior_policy_head_sequence = ${priorSequence},
        prior_policy_head_hash = ${priorHash},
        prior_policy_witness_checkpoint_id = ${priorWitnessCheckpointId},
        prior_policy_witness_evidence_digest = ${priorWitnessEvidence},
        updated_at = ${now}::timestamptz
      WHERE conversation_id = ${conversationId}`;
  }

  // Global policy log: this head becomes a leaf, and a checkpoint commits
  // the RFC 6962 root over the whole prefix. The keeper submits
  // unwitnessed checkpoints to the witness's policy namespace; heads stay
  // witness_state='missing' - and appends stay closed - until the cosigned
  // receipt lands.
  const leafCountRows = await tx`
    SELECT count(*)::int AS total FROM policy_log_leaves`;
  const leafIndex = Number(leafCountRows[0].total);
  await tx`
    INSERT INTO policy_log_leaves (
      leaf_index, policy_head_id, head_hash, created_at
    ) VALUES (
      ${leafIndex}, ${issued.policyHeadId}, ${headHashBytes},
      ${now}::timestamptz
    )`;
  const allLeaves = await tx`
    SELECT head_hash FROM policy_log_leaves ORDER BY leaf_index`;
  const policyRoot = merkleRoot(
    allLeaves.map((row) =>
      merkleLeafHash(Buffer.from(row.head_hash as Uint8Array)),
    ),
  );
  const previousCheckpoint = await tx`
    SELECT checkpoint_id FROM policy_log_checkpoints
    WHERE tree_size > 0 AND signer_key_id = ${POLICY_LOG_SIGNER_KEY_ID}
    ORDER BY tree_size DESC LIMIT 1`;
  const policyLogKeys = ed25519(deriveSeed("policy-log-signer", "global"));
  await tx`
    INSERT INTO policy_log_checkpoints (
      checkpoint_id, tree_size, root_hash, previous_checkpoint_id,
      signer_key_id, signature, witness_key_id, witness_signature,
      created_at
    ) VALUES (
      ${randomUUID()}, ${leafIndex + 1}, ${policyRoot},
      ${previousCheckpoint.length === 1
        ? String(previousCheckpoint[0].checkpoint_id)
        : null},
      ${POLICY_LOG_SIGNER_KEY_ID},
      ${signNode(null, policyRoot, policyLogKeys.privateKey)},
      'jbm-witness-pending', ${Buffer.alloc(1)}, ${now}::timestamptz
    )`;

  // Send grants for every member; each column mirrors the digest-covered
  // values exactly. Existing rows (a re-issue) are rewritten in place.
  for (const grant of memberGrants) {
    const m = grant.member;
    await tx`
      INSERT INTO conversation_send_grants (
        conversation_id, installation_id, credential_id,
        conversation_kind, conversation_generation, role,
        role_credential_id, role_credential_fingerprint,
        role_credential_subject_account_id,
        role_credential_subject_installation_id,
        role_credential_valid_from, role_credential_valid_until,
        capability, state, policy_revision, policy_head_sequence,
        policy_head_hash, expires_at, grant_evidence_digest,
        grant_inclusion_evidence_digest
      ) VALUES (
        ${conversationId}, ${m.installationId}, ${m.credentialId},
        ${input.conversationKind}, ${generation}, ${m.role}, ${m.credentialId},
        ${Buffer.from(m.credentialFingerprint, "base64url")},
        ${m.accountId}, ${m.installationId},
        ${m.validFrom}::timestamptz, ${m.validUntil}::timestamptz,
        'send_application', 'active', ${policyRevision},
        ${issued.policyHeadSequence},
        ${headHashBytes}, ${m.expiresAt}::timestamptz,
        ${Buffer.from(grant.grantEvidenceDigest, "base64url")},
        ${Buffer.from(grant.grantInclusionEvidenceDigest, "base64url")}
      )
      ON CONFLICT (conversation_id, installation_id, credential_id)
      DO UPDATE SET
        conversation_kind = EXCLUDED.conversation_kind,
        conversation_generation = EXCLUDED.conversation_generation,
        role = EXCLUDED.role,
        role_credential_id = EXCLUDED.role_credential_id,
        role_credential_fingerprint = EXCLUDED.role_credential_fingerprint,
        role_credential_subject_account_id =
          EXCLUDED.role_credential_subject_account_id,
        role_credential_subject_installation_id =
          EXCLUDED.role_credential_subject_installation_id,
        role_credential_valid_from = EXCLUDED.role_credential_valid_from,
        role_credential_valid_until = EXCLUDED.role_credential_valid_until,
        capability = EXCLUDED.capability,
        state = EXCLUDED.state,
        policy_revision = EXCLUDED.policy_revision,
        policy_head_sequence = EXCLUDED.policy_head_sequence,
        policy_head_hash = EXCLUDED.policy_head_hash,
        expires_at = EXCLUDED.expires_at,
        grant_evidence_digest = EXCLUDED.grant_evidence_digest,
        grant_inclusion_evidence_digest = EXCLUDED.grant_inclusion_evidence_digest`;
  }

  return Object.freeze({
    status: "issued" as const,
    policyHeadId: issued.policyHeadId,
    policyHeadSequence: issued.policyHeadSequence,
    policyHeadHash: issued.policyHeadHash,
  });
}

async function projectChainId(
  tx: TransactionSql,
  projectRefId: string,
): Promise<string> {
  const rows = await tx`
    SELECT chain_id FROM project_refs WHERE project_ref_id = ${projectRefId}`;
  return String(rows[0].chain_id);
}

/**
 * Lazily provisions per-project signing material and checkpoints:
 * policy row, bootstrap policy-log/directory checkpoints, current+staged
 * external-sender credentials, the policy-head signing key and the
 * provision row that pins their ids. Idempotent.
 */
export async function provisionProjectMessaging(
tx: TransactionSql,
provisioningSeed: Buffer,
projectRefId: string,
now: string,
): Promise<Record<string, unknown>> {
const { deriveSeed, ed25519, stableUuid } =
  authorityDerivations(provisioningSeed);
  const existing = await tx`
    SELECT * FROM project_messaging_provisions
    WHERE project_ref_id = ${projectRefId}`;
  if (existing.length === 1) return existing[0];

  const policyId = stableUuid("policy", projectRefId);
  await tx`
    INSERT INTO policies (
      policy_id, policy_revision, project_ref_id, canonical_document,
      policy_hash, created_at
    ) VALUES (
      ${policyId}, 1, ${projectRefId},
      ${JSON.stringify({ profile: "project-support-standard-v1" })}::jsonb,
      ${deriveSeed("policy-hash", projectRefId)}, ${now}::timestamptz
    ) ON CONFLICT DO NOTHING`;
  const policyLogCheckpointId = stableUuid("policy-log-checkpoint", projectRefId);
  await tx`
    INSERT INTO policy_log_checkpoints (
      checkpoint_id, tree_size, root_hash, signer_key_id, signature,
      witness_key_id, witness_signature, created_at
    ) VALUES (
      ${policyLogCheckpointId}, 0, ${Buffer.alloc(32)},
      'jbm-policy-log-unwitnessed', ${Buffer.alloc(1)},
      'jbm-witness-pending', ${Buffer.alloc(1)}, ${now}::timestamptz
    ) ON CONFLICT DO NOTHING`;
  const directoryCheckpointId = stableUuid("directory-checkpoint", projectRefId);
  await tx`
    INSERT INTO directory_checkpoints (
      checkpoint_id, tree_size, root_hash, signer_key_id, signature,
      created_at
    ) VALUES (
      ${directoryCheckpointId}, 0, ${Buffer.alloc(32)},
      'jbm-directory-unwitnessed', ${Buffer.alloc(1)}, ${now}::timestamptz
    ) ON CONFLICT DO NOTHING`;

  const currentSenderId = stableUuid("external-sender-current", projectRefId);
  const stagedSenderId = stableUuid("external-sender-staged", projectRefId);
  for (const [senderId, generation, purpose] of [
    [currentSenderId, 1, "external-sender-current"],
    [stagedSenderId, 2, "external-sender-staged"],
  ] as const) {
    const keys = ed25519(deriveSeed(purpose, projectRefId));
    await tx`
      INSERT INTO external_sender_credentials (
        external_sender_credential_id, project_ref_id, signer_generation,
        credential_public, credential_fingerprint, not_before, expires_at,
        created_checkpoint_id, witnessed_at, lifecycle_state
      ) VALUES (
        ${senderId}, ${projectRefId}, ${generation}, ${keys.publicRaw},
        ${createHash("sha256")
          .update("jb-msg-external-sender-fingerprint/v1", "utf8")
          .update(keys.publicRaw)
          .digest()},
        ${now}::timestamptz, ${now}::timestamptz + interval '89 days',
        ${policyLogCheckpointId}, ${now}::timestamptz, 'published'
      ) ON CONFLICT DO NOTHING`;
  }

  // An earlier suite or deployment may already hold this project's
  // generation slots (UNIQUE(project_ref_id, signer_generation)); adopt
  // whatever credential actually occupies each generation.
  const adopted = await tx`
    SELECT external_sender_credential_id, signer_generation
    FROM external_sender_credentials
    WHERE project_ref_id = ${projectRefId}
      AND signer_generation IN (1, 2)`;
  const adoptedByGeneration = new Map(
    adopted.map((row) => [
      Number(row.signer_generation),
      String(row.external_sender_credential_id),
    ]),
  );
  const effectiveCurrentId = adoptedByGeneration.get(1) ?? currentSenderId;
  const effectiveStagedId = adoptedByGeneration.get(2) ?? stagedSenderId;

  // The FULL project ref keeps the key id globally unique — an 8-char
  // prefix collides across projects sharing a uuid prefix, and the
  // second project would silently adopt the first's key via the
  // ON CONFLICT DO NOTHING below. Already-provisioned projects keep
  // their stored id: issuance reads it from the provision row.
  const signingKeyId = `jbm-policy-head-${projectRefId}`;
  const headKeys = ed25519(deriveSeed("policy-head-signer", projectRefId));
  await tx`
    INSERT INTO policy_head_signing_keys (
      policy_head_signing_key_id, project_ref_id, public_key,
      key_fingerprint, not_before, expires_at, lifecycle_state,
      policy_checkpoint_id
    ) VALUES (
      ${signingKeyId}, ${projectRefId}, ${headKeys.publicRaw},
      ${createHash("sha256")
        .update("jb-msg-policy-head-key-fingerprint/v1", "utf8")
        .update(headKeys.publicRaw)
        .digest()},
      ${now}::timestamptz, ${now}::timestamptz + interval '365 days',
      'active', ${policyLogCheckpointId}
    ) ON CONFLICT DO NOTHING`;

  await tx`
    INSERT INTO project_messaging_provisions (
      project_ref_id, policy_id, policy_revision, policy_log_checkpoint_id,
      directory_checkpoint_id, current_external_sender_credential_id,
      staged_external_sender_credential_id, policy_head_signing_key_id,
      provisioned_at
    ) VALUES (
      ${projectRefId}, ${policyId}, 1, ${policyLogCheckpointId},
      ${directoryCheckpointId}, ${effectiveCurrentId}, ${effectiveStagedId},
      ${signingKeyId}, ${now}::timestamptz
    )`;
  const rows = await tx`
    SELECT * FROM project_messaging_provisions
    WHERE project_ref_id = ${projectRefId}`;
  return rows[0];
}
