import { Buffer } from "node:buffer";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import postgres, { type Sql } from "postgres";
import {
  LAB_CONVERSATION_ID,
  LAB_ENVELOPE_ID,
  LAB_ENVELOPE_ID_2,
  LAB_IDEMPOTENCY_KEY_2,
  LAB_NOW,
  fictionalAppendRequest,
  fictionalDeliveryLabSeed,
  fictionalDeliveryLimits,
  fictionalDeliveryTrustContext,
} from "../delivery/fixtures.testing";
import {
  createFictionalDeliveryCryptoPorts,
  verifyFictionalDeliveryLabReceiptSignatureForTesting,
} from "../delivery/fictionalCryptoPorts.testing";
import type { ProductionDeliveryPorts } from "../delivery/ports";
import { createApplicationEnvelopeDeliveryService } from "../delivery/service";
import {
  parseConversationId,
  parseRfc3339Millis,
  parseSigningKeyId,
  type Rfc3339Millis,
} from "../delivery/valueObjects";
import {
  createPostgresDeliveryAppendStore,
  type PostgresDeliveryAppendStore,
} from "./postgresDeliveryStore";
import {
  installDeliveryLabClock,
  seedPostgresDeliveryLab,
  setDeliveryLabClock,
} from "./postgresDeliveryLab.testing";

const DATABASE_URL = process.env.JBM_STORAGE_DATABASE_URL;
const describeStorage = DATABASE_URL ? describe : describe.skip;

describeStorage("PostgreSQL application-append repository", () => {
  const seed = fictionalDeliveryLabSeed();
  let sql: Sql;
  let store: PostgresDeliveryAppendStore;
  let now: Rfc3339Millis = parseRfc3339Millis(LAB_NOW);

  const buildPorts = (
    overrides: Partial<ProductionDeliveryPorts> = {},
  ): ProductionDeliveryPorts => {
    const crypto = createFictionalDeliveryCryptoPorts({
      now: () => now,
      snapshot: () => store.loadSnapshot(parseConversationId(LAB_CONVERSATION_ID)),
      signingKeyId: parseSigningKeyId(seed.signingKeyId),
      signingKeyValidFrom: parseRfc3339Millis(seed.signingKeyValidFrom),
      signingKeyValidUntil: parseRfc3339Millis(seed.signingKeyValidUntil),
    });
    return {
      mlsWireInspector: crypto.mlsWireInspector,
      mlsCommitProjectionVerifier: {
        verify: () =>
          Promise.resolve({ status: "unavailable", reasonCode: "not-configured" }),
      },
      mlsExternalProposalVerifier: {
        verify: () =>
          Promise.resolve({ status: "unavailable", reasonCode: "not-configured" }),
      },
      policyHeadProofVerifier: crypto.policyHeadProofVerifier,
      conversationPolicyReplayVerifier: {
        verify: () =>
          Promise.resolve({ status: "unavailable", reasonCode: "not-configured" }),
      },
      checkpointSigner: crypto.checkpointSigner,
      signerFenceEvidenceVerifier: crypto.signerFenceEvidenceVerifier,
      checkpointSignatureVerifier: crypto.checkpointSignatureVerifier,
      conversationPageProofVerifier: {
        verify: () =>
          Promise.resolve({ status: "unavailable", reasonCode: "not-configured" }),
      },
      conversationLogHeadProofVerifier: {
        verify: () =>
          Promise.resolve({ status: "unavailable", reasonCode: "not-configured" }),
      },
      applicationAppendPreflight: store.applicationAppendPreflight,
      atomicPersistence: store.atomicPersistence,
      clock: { now: () => now },
      conversationCursorCodec: {
        decode: () =>
          Promise.resolve({ status: "unavailable", reasonCode: "not-configured" }),
        encode: () =>
          Promise.resolve({ status: "unavailable", reasonCode: "not-configured" }),
      },
      invariantIncident: {
        record: () => Promise.resolve({ status: "recorded-in-fictional-lab" }),
      },
      ...overrides,
    };
  };

  const serviceWith = (overrides: Partial<ProductionDeliveryPorts> = {}) =>
    createApplicationEnvelopeDeliveryService(
      buildPorts(overrides),
      fictionalDeliveryTrustContext(),
    );

  beforeAll(async () => {
    sql = postgres(DATABASE_URL!, { max: 8, onnotice: () => {} });
    store = createPostgresDeliveryAppendStore({ sql, now: () => now });
    await installDeliveryLabClock(sql, LAB_NOW);
    await seedPostgresDeliveryLab(sql, seed, fictionalDeliveryLimits());
  });

  afterAll(async () => {
    await sql?.end({ timeout: 5 });
  });

  it("accepts a canonical append and lands every relational projection", async () => {
    const result = await serviceWith().appendApplicationEnvelope(
      fictionalAppendRequest(),
    );
    expect(result).toMatchObject({
      status: "accepted",
      replay: "none",
      receipt: { envelopeId: LAB_ENVELOPE_ID, position: "2" },
    });
    if (result.status !== "accepted") throw new Error("append was not accepted");
    expect(
      verifyFictionalDeliveryLabReceiptSignatureForTesting(result.receipt),
    ).toBe(true);

    const [envelopeRow] = await sql`
      SELECT envelope_class, content_type, octet_length(log_head_signature) AS signature_length,
             received_at
      FROM envelopes WHERE conversation_id = ${LAB_CONVERSATION_ID} AND position = 2`;
    expect(envelopeRow.envelope_class).toBe("application");
    expect(envelopeRow.content_type).toBe(
      "application/vnd.juicebox.messaging.mls-private-message",
    );
    expect(Number(envelopeRow.signature_length)).toBe(64);
    const [conversationRow] = await sql`
      SELECT last_position FROM conversations
      WHERE conversation_id = ${LAB_CONVERSATION_ID}`;
    expect(String(conversationRow.last_position)).toBe("2");
    const [counts] = await sql`
      SELECT
        (SELECT count(*) FROM mailbox_entries WHERE conversation_id = ${LAB_CONVERSATION_ID}) AS mailboxes,
        (SELECT count(*) FROM application_append_acceptances WHERE conversation_id = ${LAB_CONVERSATION_ID}) AS acceptances,
        (SELECT count(*) FROM application_append_pendings WHERE conversation_id = ${LAB_CONVERSATION_ID}) AS pendings,
        (SELECT count(*) FROM outbox_events) AS outbox`;
    expect(String(counts.mailboxes)).toBe("2");
    expect(String(counts.acceptances)).toBe("1");
    expect(String(counts.pendings)).toBe("0");
    expect(String(counts.outbox)).toBe("1");
  });

  it("replays the durable receipt across fresh service instances", async () => {
    const first = await serviceWith().appendApplicationEnvelope(
      fictionalAppendRequest(),
    );
    const httpReplay = await serviceWith().appendApplicationEnvelope(
      fictionalAppendRequest(),
    );
    const envelopeReplay = await serviceWith().appendApplicationEnvelope(
      fictionalAppendRequest({ idempotencyKey: LAB_IDEMPOTENCY_KEY_2 }),
    );
    expect(first).toMatchObject({ status: "accepted", replay: "http" });
    expect(httpReplay).toMatchObject({ status: "accepted", replay: "http" });
    expect(envelopeReplay).toMatchObject({ status: "accepted", replay: "envelope" });
    if (
      first.status !== "accepted" ||
      httpReplay.status !== "accepted" ||
      envelopeReplay.status !== "accepted"
    ) {
      throw new Error("replays were not accepted");
    }
    expect(JSON.stringify(httpReplay.receipt)).toBe(JSON.stringify(first.receipt));
    expect(JSON.stringify(envelopeReplay.receipt)).toBe(
      JSON.stringify(first.receipt),
    );
  });

  it("conflicts on idempotency reuse with a different body", async () => {
    const conflict = await serviceWith().appendApplicationEnvelope(
      fictionalAppendRequest({
        envelopeId: LAB_ENVELOPE_ID_2,
        ciphertextText: "conflicting exact HTTP body",
      }),
    );
    expect(conflict).toEqual({
      status: "conflict",
      reasonCode: "idempotency-conflict",
    });
  });

  it("linearizes concurrent distinct appends onto consecutive positions", async () => {
    const results = await Promise.all([
      serviceWith().appendApplicationEnvelope(
        fictionalAppendRequest({
          envelopeId: "615609f1-9662-49f6-9cda-9ef319abe51d",
          idempotencyKey: "0198a5db-4c58-7e31-bbf1-0fd4c09e4acf",
          ciphertextText: "first concurrent postgres application",
        }),
      ),
      serviceWith().appendApplicationEnvelope(
        fictionalAppendRequest({
          envelopeId: "625609f1-9662-49f6-9cda-9ef319abe51d",
          idempotencyKey: "0198a5dc-4c58-7e31-bbf1-0fd4c09e4acf",
          ciphertextText: "second concurrent postgres application",
        }),
      ),
    ]);
    expect(results.map(({ status }) => status)).toEqual(["accepted", "accepted"]);
    const positions = results
      .map((result) => (result.status === "accepted" ? result.receipt.position : ""))
      .sort();
    expect(positions).toEqual(["3", "4"]);
    const rows = await sql`
      SELECT position FROM envelopes
      WHERE conversation_id = ${LAB_CONVERSATION_ID} ORDER BY position`;
    expect(rows.map((row) => String(row.position))).toEqual(["2", "3", "4"]);
  });

  it("binds ready attachments to the accepted envelope and rejects reuse", async () => {
    const attachmentId = "d5e83107-9bf8-4b42-a095-c3b64028e4aa";
    const withAttachment = await serviceWith().appendApplicationEnvelope(
      fictionalAppendRequest({
        envelopeId: "675609f1-9662-49f6-9cda-9ef319abe51d",
        idempotencyKey: "0198a5e1-4c58-7e31-bbf1-0fd4c09e4acf",
        ciphertextText: "postgres application with attachment",
        attachmentIds: [attachmentId],
      }),
    );
    expect(withAttachment).toMatchObject({ status: "accepted" });
    if (withAttachment.status !== "accepted") {
      throw new Error("attachment append was not accepted");
    }
    const [attachmentRow] = await sql`
      SELECT state, bound_envelope_position FROM attachments
      WHERE attachment_id = ${attachmentId}`;
    expect(attachmentRow.state).toBe("bound");
    expect(String(attachmentRow.bound_envelope_position)).toBe(
      withAttachment.receipt.position,
    );
    const [joinRow] = await sql`
      SELECT count(*) AS links FROM envelope_attachments
      WHERE attachment_id = ${attachmentId}`;
    expect(String(joinRow.links)).toBe("1");

    const reuse = await serviceWith().appendApplicationEnvelope(
      fictionalAppendRequest({
        envelopeId: "685609f1-9662-49f6-9cda-9ef319abe51d",
        idempotencyKey: "0198a5e2-4c58-7e31-bbf1-0fd4c09e4acf",
        ciphertextText: "postgres application reusing a bound attachment",
        attachmentIds: [attachmentId],
      }),
    );
    expect(reuse).toEqual({
      status: "rejected",
      reasonCode: "attachment-invalid",
    });
  });

  it("retires an expired stranded pending and reuses its fenced position", async () => {
    let strand = true;
    const strandingService = serviceWith({
      checkpointSigner: {
        signExact: async (request) => {
          if (strand) {
            strand = false;
            return { status: "unavailable", reasonCode: "dependency-unavailable" };
          }
          return buildPorts().checkpointSigner.signExact(request);
        },
        resolveOrCancelIfUnsigned: (request) =>
          buildPorts().checkpointSigner.resolveOrCancelIfUnsigned(request),
      },
    });
    const stranded = await strandingService.appendApplicationEnvelope(
      fictionalAppendRequest({
        envelopeId: "635609f1-9662-49f6-9cda-9ef319abe51d",
        idempotencyKey: "0198a5dd-4c58-7e31-bbf1-0fd4c09e4acf",
        ciphertextText: "stranded postgres application",
      }),
    );
    expect(stranded).toEqual({
      status: "unavailable",
      reasonCode: "dependency-unavailable",
    });
    const [pendingCount] = await sql`
      SELECT count(*) AS pendings FROM application_append_pendings
      WHERE conversation_id = ${LAB_CONVERSATION_ID}`;
    expect(String(pendingCount.pendings)).toBe("1");

    now = parseRfc3339Millis("2026-08-14T16:22:00.000Z");
    await setDeliveryLabClock(sql, now);
    const drained = await serviceWith().appendApplicationEnvelope(
      fictionalAppendRequest({
        envelopeId: "645609f1-9662-49f6-9cda-9ef319abe51d",
        idempotencyKey: "0198a5de-4c58-7e31-bbf1-0fd4c09e4acf",
        ciphertextText: "post-retirement postgres application",
      }),
    );
    expect(drained).toMatchObject({
      status: "accepted",
      receipt: { position: "6" },
    });
    const [tombstones] = await sql`
      SELECT count(*) AS retirements FROM application_append_retirements
      WHERE conversation_id = ${LAB_CONVERSATION_ID}`;
    expect(String(tombstones.retirements)).toBe("1");
    const [pendingAfter] = await sql`
      SELECT count(*) AS pendings FROM application_append_pendings
      WHERE conversation_id = ${LAB_CONVERSATION_ID}`;
    expect(String(pendingAfter.pendings)).toBe("0");
  });

  it("gates retirement on database-authoritative time, not the application clock", async () => {
    let strand = true;
    const strandingService = serviceWith({
      checkpointSigner: {
        signExact: async (request) => {
          if (strand) {
            strand = false;
            return { status: "unavailable", reasonCode: "dependency-unavailable" };
          }
          return buildPorts().checkpointSigner.signExact(request);
        },
        resolveOrCancelIfUnsigned: (request) =>
          buildPorts().checkpointSigner.resolveOrCancelIfUnsigned(request),
      },
    });
    const stranded = await strandingService.appendApplicationEnvelope(
      fictionalAppendRequest({
        envelopeId: "695609f1-9662-49f6-9cda-9ef319abe51d",
        idempotencyKey: "0198a5e3-4c58-7e31-bbf1-0fd4c09e4acf",
        ciphertextText: "clock-gate stranded application",
      }),
    );
    expect(stranded).toEqual({
      status: "unavailable",
      reasonCode: "dependency-unavailable",
    });
    const [retirementsBefore] = await sql`
      SELECT count(*) AS retirements FROM application_append_retirements
      WHERE conversation_id = ${LAB_CONVERSATION_ID}`;

    // Only the application clock advances past the pending's expiry; the
    // database-authoritative clock still reads the earlier instant, so the
    // store must refuse to retire the live fenced pending.
    now = parseRfc3339Millis("2026-08-14T16:23:00.000Z");
    const skewedAttempt = await serviceWith().appendApplicationEnvelope(
      fictionalAppendRequest({
        envelopeId: "6a5609f1-9662-49f6-9cda-9ef319abe51d",
        idempotencyKey: "0198a5e4-4c58-7e31-bbf1-0fd4c09e4acf",
        ciphertextText: "skewed-clock retirement attempt",
      }),
    );
    expect(skewedAttempt.status).toBe("unavailable");
    const [pendingHeld] = await sql`
      SELECT count(*) AS pendings FROM application_append_pendings
      WHERE conversation_id = ${LAB_CONVERSATION_ID}`;
    expect(String(pendingHeld.pendings)).toBe("1");
    const [retirementsHeld] = await sql`
      SELECT count(*) AS retirements FROM application_append_retirements
      WHERE conversation_id = ${LAB_CONVERSATION_ID}`;
    expect(String(retirementsHeld.retirements)).toBe(
      String(retirementsBefore.retirements),
    );

    // Advancing the database clock is what makes the same retirement legal.
    await setDeliveryLabClock(sql, now);
    const drained = await serviceWith().appendApplicationEnvelope(
      fictionalAppendRequest({
        envelopeId: "6a5609f1-9662-49f6-9cda-9ef319abe51d",
        idempotencyKey: "0198a5e4-4c58-7e31-bbf1-0fd4c09e4acf",
        ciphertextText: "skewed-clock retirement attempt",
      }),
    );
    expect(drained).toMatchObject({ status: "accepted" });
    const [pendingDrained] = await sql`
      SELECT count(*) AS pendings FROM application_append_pendings
      WHERE conversation_id = ${LAB_CONVERSATION_ID}`;
    expect(String(pendingDrained.pendings)).toBe("0");
    const [finalized] = await sql`
      SELECT finalized_at FROM application_append_acceptances
      WHERE conversation_id = ${LAB_CONVERSATION_ID}
        AND envelope_id = '6a5609f1-9662-49f6-9cda-9ef319abe51d'`;
    expect(new Date(finalized.finalized_at as Date).toISOString()).toBe(
      "2026-08-14T16:23:00.000Z",
    );
  });

  it("fences realms and quota scopes with relational constraints", async () => {
    await expect(
      sql`
        INSERT INTO application_append_acceptances (
          realm_id, conversation_id, envelope_id, position, intent_digest,
          admission_command_digest, semantic_identity_digest,
          acceptance_canonical, finalized_at
        ) VALUES (
          'wrong-realm', ${LAB_CONVERSATION_ID},
          '00000000-0000-4000-8000-0000dead0001', 999,
          ${Buffer.alloc(32, 0x01)}, ${Buffer.alloc(32, 0x02)},
          ${Buffer.alloc(32, 0x03)}, ${"{}"}::jsonb, delivery_db_now()
        )`,
    ).rejects.toThrow(/foreign key/);
    await expect(
      sql`
        INSERT INTO quota_counters (
          scope_type, scope_hash, quota_name, window_started_at,
          window_seconds, updated_at
        ) VALUES (
          'account', ${Buffer.alloc(32, 0x09)}, 'application-append',
          delivery_db_now(), 86400, delivery_db_now()
        )`,
    ).rejects.toThrow(/foreign key/);
    const snapshot = await store.loadSnapshot(
      parseConversationId(LAB_CONVERSATION_ID),
    );
    for (const binding of snapshot.quotaBindings) {
      const [scopeRow] = await sql`
        SELECT realm_id, subject_id FROM quota_scopes
        WHERE scope_type = ${binding.scope}
          AND scope_hash = ${Buffer.from(binding.scopeHash, "base64url")}`;
      expect(scopeRow.realm_id).toBe(snapshot.conversation.realmId);
      expect(String(scopeRow.subject_id).length).toBeGreaterThan(0);
    }
    const [conversationScopes] = await sql`
      SELECT realm_id, project_scope_id, tenant_scope_id FROM conversations
      WHERE conversation_id = ${LAB_CONVERSATION_ID}`;
    expect(conversationScopes.realm_id).toBe(snapshot.conversation.realmId);
    expect(conversationScopes.project_scope_id).toBe(
      snapshot.conversation.projectScopeId,
    );
    expect(conversationScopes.tenant_scope_id).toBe(
      snapshot.conversation.tenantScopeId,
    );
  });
});
