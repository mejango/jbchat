import { readFileSync, writeFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import postgres, { type Sql } from "postgres";
import {
  LAB_CONVERSATION_ID,
  fictionalAppendRequest,
  fictionalDeliveryLabSeed,
  fictionalDeliveryTrustContext,
} from "../delivery/fixtures.testing";
import { createFictionalDeliveryCryptoPorts } from "../delivery/fictionalCryptoPorts.testing";
import type { ProductionDeliveryPorts } from "../delivery/ports";
import process from "node:process";
import { createApplicationEnvelopeDeliveryService } from "../delivery/service";
import {
  parseConversationId,
  parseRfc3339Millis,
  parseSigningKeyId,
  type Rfc3339Millis,
} from "../delivery/valueObjects";
import { installDeliveryLabClock } from "./postgresDeliveryLab.testing";
import {
  createPostgresDeliveryAppendStore,
  type PostgresDeliveryAppendStore,
} from "./postgresDeliveryStore";

const DATABASE_URL = process.env.JBM_STORAGE_DATABASE_URL;
const PHASE = process.env.JBM_FAILOVER_DRILL_PHASE;
const STATE_PATH = process.env.JBM_FAILOVER_DRILL_STATE;
const describeDrill =
  DATABASE_URL && PHASE && STATE_PATH ? describe : describe.skip;

const PRIMARY_ENVELOPE_ID = "6d5609f1-9662-49f6-9cda-9ef319abe51d";
const PRIMARY_IDEMPOTENCY_KEY = "0198a5e7-4c58-7e31-bbf1-0fd4c09e4acf";
const PROMOTED_ENVELOPE_ID = "6e5609f1-9662-49f6-9cda-9ef319abe51d";
const PROMOTED_IDEMPOTENCY_KEY = "0198a5e8-4c58-7e31-bbf1-0fd4c09e4acf";
const PREPARE_NOW = "2026-08-14T16:23:40.000Z";
const VERIFY_NOW = "2026-08-14T16:23:50.000Z";

interface FailoverDrillState {
  readonly primaryReceipt: unknown;
  readonly primaryPosition: string;
}

describeDrill(`failover drill (${PHASE} phase)`, () => {
  const seed = fictionalDeliveryLabSeed();
  let sql: Sql;
  let store: PostgresDeliveryAppendStore;
  const now: Rfc3339Millis = parseRfc3339Millis(
    PHASE === "prepare" ? PREPARE_NOW : VERIFY_NOW,
  );

  const buildPorts = (): ProductionDeliveryPorts => {
    const crypto = createFictionalDeliveryCryptoPorts({
      now: () => now,
      snapshot: () =>
        store.loadSnapshot(parseConversationId(LAB_CONVERSATION_ID)),
      signingKeyId: parseSigningKeyId(seed.signingKeyId),
      signingKeyValidFrom: parseRfc3339Millis(seed.signingKeyValidFrom),
      signingKeyValidUntil: parseRfc3339Millis(seed.signingKeyValidUntil),
    });
    const unavailablePort = {
      verify: () =>
        Promise.resolve({ status: "unavailable", reasonCode: "not-configured" }),
    };
    return {
      mlsWireInspector: crypto.mlsWireInspector,
      mlsCommitProjectionVerifier: unavailablePort,
      mlsExternalProposalVerifier: unavailablePort,
      policyHeadProofVerifier: crypto.policyHeadProofVerifier,
      conversationPolicyReplayVerifier: unavailablePort,
      checkpointSigner: crypto.checkpointSigner,
      signerFenceEvidenceVerifier: crypto.signerFenceEvidenceVerifier,
      checkpointSignatureVerifier: crypto.checkpointSignatureVerifier,
      conversationPageProofVerifier: unavailablePort,
      conversationLogHeadProofVerifier: unavailablePort,
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
    };
  };

  const service = () =>
    createApplicationEnvelopeDeliveryService(
      buildPorts(),
      fictionalDeliveryTrustContext(),
    );

  beforeAll(async () => {
    sql = postgres(DATABASE_URL!, { max: 4, onnotice: () => {} });
    store = createPostgresDeliveryAppendStore({ sql, now: () => now });
    await installDeliveryLabClock(sql, now);
  });

  afterAll(async () => {
    await sql?.end({ timeout: 5 });
  });

  if (PHASE === "prepare") {
    it("commits an append on the primary for the standby to replicate", async () => {
      const accepted = await service().appendApplicationEnvelope(
        fictionalAppendRequest({
          envelopeId: PRIMARY_ENVELOPE_ID,
          idempotencyKey: PRIMARY_IDEMPOTENCY_KEY,
          ciphertextText: "pre-failover primary application",
        }),
      );
      expect(accepted).toMatchObject({ status: "accepted" });
      if (accepted.status !== "accepted") throw new Error("append refused");
      const state: FailoverDrillState = {
        primaryReceipt: accepted.receipt,
        primaryPosition: String(
          (accepted.receipt as { position: string }).position,
        ),
      };
      writeFileSync(STATE_PATH!, JSON.stringify(state));
    });
    return;
  }

  const state = (): FailoverDrillState =>
    JSON.parse(readFileSync(STATE_PATH!, "utf8")) as FailoverDrillState;

  it("replays the pre-failover receipt identically on the promoted standby", async () => {
    const replay = await service().appendApplicationEnvelope(
      fictionalAppendRequest({
        envelopeId: PRIMARY_ENVELOPE_ID,
        idempotencyKey: PRIMARY_IDEMPOTENCY_KEY,
        ciphertextText: "pre-failover primary application",
      }),
    );
    expect(replay).toMatchObject({ status: "accepted", replay: "http" });
    if (replay.status !== "accepted") throw new Error("replay refused");
    expect(JSON.stringify(replay.receipt)).toBe(
      JSON.stringify(state().primaryReceipt),
    );
  });

  it("accepts a fresh append on the promoted standby with chain continuity", async () => {
    const accepted = await service().appendApplicationEnvelope(
      fictionalAppendRequest({
        envelopeId: PROMOTED_ENVELOPE_ID,
        idempotencyKey: PROMOTED_IDEMPOTENCY_KEY,
        ciphertextText: "post-failover promoted application",
      }),
    );
    expect(accepted).toMatchObject({ status: "accepted" });
    if (accepted.status !== "accepted") throw new Error("append refused");
    expect(
      BigInt((accepted.receipt as { position: string }).position),
    ).toBe(BigInt(state().primaryPosition) + 1n);
    const [conversationRow] = await sql`
      SELECT last_position FROM conversations
      WHERE conversation_id = ${LAB_CONVERSATION_ID}`;
    expect(String(conversationRow.last_position)).toBe(
      (accepted.receipt as { position: string }).position,
    );
  });
});
