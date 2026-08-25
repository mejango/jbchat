import { Buffer } from "node:buffer";
import type { Sql } from "postgres";

export interface ConversationPageReadInput {
  readonly conversationId: string;
  readonly installationId: string;
  /** Authenticated positive cursor anchor, or null for the first page. */
  readonly afterPosition: string | null;
  readonly maxEvents: number;
  readonly maxSerializedBytes: number;
}

export interface ConversationPageEvent {
  readonly position: string;
  readonly envelopeId: string;
  readonly envelopeClass: string;
  readonly contentType: string;
  readonly envelopeBytes: string;
  readonly headHash: string;
  readonly receivedAt: string;
}

export interface ConversationPageSnapshot {
  readonly position: string;
  readonly generation: string;
  readonly releaseProfileId: string;
  readonly etag: string;
  readonly epoch: string;
  readonly rosterVersion: string;
  readonly confirmedTranscriptHash: string;
  readonly policyHeadId: string;
  readonly policyHeadSequence: string;
  readonly policyHeadHash: string;
  readonly policyDeliveryLogPosition: string;
}

export type ConversationPageReadResult =
  | {
      readonly status: "page";
      readonly events: readonly ConversationPageEvent[];
      readonly nextPosition: string;
      readonly hasMore: boolean;
      readonly snapshot: ConversationPageSnapshot;
    }
  | {
      readonly status: "history-gone";
      readonly nextRequiredPosition: string;
    }
  | { readonly status: "not-a-member" };

/**
 * Position-ordered authoritative conversation page scan over relational
 * rows: the membership window scopes visibility (a cursorless first page
 * starts after joined_position - 1 and a removed member is capped exactly
 * at removed_position), bytes are accounted before appending each item and
 * an item is never split, and every page end - including a later empty page
 * at an authenticated positive anchor - is joined to the immutable exact
 * historical projection stored for that position. A missing required
 * projection returns typed history-gone rather than substituting current
 * state. This is the storage producer only: the client kernel's five
 * release-pinned verifier adapters, the witnessed log-head route, and the
 * production sync route remain unconfigured by design, so nothing this
 * reader emits is treated as verified evidence.
 */
export function createConversationPageReader(context: {
  readonly sql: Sql;
}): {
  readPage: (
    input: ConversationPageReadInput,
  ) => Promise<ConversationPageReadResult>;
} {
  const { sql } = context;

  const snapshotAt = async (
    conversationId: string,
    position: string,
  ): Promise<ConversationPageSnapshot | null> => {
    const rows = await sql`
      SELECT position, generation, release_profile_id, etag, epoch,
             roster_version, confirmed_transcript_hash, policy_head_id,
             policy_head_sequence, policy_head_hash,
             policy_delivery_log_position
      FROM conversation_page_end_projections
      WHERE conversation_id = ${conversationId} AND position = ${position}`;
    if (rows.length !== 1) return null;
    const row = rows[0];
    return Object.freeze({
      position: String(row.position),
      generation: String(row.generation),
      releaseProfileId: String(row.release_profile_id),
      etag: String(row.etag),
      epoch: String(row.epoch),
      rosterVersion: String(row.roster_version),
      confirmedTranscriptHash: Buffer.from(
        row.confirmed_transcript_hash as Uint8Array,
      ).toString("base64url"),
      policyHeadId: String(row.policy_head_id),
      policyHeadSequence: String(row.policy_head_sequence),
      policyHeadHash: Buffer.from(
        row.policy_head_hash as Uint8Array,
      ).toString("base64url"),
      policyDeliveryLogPosition: String(row.policy_delivery_log_position),
    });
  };

  return Object.freeze({
    async readPage(
      input: ConversationPageReadInput,
    ): Promise<ConversationPageReadResult> {
      const memberships = await sql`
        SELECT joined_position, removed_position FROM memberships
        WHERE conversation_id = ${input.conversationId}
          AND installation_id = ${input.installationId}`;
      if (memberships.length !== 1) {
        return Object.freeze({ status: "not-a-member" });
      }
      const membership = memberships[0];
      const joined = BigInt(String(membership.joined_position));
      const removedCap =
        membership.removed_position === null
          ? null
          : BigInt(String(membership.removed_position));
      const anchor =
        input.afterPosition === null ? joined - 1n : BigInt(input.afterPosition);

      const ceiling = removedCap === null ? 9223372036854775807n : removedCap;
      const candidates = await sql`
        SELECT position, envelope_id, envelope_class, content_type,
               octet_length(envelope_bytes) AS envelope_byte_length, head_hash,
               received_at
        FROM envelopes
        WHERE conversation_id = ${input.conversationId}
          AND position > ${String(anchor)}
          AND position <= ${String(ceiling)}
        ORDER BY position
        LIMIT ${input.maxEvents + 1}`;

      const events: ConversationPageEvent[] = [];
      let accountedBytes = 0;
      let hasMore = candidates.length > input.maxEvents;
      for (const row of candidates.slice(0, input.maxEvents)) {
        const byteLength = Number(row.envelope_byte_length);
        if (
          events.length > 0 &&
          accountedBytes + byteLength > input.maxSerializedBytes
        ) {
          hasMore = true;
          break;
        }
        accountedBytes += byteLength;
        events.push(
          Object.freeze({
            position: String(row.position),
            envelopeId: String(row.envelope_id),
            envelopeClass: String(row.envelope_class),
            contentType: String(row.content_type),
            envelopeBytes: String(byteLength),
            headHash: Buffer.from(row.head_hash as Uint8Array).toString(
              "base64url",
            ),
            receivedAt: new Date(row.received_at as Date).toISOString(),
          }),
        );
      }

      if (events.length === 0) {
        // An empty page is valid only after an authenticated positive
        // anchor and must replay the exact stored historical projection.
        if (input.afterPosition === null) {
          return Object.freeze({
            status: "history-gone",
            nextRequiredPosition: String(joined),
          });
        }
        const snapshot = await snapshotAt(
          input.conversationId,
          input.afterPosition,
        );
        if (!snapshot) {
          return Object.freeze({
            status: "history-gone",
            nextRequiredPosition: String(joined),
          });
        }
        return Object.freeze({
          status: "page",
          events: Object.freeze([]),
          nextPosition: input.afterPosition,
          hasMore: false,
          snapshot,
        });
      }

      const pageEnd = events[events.length - 1].position;
      const snapshot = await snapshotAt(input.conversationId, pageEnd);
      if (!snapshot) {
        return Object.freeze({
          status: "history-gone",
          nextRequiredPosition: String(joined),
        });
      }
      return Object.freeze({
        status: "page",
        events: Object.freeze(events),
        nextPosition: pageEnd,
        hasMore,
        snapshot,
      });
    },
  });
}
