# ADR 0002 — Witness design (ENG-003 design half)

Status: ratified 2026-08-18 by project-owner delegation, closing the
"design approved before G2" half of ENG-003. The "independently operated
witness deployed and evidenced before G3" half remains open by design and
is NOT closed by this document or by any self-operated deployment.

## Context

Three witnessed logs exist with three trust surfaces: the entitlement
policy log (`policy_log_checkpoints`, whose rows cannot exist unwitnessed),
the per-conversation delivery log (`log_witness_receipts`, asynchronous,
per-append), and the Key Transparency device directory
(`directory_checkpoints`). The ratified specs pin the receipt shapes, the
continuity rules clients enforce (monotone tree size, monotone witness
time, same-size-same-root), Ed25519 with 64-byte signatures for delivery
receipts, and the outage semantics — but deliberately leave open the
accumulator, the witness signing preimage, the freshness number, and the
backlog bound. Those four openings are the design decision.

## Decision

1. **One witness service, three namespaces.** A single isolated service
   operates three append-only logs named `delivery`, `policy`, and
   `directory`. Namespaces share nothing but code: separate trees,
   separate checkpoint sequences, one signing key valid across namespaces
   (the namespace is bound inside every signed preimage).
2. **Accumulator: RFC 6962.** Leaf hash `SHA-256(0x00 || leaf)`, interior
   node `SHA-256(0x01 || left || right)`, Merkle tree head over the leaf
   sequence, RFC 6962 section 2.1 inclusion and consistency proofs. The
   witness leaf payload for each namespace is the length-prefixed
   canonical tuple defined in item 3's preimage table.
3. **Witness signing preimage.** A checkpoint signature is plain Ed25519
   (no prehash variant) over:

   ```text
   SHA-256(
     ASCII("jb-msg-witness-checkpoint/v1") ||
     LP(namespace) || LP(checkpointId) || LP(treeSizeDecimalASCII) ||
     LP(rootHash[32]) || LP(witnessKeyId) || LP(witnessedAtRfc3339Millis)
   )
   ```

   with `LP(v) = u32be(len(v)) || v`, mirroring the delivery checkpoint
   digest convention. Checkpoint IDs are UUIDv4. Leaf payloads:
   - `delivery`: `LP(conversationId) || LP(positionDecimal) ||
     LP(previousHeadHash[32]) || LP(headHash[32]) || LP(signingKeyId)`
   - `policy`: `LP(policyLogCheckpointId) || LP(treeSizeDecimal) ||
     LP(rootHash[32]) || LP(previousCheckpointIdOrEmpty) || LP(signerKeyId)`
   - `directory`: `LP(directoryCheckpointId) || LP(treeSizeDecimal) ||
     LP(rootHash[32]) || LP(previousCheckpointIdOrEmpty) || LP(signerKeyId)`
4. **Extension verification is the witness's whole job.** Before
   cosigning, the witness independently verifies the submitter's Ed25519
   signature over the submitted checkpoint digest against the registered
   key valid at the checkpoint's receipt time, and enforces continuity:
   for `delivery`, exactly-next position per conversation with
   `previousHeadHash` equal to its own stored head, and never a second
   distinct head at a witnessed position; for `policy` and `directory`,
   exact extension of the previous checkpoint. A violation returns a
   typed equivocation rejection carrying both conflicting facts — the
   SEV-0 trigger — and cosigns nothing.
5. **Witness freshness limit: 300 seconds**, published in the trust
   manifest. Sensitive sends fail closed when the newest applicable
   receipt is older; this binds the limit to the existing five-minute
   family (policy-head validity, freeze SLO, split-view alert SLO)
   rather than minting a new constant.
6. **Bounded backlog: 10,000 queued delivery heads per realm.** Below the
   bound, ordinary appends continue with receipts pending; at the bound,
   the delivery service degrades exactly as the outage table specifies.
   The bound is measured in the lab, not aspirational.
7. **Isolation and custody.** The witness runs as a separate Railway
   project with its own PostgreSQL, its own checksummed migration set and
   ledger, its own signing key (never the delivery, policy-head, or
   external-sender key material), and no write credential against the
   Delivery database — and vice versa. The delivery side stores only
   returned receipts. Remote witness calls never occur inside database
   transactions; the policy accept-before-serve call happens before the
   issuance transaction commits its served state.
8. **Transfer is overlap, never key handover.** A successor operator
   generates a fresh `witnessKeyId`; the receipt tables' composite keys
   already admit concurrent witnesses. The transfer sequence is: successor
   key enters the trust manifest; successor cosigns a checkpoint at tree
   size >= the incumbent's last published size with the same root and
   publishes a consistency proof back to the incumbent's last checkpoint;
   both keys cosign during the overlap window; the incumbent key retires
   from the manifest only after the client-anchor lifetime passes. A
   quarterly witness-transfer drill joins the existing split-view drills.
9. **Directory receipts become attributable.** `directory_checkpoints`
   gains `witness_key_id` with a paired-nullability constraint, so a
   receipt from one operator is distinguishable from another's — a
   precondition for item 8.
10. **Read surface.** `GET /v1/transparency/checkpoints/{checkpointId}`,
    `GET /v1/transparency/checkpoints/latest?namespace=`, and
    `GET /v1/transparency/proofs/consistency?namespace=&from=&to=`, all
    independently cacheable, plus a gossip ingest
    (`POST /v1/witness/gossip`) accepting
    `(conversationId, position, headHash, witnessCheckpointId)` tuples
    and alerting on any tuple inconsistent with the tree within the
    five-minute SLO.

## Consequences

- The lab can now witness policy-head issuance honestly (in-process core,
  fictional key), flipping `witness_state` from `missing` to a genuinely
  computed `verified` in lab evidence — while production heads remain
  unwitnessed until the service is deployed.
- `witnessTrustMode` stays the single frozen literal `continuity`; a
  quorum-of-witnesses model would be a successor profile.
- The succinct coalesced policy-transition range proof can now be
  specified against a concrete accumulator (RFC 6962 consistency proofs)
  in a later ADR.

## Reopening conditions

Amend by successor ADR if the auditor rejects RFC 6962 for the directory
map use-case (a KT-map construction may replace the directory namespace),
or if a quorum witness model is adopted for a later profile version.
