# Production messaging service API

Status: implementation specification for API version 1. This is not the contract of the
development SQLite service under `/api/dev/messaging`.

## 1. Scope and invariants

The production service has two planes:

- The control plane authenticates wallets and installations, evaluates eligibility, authorizes
  membership changes, advances roster state with compare-and-swap (CAS), and enforces policy.
- The delivery plane durably orders and distributes opaque MLS artifacts, encrypted application
  messages, encrypted attachment objects, and content-free push wakeups.

The service MUST NOT possess an MLS group secret, attachment content key, decrypted message, shipping
address, delivery note, or tracking number. It necessarily observes metadata described in
[Metadata visible to the service](#17-metadata-visible-to-the-service).

Clients MUST authenticate the sender credential and enforce decrypted event-kind authorization after
opening an MLS application message. Server authorization proves that an installation could append to the
conversation; it does not prove what the opaque application message contains.

WhatsApp, Telegram, email, or SMS full-text connectors are separate relay conversations and plaintext
trust domains. They MUST NOT join, inherit, or backfill an existing native MLS conversation. A relay
lists its gateway, business, provider, and other plaintext-capable endpoints before opt-in and is
labelled `relay`, not native E2EE. A notification-only connector may send a generic deep link without
receiving message plaintext.

The words MUST, MUST NOT, SHOULD, and MAY are normative.

## 2. Protocol conventions

### 2.1 Transport and versioning

- The base path is `/v1`. Version 1 is served only over TLS 1.3; TLS 1.2 MAY remain enabled during a
  measured compatibility period. Plain HTTP MUST be rejected before application processing.
- JSON requests use `Content-Type: application/vnd.juicebox.messaging.v1+json`.
- JSON responses use that media type, except errors which use `application/problem+json`.
- Binary values in JSON are unpadded canonical base64url. The server rejects padding, whitespace,
  non-canonical encodings, and values whose re-encoding differs.
- Timestamps are UTC RFC 3339 strings with millisecond precision. Servers generate authoritative
  timestamps.
- Service-visible core object IDs are lowercase canonical UUIDv4: account, wallet-link, installation,
  authentication-session record, credential, policy, policy-head, relationship, relationship-scope,
  conversation, campaign, attachment, and archive. A session record ID is metadata, never its bearer
  capability.
  Clients independently generate UUIDv4 application `caseId`/`eventId` and transport `envelopeId`.
  `caseId` and `eventId` exist only inside MLS application plaintext and are never server records,
  routes, lookups, indexes, logs, or telemetry; the delivery service sees only `envelopeId`. UUIDv4 supplies 122 random bits; IDs
  are non-secret and never authority. Operational request, enrollment attempt, challenge, embed-context/
  redemption, plan, intent, proposal, signer-migration, and other job IDs use lowercase canonical
  UUIDv7; `signerMigrationId` is the UUIDv7
  identifier of that migration job. Bearer tokens, claim/cursor/upload/download handles,
  nonces, and other secret capabilities use at least 256 CSPRNG bits (encoded canonical base64url) and
  never reuse an object ID. Any durable domain-record ID not explicitly classified as operational is
  UUIDv4.
- Integer counters that may exceed JavaScript's safe integer range are decimal strings with grammar
  `0|[1-9][0-9]*`.
- Unknown request fields are rejected with `400 unknown_field`. Clients MUST ignore unknown response
  fields within the same major version.
- Responses containing authentication, roster, mailbox, envelope, attachment, or eligibility data
  include `Cache-Control: no-store, private`, `Pragma: no-cache`, and `Vary: Authorization, DPoP`.
- The server emits `X-Request-Id`. A caller MAY submit a UUIDv7 `X-Request-Id`; invalid or repeated
values are replaced. Request IDs are not authorization or idempotency keys.

MLS and service wire counters are unsigned 64-bit in the protocol, but version 1 accepts and stores only
`0..9223372036854775807` (`2^63-1`) so PostgreSQL `bigint` is exact. A larger, negative, signed,
fractional, exponent, leading-zero, or JavaScript-number value is rejected as
`400 counter_out_of_range`; it is never rounded, clamped, wrapped, or coerced. A conversation must
migrate to a fresh generation before its next epoch, roster, position, policy-head, or generation-local
counter would exceed the cap. If safe migration cannot complete, the generation becomes `suspended`
and the mutation fails closed. Mailbox/cursor namespaces likewise fail closed rather than wrap. EVM
`uint256` project IDs, token amounts, and evidence values are separate canonical decimal strings backed
by `numeric(78,0)` and are not truncated to the service-counter cap.

Version 1 initially links EVM wallets. `accountId` is a service-scoped opaque UUIDv4 and MUST NOT encode a
wallet. `walletRef` is a CAIP-10 value such as `eip155:8453:0x...`; the same hexadecimal address on two
chains is not automatically the same authorization scope. `installationId` is a fresh UUIDv4 for one
app installation and changes on reinstall or recovery.

`projectRef` is a canonical object, never a delimiter-joined string:

```json
{
  "protocol": "juicebox",
  "protocolVersion": "v6",
  "chainId": "eip155:8453",
  "projectsContract": "0x...checksummed",
  "projectId": "42"
}
```

The canonical project hash domain-separates all five length-prefixed fields. An omnichain project has a
separate opaque service ID mapped to a verified set of these references; an indexer grouping is never
an authorization key.

`GET /v1/capabilities` returns the signed deployment manifest: API major/minor, minimum client minor,
selected MLS implementation build, fixed RFC 9420 cipher suite `0x0001`
(`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`), credential profile, application schema versions,
enabled features, `lastResortKeyPackages: false`, KeyPackage inventory thresholds, community
account/installation caps, every byte/rate/retention ceiling, manifest
issue/expiry, signing key ID, and signature. The response is public and cacheable for at most 60
seconds. Clients verify it against the pinned deployment-manifest root before creating KeyPackages or
sealing; an unknown, expired, downgraded, or inconsistent manifest fails closed. The endpoint describes
an already reviewed deployment—it is not client-driven negotiation.

The manifest's `deliveryLimits` object has exactly these canonical-decimal-string fields, in this
digest order: `applicationCiphertextDecodedMaxBytes`, `externalProposalDecodedMaxBytes`,
`mlsCommitDecodedMaxBytes`, `welcomeDecodedMaxBytes`, `pageDecodedArtifactsMaxBytes`,
`pageSerializedResponseMaxBytes`, `conversationEventsMaxPerPage`, `mailboxEntriesMaxPerPage`,
`conversationRecipientInstallationsMax`, `cursorMaxCharacters`, and `attachmentsMaxPerEnvelope`. Its
binding is exactly:

```text
SHA-256(
  ASCII("jb-msg-delivery-limits/v1") ||
  canonical_length_prefixed(
    ASCII(key1), ASCII(canonicalDecimalValue1), ...,
    ASCII(key11), ASCII(canonicalDecimalValue11)
  )
)
```

Here `canonical_length_prefixed` applies `u32be(byteLength) || bytes` to every key and value in that
fixed order. Page byte/count limits and `conversationRecipientInstallationsMax` are positive,
`conversationRecipientInstallationsMax` is at most 2,500, and `cursorMaxCharacters` is at least 43. A zero
artifact ceiling disables new admission for that artifact class. A zero attachment-reference ceiling
allows an otherwise valid application with an empty attachment list and rejects every attachment
reference; it does not disable the application class. Each conversation generation immutably stores
its `releaseProfileId`, complete parsed `deliveryLimits`, `deliveryLimitsDigest`, and
`releaseTrustRootDigest`. Profiles are archived and never edited in place. Lowering or zero-disabling a
limit creates a new profile and any policy-required fresh-generation migration; historical reads and
exact retries use the generation's archived profile, never the deployment's newest profile.

`GET /v1/release-profiles/{releaseProfileId}` returns the immutable archived profile needed to verify a
plan, conversation generation, historical page, or replay. The response contains the exact canonical
full `deliveryLimits`, its digest, release trust-root digest, originating signed deployment-manifest
identity and signature, and the bounded signing-key history/proof needed to authenticate that manifest
under the client's pinned deployment root. The client verifies the profile ID, manifest signature and
trust path, recomputed limits digest, and every generation binding before using it. A profile is public,
content-addressed by those authenticated bindings, cacheable as immutable, and never served with
different bytes under the same ID. It remains available while any plan, generation, envelope, pending
or accepted replay record, retained page, export, or backup can reference it; purge occurs only after
all such references and their backup-erasure windows end. A missing or unverifiable required profile
fails closed as `503 temporarily_unavailable`, never as permission to use the current manifest.

### 2.2 Errors

Errors have this shape:

```json
{
  "type": "https://messaging.juicebox.money/problems/conversation-state-changed",
  "title": "Conversation state changed",
  "status": 412,
  "code": "conversation_state_changed",
  "detail": "Refresh the roster and seal again.",
  "requestId": "0195e5c1-a7d0-7d6a-a521-256e257df384",
  "retryable": true,
  "currentState": {
    "epoch": "19",
    "rosterVersion": "27",
    "etag": "\"e19-r27\""
  }
}
```

`detail` never contains request bodies, wallet signatures, tokens, ciphertext, attachment URLs, push
tokens, or upstream RPC responses. Expected codes are:

| Status | Codes | Meaning |
| --- | --- | --- |
| 400 | `invalid_request`, `unknown_field`, `invalid_cursor`, `counter_out_of_range` | Malformed, non-canonical, or outside the v1 counter cap. |
| 401 | `invalid_session`, `invalid_wallet_proof`, `invalid_possession_proof`, `invalid_dpop` | Authentication failed. |
| 403 | `not_eligible`, `forbidden_role`, `device_credential_inactive`, `installation_revoked`, `origin_denied` | Authenticated but unauthorized. |
| 404 | `not_found`, `context_invalid` | Missing/unauthorized resources and all invalid embed-context states intentionally collapse. |
| 409 | `idempotency_conflict`, `enrollment_terminal`, `membership_intent_conflict`, `key_package_taken`, `key_package_inventory_exhausted` | A uniqueness, workflow, or visible replenishment conflict. |
| 410 | `cursor_expired`, `history_gone`, `plan_expired`, `resource_expired` | A required retained artifact is unavailable or a safe restart/resync is required. |
| 412 | `conversation_state_changed` | CAS precondition failed. |
| 413 | `envelope_too_large`, `attachment_too_large` | Declared or uploaded ciphertext exceeds policy. |
| 415 | `unsupported_media_type` | Wrong API or envelope content type. |
| 429 | `rate_limited`, `quota_exceeded` | Retry after `Retry-After`; no write occurred. |
| 503 | `enrollment_verification_unavailable`, `eligibility_unavailable`, `tenant_not_configured`, `temporarily_unavailable` | Fail-closed authority, configuration, dependency, or overload response. |

### 2.3 Idempotency

Every POST, PUT, PATCH, and DELETE that can mutate durable state MUST include `Idempotency-Key`, a
UUIDv7 or at least 128 bits of base64url entropy. Exceptions are authentication challenges and safe
session introspection; “authentication challenge” here means a server-selected DPoP nonce response,
not device-enrollment challenge issuance. Authenticated native requests are scoped to
`(account_id, installation_id, HTTP method, route template, resource_id, key)`. Before a native session
exists, the server uses an explicit non-secret principal type plus purpose-separated 32-byte principal
HMAC: enrollment allocation binds registered client plus canonical wallet lookup; later enrollment
mutations bind the enrollment capability/ID; embed issuance binds tenant plus mTLS/OAuth issuer; embed
redemption binds tenant plus resolved context and exact channel. Raw wallet refs, enrollment/context
handles, origin strings, and channel values never enter an idempotency key/index/log. No two principal
types share a namespace.

For this section, `LP(value) = u32be(byteLength(value)) || value`; strings are their exact UTF-8 bytes.
The committed request digest is exactly:

```text
SHA-256(
  ASCII("jb-msg-idempotency-request/v1") ||
  LP(uppercase HTTP method) ||
  LP(exact route template) ||
  LP(canonical resource ID, or empty) ||
  LP(exact accepted media type) ||
  LP(exact If-Match field value, or empty) ||
  LP(raw request-body bytes)
)
```

Requests with a query string or `Content-Encoding` on a mutation route are rejected before this
commitment. Authorization, cookie, DPoP, origin, request ID, and other transport headers are excluded
from the digest because the separately stored principal scope authenticates them; no selected-header
set is implementation-defined. Consequently, changing JSON whitespace/key order, the media type,
`If-Match`, or any body byte under one key is a conflict even if parsing would produce an equivalent
object.

Before authorization-state or CAS checks that could have changed after a successful first request, the
server looks up the idempotency record:

1. It computes the exact domain-separated request digest above.
2. If no record exists, it processes the mutation in the same database transaction that inserts the
   idempotency record.
3. If a record with the same hash exists, it returns the original status, selected response headers,
   and response body with `Idempotency-Replayed: true`.
4. If the key exists with another hash, it returns `409 idempotency_conflict`.

Records live for seven days unless a route's stricter secret-retention contract applies. An encrypted
enrollment success/result body is purged within 15 minutes and embed idempotency/linkage within 24
hours; later reads expose only the terminal non-secret state and never mint replacement bearer/context
secrets. Retrying after record expiry is not safe; SDKs MUST generate a new key only for a new user
intent. Provider upload URLs and wallet challenges have their own shorter expiry.

Envelope-accepting routes additionally perform a durable secondary lookup by
`(conversationId, envelopeId)` before current-state checks. That record remains for at least as long as
the immutable envelope and is not removed when the ordinary idempotency record expires. Its semantic
identity includes the route conversation, authenticated sender, exact `If-Match`, and the complete
strictly parsed append body—including ordered attachment IDs, policy-head and expected-state bindings,
exact envelope bytes, and declared hash. An exact match returns the original immutable position/head/
receipt; any difference returns `409 idempotency_conflict`. A new idempotency key cannot turn an
accepted envelope ID into a second append or bypass this conflict.

The application-envelope route has a third durable replay state: an invisible pending append intent.
Its preflight order is the live HTTP-key record, the realm-scoped durable
`(conversationId, envelopeId)` accepted binding, then an exact pending intent, all before current
admission state or limits. An accepted match returns the original receipt. A pending exact match
resumes signing, independent verification, and finalization for the same reserved tuple; if that cannot
complete within the request's absolute deadline, the public result is `503 temporarily_unavailable`,
never an unsigned success or a public `pending` success. A nonmatching pending command conflicts or
retries only after the existing lane resolves. Only a true replay miss consults current admission
policy, quotas, and class/attachment limits. Exact historical replay uses the full archived admission
command/profile and remains valid when a later profile lowers or disables new admission.

A success for an envelope/proposal/Commit, Welcome, membership or active-generation change,
idempotency record, mailbox entry, or cursor acknowledgement is returned only after synchronous
in-region and fenced cross-region critical-ledger durability (RPO 0). A bound encrypted object also
requires its cross-region replication receipt. Quorum loss returns 503; a connection loss is an unknown
outcome and the caller resends the exact request/key. The at-most-five-minute asynchronous regional RPO
applies only to explicitly rebuildable caches/indexes/metrics/push hints, never accepted transcript or
authorization state.

## 3. Wallet and installation authentication

### 3.1 Installation keys

Each installation has two unrelated keys:

- `installationAuthKey`: profile `p256-es256-dpop.v1`, a non-exportable P-256 key used for DPoP and
  enrollment possession (`ES256`). Its strict public JWK has exactly `kty: EC`, `crv: P-256`, canonical
  `x`/`y`, `use: sig`, and `alg: ES256`. Its RFC 7638 SHA-256 JWK thumbprint is
  `installationAuthJkt` and the session confirmation value `jkt`.
- `mlsCredentialKey`: profile `mls-credential-ed25519-suite-0x0001.v1`, an Ed25519 signature key for
  cipher suite `0x0001` (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`). Its canonical public key and
  domain-separated 32-byte `credentialFingerprint` are visible to roster members.

Private keys remain in the platform key store. Browser implementations use non-exportable WebCrypto
keys when available and clearly label weaker fallback storage.

### 3.2 Allocate an enrollment attempt

Enrollment is a paired wallet-control and installation-key-possession ceremony, not generic sign-in.
`POST /v1/device-enrollments` accepts no caller-chosen installation or credential ID:

```json
{
  "walletRef": "eip155:1:0xAbC...123",
  "proofProfile": "siwe-erc4361-v1",
  "client": {
    "clientId": "juicebox-messaging-web",
    "origin": "https://chat.juicebox.money",
    "audience": "https://api.chat.juicebox.money/v1"
  },
  "purpose": "device-enrollment",
  "scope": {
    "kind": "wallet-challenge-scope.v1",
    "project": null,
    "action": "device-enrollment"
  },
  "installationKind": "native"
}
```

The only public wallet proof profiles are exactly `siwe-erc4361-v1` and
`eip712-device-enrollment-v1`. Legacy/internal discriminants such as `siwe-eip4361`, `eip712-v4`, or
`JuiceboxMessagingChallenge` are rejected on the wire, not treated as aliases or fallback graphs.

The server canonicalizes the CAIP-10 wallet reference and resolves or provisionally allocates the
opaque service account without revealing prior registration. It creates one UUIDv7 `enrollmentId` and
preallocates fresh random UUIDv4 `installationId` and `deviceCredentialId`. No supplied value can
replace them. It also creates a 256-bit `enrollmentResultHandle`, stores only its purpose-separated
HMAC, and returns the handle once in a no-store response with `issuedAt`, `expiresAt` (at most five
minutes), and state `allocated`. Subsequent enrollment calls put the handle only in
`Authorization: Enrollment <handle>`; it never appears in a URL, cookie, log, trace, or analytics event.

```json
{
  "enrollmentId": "0198a5d7-4c58-7e31-bbf1-0fd4c09e4acf",
  "installationId": "5ec2d18e-f082-48fa-8b01-55e43fed021c",
  "deviceCredentialId": "c3c82f16-bf3c-45e0-8518-ca1bf6ab3b66",
  "enrollmentResultHandle": "base64url-256-bit-handle",
  "state": "allocated",
  "issuedAt": "2026-08-14T16:20:00.000Z",
  "expiresAt": "2026-08-14T16:25:00.000Z"
}
```

The exact registered HTTPS `origin`, API `audience`, `clientId`, `purpose`, and full canonical `scope`
are independently stored and later signed. `scope.action` MUST equal `purpose`. Initial enrollment uses
`project: null`; recovery or a project-scoped high-risk action uses a separately registered purpose and
scope and cannot reuse this attempt. `installationKind` is `native`; relay gateways use the isolated
relay authority and never receive a native device credential. The persisted platform is derived from
the registered client ID/configuration, not a caller-controlled platform string. A top-level request
creates a `top_level` storage partition. Enrollment initiated from a live unauthenticated embed session
derives `embedded` plus the server-pinned tenant and exact parent origin from that session; the request
cannot supply them. It always preallocates a distinct installation/key pair for that
`(messaging origin, top-level site)` partition and cannot reuse or import the top-level installation.

### 3.3 Bind keys and issue paired challenges

After learning the preallocated IDs, the client generates its keys and one ordinary, single-use MLS
KeyPackage. `POST /v1/device-enrollments/{enrollmentId}/challenges` requires the enrollment capability,
idempotency, and this exact `DeviceKeyBinding`:

```json
{
  "installationId": "5ec2d18e-f082-48fa-8b01-55e43fed021c",
  "installationAuthKey": {
    "profile": "p256-es256-dpop.v1",
    "algorithm": "P-256",
    "publicJwk": {
      "kty": "EC",
      "crv": "P-256",
      "x": "base64url",
      "y": "base64url",
      "use": "sig",
      "alg": "ES256"
    },
    "jwkThumbprint": "base64url-32-bytes"
  },
  "mlsCredentialKey": {
    "profile": "mls-credential-ed25519-suite-0x0001.v1",
    "algorithm": "Ed25519",
    "ciphersuite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
    "publicKey": "base64url-32-bytes",
    "credentialFingerprint": "base64url-32-bytes",
    "initialKeyPackage": {
      "kind": "ordinary-mls-key-package.v1",
      "keyPackageRef": "base64url-32-bytes",
      "sha256": "base64url-32-bytes",
      "keyPackage": "base64url",
      "expiresAt": "2026-08-21T16:20:00.000Z"
    }
  }
}
```

The server recomputes the JWK thumbprint, MLS credential fingerprint, KeyPackage reference and hash;
validates the pinned suite, credential, init-key, expiry and ordinary-package profile; and rejects a
last-resort package. It preallocates both challenge IDs, persists the canonical full binding, then
constructs the wallet payload before the possession digest, and returns two server-owned records:

- a UUIDv7 wallet `challengeId`, exact SIWE bytes or exact EIP-712 type graph/value, canonical payload
  digest, alphanumeric server nonce with at least 128 bits of entropy, issue/not-before/expiry, and
  method-independent wallet binding; and
- a preallocated UUIDv7 `possessionChallengeId` and 32-byte `challengeDigest` for a
  `DevicePossessionChallenge`. Only after the exact wallet payload/digest exists, the server computes
  this digest over domain separator `jb-msg-device-possession/v1`, wallet challenge ID and payload
  digest, possession-challenge ID and fresh server nonce, plus the same enrollment/account/chain,
  preallocated installation/device-credential IDs, both public-key commitments, initial KeyPackage
  ref/hash, audience, client, origin, purpose, scope digest, protocol profiles, and time window. This
  one-way construction binds the two proofs without a circular digest.

For SIWE, domain, fixed authentication URI, version, chain, account, alphanumeric nonce, `challengeId`
as Request ID, exact statement `Authorize this wallet to enroll one Juicebox Messaging device.`, and
time fields are exact. The resources array has
exactly these 13 ordered entries: enrollment ID, service account ID, installation ID,
device-credential ID, encoded audience, client ID, scope digest, installation-auth JKT, MLS credential
fingerprint, KeyPackage ref, KeyPackage SHA-256, protocol-profile commitment, and
`possessionChallengeId`. Purpose equals the canonical scope action and is covered by the fixed
statement as well as the protocol-profile/scope commitments. Values are encoded by the published
`urn:juicebox:messaging:*:v1:` resource profile; the protocol-profile value is exactly
`device-enrollment.v1`, and no free-form URI or reordering is allowed. The
possession digest is not a SIWE resource.

For EIP-712, the fixed primary type is `JuiceboxMessagingDeviceEnrollmentV1` with fields
`challengeId`, `possessionChallengeId`, `audience`, `clientId`, `origin`, `purpose`, `action`, `scopeDigest`,
`enrollmentId`, `accountId`, `chainId`, `installationId`, `deviceCredentialId`,
`installationAuthProfile`, `installationAuthJkt`, `mlsCredentialProfile`, `mlsCiphersuite`,
`mlsCredentialPublicKey`, `mlsCredentialFingerprint`, `keyPackageKind`, `keyPackageRef`,
`keyPackageSha256`, `protocolProfile`, `nonce`, `issuedAt`, `notBefore`, and `expiresAt`. UUIDs are
canonical 16-byte values, hashes are `bytes32`, times are uint64 Unix seconds, and strings/keys are
exact canonical encodings. `action` MUST byte-equal `purpose`. The fixed domain binds name
`Juicebox Messaging`, version `1`, the
allowlisted chain ID, and deployment/environment salt. `challengeDigest` is deliberately absent and
is computed afterward for the possession proof. There is no profile fallback and no reusable unscoped
`personal_sign` payload.

### 3.4 Claim, verify, and issue

`POST /v1/device-enrollments/{enrollmentId}/complete` requires the enrollment capability and
idempotency:

```json
{
  "walletProof": {
    "challengeId": "0195e5c1-a7d0-7d6a-a521-256e257df384",
    "profile": "siwe-erc4361-v1",
    "signature": "0x..."
  },
  "possessionProof": {
    "kind": "p256-es256-installation-possession.v1",
    "possessionChallengeId": "0195e5d2-9900-7b6d-82fa-1734ded26617",
    "enrollmentId": "0195e5b4-23ef-765a-b9f5-74b9b20df0e1",
    "installationId": "5ec2d18e-f082-48fa-8b01-55e43fed021c",
    "challengeDigest": "base64url-32-bytes",
    "signature": "base64url-64-byte-r-and-s"
  }
}
```

After bounded parsing and idempotent-result lookup, one transaction CASes both challenge rows from
`issued` to `claimed`, records one UUIDv7 completion request and its request hash, and commits before
expensive verification. The canonical claim time MUST be within both stored not-before/expiry windows,
and the final verifier time must still be before both expiries; crossing either deadline produces no
credential. The claims are terminal: invalid proof, verifier `unavailable`, timeout,
process crash, audit failure, or an interrupted response never returns either challenge to `issued`.
An exact retry returns the stored terminal result; a changed retry conflicts. The status endpoint
`GET /v1/device-enrollments/{enrollmentId}` requires the enrollment capability and reveals only
`pending|issued|invalid|unavailable|expired`, stable reason code, and the successful result if any.

The possession verifier accepts only a canonical 64-byte P-256 `r || s` ES256 signature over the exact
stored digest, requires low-S and the bound public key, and rejects DER, alternate digest, or substituted
ID. The wallet verifier selects the method from the submitted bytes and one recorded finalized chain
state: exact EOA recovery, ERC-1271 exact magic at the pinned block, or bounded read-only ERC-6492
simulation. It never broadcasts a 6492 deployment. Provider disagreement, pruned state, ambiguous code,
unsupported wrapper/proxy, gas/size limit, missing canonicality, or unresolved ENG-004 finality returns
`503 enrollment_verification_unavailable` and issues no account activation, credential, session, or
eligibility lease. It never falls back between methods.

Only the single winning verified attempt may atomically activate the account/installation, insert the
initial ordinary KeyPackage, issue a signed device credential, append its key-transparency directory
entry, obtain the required inclusion/consistency proof and witness receipt, create the device-bound
session, persist idempotency/audit/outbox rows, and return success. The device credential is the signed
`device-credential.v1` canonical object containing `deviceCredentialId`, account/participant and chain,
the full `DeviceKeyBinding`, wallet- and possession-evidence digests, `issuedAt`, `expiresAt` no more
than 30 days later, monotonic `revocationVersion`, `roleBinding: null`, signer key ID, canonical payload
digest, and signature. It conveys no project, customer, staff, purchase, or conversation role.

The success response is:

```json
{
  "tokenType": "DPoP",
  "accessToken": "opaque-high-entropy-token",
  "expiresIn": 900,
  "refreshToken": "opaque-rotating-token",
  "refreshExpiresIn": 2592000,
  "account": {
    "accountId": "7f94c690-2af4-4a45-a7cc-9d85ce6cbd26",
    "walletRef": "eip155:1:0xAbC...123"
  },
  "installation": {
    "installationId": "5ec2d18e-f082-48fa-8b01-55e43fed021c",
    "kind": "native",
    "deviceCredentialId": "c3c82f16-bf3c-45e0-8518-ca1bf6ab3b66",
    "credentialFingerprint": "base64url-32-bytes",
    "credentialExpiresAt": "2026-09-13T16:20:00.000Z"
  },
  "deviceCredential": "signed-device-credential.v1",
  "directoryEntry": {
    "entryId": "41573574-9359-42d5-a086-bad686006b37",
    "checkpointId": "2e6c1a5a-968a-4419-8569-4b3db779f951",
    "inclusionProof": "base64url",
    "consistencyProof": "base64url",
    "witnessReceipt": "base64url"
  }
}
```

### 3.5 Session and device-credential enforcement

Access and refresh tokens are stored as keyed hashes, never plaintext. Access tokens last 15 minutes.
Refresh tokens expire no later than the bound device credential, last at most 30 days, rotate on every
use, and invalidate the whole token family if an already rotated token is reused. Every session row
names the exact active `deviceCredentialId`, installation, account, `installationAuthJkt`, audience,
client, and origin. A missing, expired, suspended, revoked, or superseded credential makes session
creation, refresh, and authenticated requests fail closed even if the bearer token has not expired.

Every authenticated request sends `Authorization: DPoP <accessToken>` and a DPoP proof conforming to
RFC 9449. The proof MUST bind `htm`, normalized `htu`, `iat` within 60 seconds, unique `jti`, the
access-token hash `ath`, and the registered P-256 key. The service maintains a five-minute DPoP `jti`
replay cache. A `DPoP-Nonce` challenge is used after clock or replay anomalies.

- `POST /v1/auth/refresh` rotates the refresh token and requires DPoP plus idempotency.
- `GET /v1/auth/session` returns account, linked wallet, installation, bound device-credential ID/state/
  expiry/revocation version, session expiry, and, for the
  cookie-BFF profile, the existing session-bound `csrfToken`; it does not mutate/rotate the token or
  return bearer/refresh secrets.
- `DELETE /v1/auth/session` revokes the current token family.
- `POST /v1/installations/{installationId}/device-credential-renewals` requires a fresh, exact wallet
  proof and installation possession. Renewal may supersede a credential only for the identical key
  binding; a key change creates a new installation. Superseded credentials are terminal and appear in
  the append-only directory.
- `DELETE /v1/installations/{installationId}` requires a fresh wallet proof, irreversibly revokes the
  installation and credential, revokes all sessions and KeyPackages, appends/witnesses the directory
  entry, unregisters push endpoints, and creates membership-removal intents in every active group.

Browser deployments MAY wrap tokens in a same-site first-party BFF, but that does not change the DPoP
contract between the BFF and this service. Tokens MUST NOT appear in URLs, fragments, logs, analytics,
or postMessage payloads.

Browser mutations require an exact `Origin` match against the registered HTTPS origin and
`Sec-Fetch-Site: same-origin`; missing/`null` origin is rejected for browser client IDs. CORS is denied
by default and never reflects an arbitrary Origin. A cookie BFF uses a `__Host-` Secure, HttpOnly,
SameSite=Lax session cookie plus a separate session-bound CSRF token returned by session introspection;
the token is sent in `X-CSRF-Token`, compared in constant time, and rotated only on protected session
mutation—not on GET. Native client registrations omit browser origin headers but still bind DPoP `htu`,
client ID, platform attestation policy, and the fixed service audience. Proxies may influence external
origin only in an explicit trusted-proxy deployment with a fixed hop/address allowlist.

### 3.6 KeyPackage publication

`POST /v1/installations/{installationId}/key-packages` requires matching DPoP installation and
idempotency and accepts at most 20 `{keyPackageRef, keyPackage, keyPackageSha256, expiresAt}` objects
for the active release profile. The reference is the profile-defined domain-separated hash. The server
checks canonical public structure, suite/profile, installation credential fingerprint, size, uniqueness,
and expiry without receiving private init-key material. It returns accepted refs and the independently
witnessed device-directory checkpoint/proofs. Exact replay returns the original result; a taken or used
ref cannot be republished. Version 1 disables RFC 9420 last-resort KeyPackages: every published package
is ordinary, single-use inventory and the capabilities manifest MUST report
`lastResortKeyPackages: false`.

`DELETE /v1/installations/{installationId}/key-packages/{keyPackageRef}` removes only an unused,
untaken package and is idempotent. The instant a planning response exposes package bytes, the service
atomically marks that package `taken` by that plan and permanently removes it from available inventory.
Activation later marks it `used`; expiry, cancellation, abort, or an ambiguous activation outcome never
releases it. The service may destroy its bytes after retaining the bounded audit hash, but it MUST NOT
make the ref available again. Exhaustion returns `409 key_package_inventory_exhausted` with a
non-enumerating `replenishmentRequired: true`; it never reuses a package or silently substitutes a
last-resort package.

### 3.7 Tenant-bound embedded client context

Embedding is an explicit production target but is not an authorization shortcut. The frame document is
served at the dedicated messaging origin as `/embed/{tenantPublicId}`; `tenantPublicId` is public
lowercase routing data and never a wallet, project, order, participant, conversation, or capability.
The production API refuses context issuance and the frame returns a generic unavailable document until
the tenant is `active`, its exact HTTPS parent origin is ownership-verified and `active`, its fixed frame
audience/client and top-level destinations are registered, and its environment-specific CSP/theme
configuration is complete. It never derives tenant or origin authority from `Host`, `Origin`,
`Referer`, a query, or `postMessage` data.

Tenant administration uses strongly reauthenticated, audited control-plane endpoints:

- `PUT /v1/tenants/{tenantPublicId}/embed-configuration` fixes the frame audience, registered host
  client IDs, theme hash, reason-code destination hashes, and state.
- `POST /v1/tenants/{tenantPublicId}/parent-origins` starts DNS/HTTPS ownership verification for one
  canonical HTTPS origin. Wildcards, paths, queries, fragments, userinfo, IP ambiguity, Unicode
  confusables, and inherited environment registrations are rejected.
- `DELETE /v1/tenants/{tenantPublicId}/parent-origins/{originId}` revokes that exact origin and all
  unredeemed contexts and live embed sessions bound to it. Tenant suspension/revocation does the same.

The registered host backend—not browser JavaScript—calls `POST /v1/embed/contexts` with an OAuth
client-credentials token bound to mutual TLS, exact tenant scope, API audience, and idempotency:

```json
{
  "tenantPublicId": "juicebox",
  "parentOrigin": "https://juicebox.money",
  "frameAudience": "https://chat.juicebox.money/embed",
  "hostClientId": "juicebox-money-production",
  "purpose": "open-secure-messaging",
  "action": "open",
  "resource": {
    "kind": "opaque-host-resource.v1",
    "resourceRef": "base64url-256-bit-opaque-reference"
  }
}
```

The context/redemption API rejects any query field before tenant, handle, or resource resolution. URL
fragments are client-only and a production context handle is forbidden there; no route strips a
fragment and treats the remainder as valid. The service compares, rather than learns, tenant, client,
parent origin, frame audience, purpose, and
allowed action against configuration. `resourceRef` is an integration-issued opaque reference; the
context contains no order description, shipping data, provider message, phone number, eligibility
assertion, wallet proof, or plaintext. The service creates a UUIDv7 `embedContextId` plus an independent
256-bit random `contextHandle`, stores only a purpose-separated HMAC of the handle and a lookup HMAC
plus envelope-encrypted copy of the opaque integration reference in the isolated short-lived context
store, and returns the handle once with `issuedAt`, `notBefore`, `expiresAt` no more than two
minutes later, and state `issued`. The response is no-store. The handle may appear only in the bounded
`host.init` payload and redemption request body; it is never placed in a URL, referrer, storage,
analytics, trace, or support log and is never retried after a channel restart.

```json
{
  "embedContextId": "0198a5f1-8f4d-76ac-a8f8-62c692241f36",
  "contextHandle": "base64url-256-bit-handle",
  "state": "issued",
  "issuedAt": "2026-08-14T16:20:00.000Z",
  "notBefore": "2026-08-14T16:20:00.000Z",
  "expiresAt": "2026-08-14T16:22:00.000Z"
}
```

After exact parent/source/bootstrap checks establish the version-1 channel, the frame calls
`POST /v1/embed/context-redemptions` through its same-origin BFF:

```json
{
  "contextHandle": "base64url-256-bit-handle",
  "tenantPublicId": "juicebox",
  "parentOrigin": "https://juicebox.money",
  "frameAudience": "https://chat.juicebox.money/embed",
  "channel": {
    "protocol": "org.juicebox.messaging.embed",
    "version": 1,
    "channelId": "base64url-256-bit",
    "bootstrapNonce": "base64url-256-bit",
    "parentNonce": "base64url-256-bit",
    "frameNonce": "base64url-256-bit"
  }
}
```

The BFF accepts this route only from its exact messaging origin with same-origin Fetch Metadata, body
capture disabled, no CORS, and an empty query. It rejects query fields before handle lookup. Framework-
internal `_rsc` is permitted only on reviewed document routing and is never accepted on context or
redemption APIs. It resolves the tenant and parent origin from server configuration,
compares every context binding, and stores HMAC/SHA-256 channel commitments rather than raw nonces. In
one transaction it CASes `issued -> claimed` before resolving the resource, creates one UUIDv7
redemption record, and on success marks `redeemed` and creates one UUIDv4 embed-session record bound to
the context, tenant, exact origin, audience, host client, channel commitments, and expiry. Claimed,
expired, revoked, mismatched, malformed, and already redeemed handles all return the same
`404 context_invalid`; a failed claim is terminal and cannot be moved back to `issued`.

Successful redemption sets the embed cookie and returns only:

```json
{
  "state": "authentication_required",
  "expiresAt": "2026-08-14T16:30:00.000Z"
}
```

The embed session is delivered only as a messaging-origin `__Host-jbm_embed` cookie with `Secure`,
`HttpOnly`, `SameSite=None`, `Path=/`, and `Partitioned`; responses are no-store and duplicate/ambiguous
cookie names fail closed. `Domain` is absent. It is distinct from every top-level cookie and the server also namespaces it
by tenant, exact parent origin, and channel. A browser that blocks or ignores the required isolated
third-party profile opens the fixed top-level messaging origin and never silently downgrades to a
shared global `SameSite=None` login, parent storage, or transferable token. The session
is created only while the context is unexpired and then expires with the channel or within ten minutes
of redemption, whichever is earlier; the consumed context handle is no longer a session lifetime or
recovery mechanism. Channel destroy, reload, origin drift, tenant/origin revocation, or explicit
`DELETE /v1/embed/session` revokes it. Destroy/timeout before redemption revokes the issued context and
requires a fresh handle. The frame bootstrap rejects or clears unexpected `location.search` or
`location.hash` without logging their contents; a handle is never recovered from either. It conveys
only the intended opaque navigation hint: it does not establish wallet control, installation
enrollment, purchase finality, eligibility, role, MLS membership, or message access. Those checks run
independently on the messaging origin. Provider-relay plaintext and native E2EE plaintext never enter
the context, redemption, embed-session, cookie, or `postMessage` planes.

- `GET /v1/embed/session` is same-origin/no-store and returns only `{state:
  "authentication_required"|"authorization_pending"|"ready", expiresAt}`. Before independent
  authentication/authorization it returns no tenant resource, wallet, project, purchase, role,
  conversation, or existence detail.
- `POST /v1/embed/session/auth-binding` requires both the live embed cookie and the ordinary active
  embedded-partition device session, CSRF, Fetch Metadata, idempotency, and the exact channel ID/nonce
  tuple in the body. A top-level `/app` session is never accepted as ambient embed authority. It
  atomically attaches the ordinary session after rechecking credential, tenant/origin/context and
  channel state, rotates the embed cookie to a fresh 256-bit secret, records the old token hash as
  revoked, and returns the new cookie no-store. It then runs ordinary finalized eligibility/MLS
  authorization; binding itself never grants access. Changed/replayed channel bytes fail terminally
  without rebinding.
- `DELETE /v1/embed/session` requires same-origin CSRF and atomically revokes the embed cookie row and
  channel binding. Teardown is idempotent and returns no context detail.

## 4. Eligibility and authorization context

Wallet authentication proves account control, not purchase ownership or project authority. Every
conversation operation is authorized against a server-side eligibility grant.

A caller supplies only an opaque claim handle:

```json
{
  "provider": "juicebox.v1",
  "projectRef": {
    "protocol": "juicebox",
    "protocolVersion": "v6",
    "chainId": "eip155:1",
    "projectsContract": "0x...",
    "projectId": "42"
  },
  "capability": "purchase-support",
  "claimHandle": "base64url-256-bit-handle"
}
```

The eligibility adapter resolves it to a minimal grant only after the release-approved chain finality
profile proves one canonical block and the independent RPC quorum agrees. ENG-004 is unresolved by
default: a chain without a ratified, enabled finality profile—including exact tag/depth semantics,
canonicality recheck cadence, provider quorum, archive-state support, and exceptional-pause rule—returns
`503 eligibility_unavailable` and creates no lease. `latest`, `safe`, an indexer, a single provider, or a
generic confirmation count cannot create or extend authority.

Eligible capabilities are:

- `purchase-support`: while PD-003 is open, this account is exactly the finalized canonical
  `Pay.beneficiary` (and, for supported item evidence, the matching `Mint.beneficiary`). Payer, caller,
  transaction sender, funder, checkout signer, and gift purchaser do not satisfy the capability;
  ambiguity returns no lease.
- `project-staff`: this account currently has the configured project permission.
- `token-holder`: the account meets the token and balance policy at the evaluated block.
- `item-set-buyer`: the account owns a qualifying receipt for the policy's item-set hash.

The grant binds account, installation, project, capability, normalized policy hash, opaque subject hash,
source chain/block, issued time, and expiry. Raw shipping, line-item, and payment details are not copied
into the grant. Revocable grants are rechecked at policy-defined intervals and on sensitive operations.

### 4.1 Claim issuance by a host application

Juicebox Money, Revnet, or another approved shop backend exchanges evidence for a handle through
`POST /v1/integrations/eligibility-claims`. This endpoint is not callable with a user session. It
requires the integration's OAuth client-credentials token bound to its mutual-TLS certificate, an
audience for this exact service, the project scope, and idempotency.

```json
{
  "provider": "juicebox.v1",
  "projectRef": {
    "protocol": "juicebox",
    "protocolVersion": "v6",
    "chainId": "eip155:1",
    "projectsContract": "0x...",
    "projectId": "42"
  },
  "capability": "purchase-support",
  "walletRef": "eip155:1:0xAbC...123",
  "evidence": {
    "kind": "onchain-receipt",
    "chainId": "eip155:1",
    "transactionHash": "0x...",
    "logIndex": "17"
  },
  "policyHash": "base64url-sha256"
}
```

Allowed evidence kinds and required fields are versioned per integration; arbitrary JSON is rejected.
The adapter independently reads canonical finalized chain state and checks the integration's project
scope. It never trusts the submitted account or capability alone. A successful response returns the
opaque 256-bit `claimHandle`, `issuedAt`, `validUntil`, and capability. The handle is returned once and
stored only as an HMAC. Host applications keep it in authenticated application state or a one-time
fragment handoff that is scrubbed before analytics, never a query parameter.

`project-staff` and simple `token-holder` grants MAY be resolved directly from the authenticated
account and finalized chain state by omitting `claimHandle`. `purchase-support` and
`item-set-buyer` require a claim handle so purchase/item identity is not guessed from public account
history.

Every request derives `accountId`, `installationId`, installation kind, active memberships, and role credential from
the DPoP session and database. Client-supplied sender IDs, roles, grant results, timestamps, project
authority, roster membership, or mailbox ownership are ignored or rejected as unknown fields.

## 5. Conversation kinds and lifecycle

Version 1 has two native cryptographic conversation kinds:

| Kind | Creator | Eligible roster | Default history behavior |
| --- | --- | --- | --- |
| `relationship` | Verified customer or project staff after consent | Customer installations and named project-support installations | Purchase cases are encrypted application subthreads; new installations receive no prior history. |
| `community_room` | Project staff | Installations satisfying the stored condition policy, provisionally capped at 250 accounts pending manifest ratification | Same forward-only join rule. |

`deliveryPurpose` is a separate immutable authorization dimension with the closed v1 values
`purchase-support`, `announcement`, and `community`; it is not inferred from the broad conversation
kind. Version 1 role credentials and membership roles use the closed set `customer`, `project-staff`,
`publisher`, `subscriber`, `member`, and `moderator`. New application admission uses this exact matrix:

| Delivery purpose | Roles allowed to append applications | Read-only role |
| --- | --- | --- |
| `purchase-support` | `customer`, `project-staff` | None |
| `announcement` | `publisher` | `subscriber` |
| `community` | `member`, `moderator` | None |

Any other purpose/role pair returns `403 forbidden_role`. The active role credential is bound to the
same conversation, account, installation, credential subject, generation, policy revision, and
authorization proof used for admission. A client-supplied role never grants send authority.

A project/customer pair may have multiple concurrent relationship security domains. `relationshipId`
identifies a stored domain record and `relationshipScopeId` is its opaque, non-enumerable scope key.
The service derives an immutable `readerHistoryRetentionPolicyHash` over the exact business purpose,
business entity, reader-role/installations policy, history-transfer mode, and retention policy/revision. One
scope has at most one active `conversationId` generation. Multiple purchase cases MAY share that
generation only when both `relationshipScopeId` and the effective policy hash match exactly. A changed
business purpose, reader set/policy, business entity, retention rule, or history rule creates a new scope and generation;
it never mutates or broadens an old scope. The opaque `caseId`, canonical order reference, fulfillment
events, and purchase details remain in MLS application plaintext.

Announcements are campaigns over consented relationship conversations, not an MLS channel containing
the whole audience. Section 13 defines their fanout contract. Full-text provider relays are separate
non-native conversation types and are not created through the native endpoints in this document.

Conversation states are `provisioning`, `active`, `membership_pending`, `suspended`, `closing`,
`closed`, `retention_expired`, and `purged`. A plan is a separate expiring resource, not a conversation
state. Only `active` accepts application envelopes. `membership_pending` accepts proposal/commit and
repair traffic only; `suspended` accepts the minimum authenticated control traffic needed to repair or
close; `closing` and later states reject application envelopes.

`rosterVersion` is a service control-plane CAS counter. `epoch` is the MLS epoch claimed by the
accepted client artifact. Both begin at `0` on the short-lived provisioning record. Activation produces version `1` and the
initial MLS epoch. Every accepted membership commit increments roster version exactly once and must
advance epoch exactly once. An MLS Update commit advances epoch but leaves roster version and roster
hash unchanged. Clients reject any artifact whose cryptographic MLS state disagrees even
if the service counters match.

## 6. Planning and activating a conversation

### 6.1 Obtain an exact roster plan

`POST /v1/conversation-plans`

```json
{
  "kind": "relationship",
  "deliveryPurpose": "purchase-support",
  "projectRef": {
    "protocol": "juicebox",
    "protocolVersion": "v6",
    "chainId": "eip155:1",
    "projectsContract": "0x...",
    "projectId": "42"
  },
  "eligibility": {
    "provider": "juicebox.v1",
    "capability": "purchase-support",
    "claimHandle": "base64url"
  },
  "creatorInstallationId": "5ec2d18e-f082-48fa-8b01-55e43fed021c",
  "relationshipScope": {
    "relationshipScopeId": null,
    "policyProfileId": "project-support-standard-v3",
    "expectedReaderHistoryRetentionPolicyHash": null
  },
  "recipientSelection": {
    "mode": "named-project-support",
    "maximumStaffAccounts": 3
  }
}
```

For a new scope the ID/hash fields are `null`; the service resolves the immutable project-authorized
`policyProfileId`, derives the effective policy, creates random
`relationshipId` and `relationshipScopeId`, and reveals them only to authorized participants. To reuse a
known scope the caller supplies both values; missing/unauthorized scope IDs return the same 404 and a
hash mismatch returns `412 relationship_scope_changed` without revealing the current policy. The
server verifies eligibility and consent. If that exact scope, effective policy hash, and roster already
have an active generation, it returns `action: reuse_generation`, current ETag, and no key packages; the
client opens the encrypted case through a normal envelope. The service never searches or coalesces a
scope based on project/customer IDs visible to the caller. Otherwise it atomically takes one previously
untaken MLS KeyPackage per selected non-creator installation and returns a ten-minute plan. Returning
these bytes is
the irreversible take boundary even if the plan is never activated:

```json
{
  "planId": "0195e5ca-e049-7d3b-aed2-5ac88e3d4df4",
  "action": "create_generation",
  "relationshipId": "ba79a739-d4c8-42df-89a3-79fd58d41a74",
  "relationshipScopeId": "fc057686-191c-4e02-9474-0de68fc4109b",
  "readerHistoryRetentionPolicyHash": "base64url-32-bytes",
  "conversationId": "c99daf46-89d8-4e84-aada-53a04fa111c9",
  "kind": "relationship",
  "deliveryPurpose": "purchase-support",
  "releaseProfileId": "delivery-v1-2026q3",
  "deliveryLimitsDigest": "base64url-32-bytes",
  "releaseTrustRootDigest": "base64url-32-bytes",
  "projectRef": {
    "protocol": "juicebox",
    "protocolVersion": "v6",
    "chainId": "eip155:1",
    "projectsContract": "0x...",
    "projectId": "42"
  },
  "expiresAt": "2026-08-14T16:10:00.000Z",
  "planEtag": "\"plan-0195e5ca-e049-7d3b-aed2-5ac88e3d4df4-1\"",
  "roster": [
    {
      "accountId": "3f5e9ba2-9b2e-4a4d-9de1-13055be09266",
      "installationId": "5ec2d18e-f082-48fa-8b01-55e43fed021c",
      "installationKind": "native",
      "role": "customer",
      "bootstrapMode": "creator",
      "credentialFingerprint": "sha256:base64url"
    },
    {
      "accountId": "0ef6c7c0-6e43-46b9-a619-1db8428495d8",
      "installationId": "c28ef6a2-93fc-4f88-97be-fb246f50c519",
      "installationKind": "native",
      "role": "project-staff",
      "bootstrapMode": "welcome",
      "credentialFingerprint": "sha256:base64url",
      "keyPackageRef": "base64url-sha256",
      "keyPackage": "base64url"
    }
  ],
  "rosterHash": "base64url-sha256-over-canonical-roster"
}
```

The plan also returns `externalSenders.current` and `externalSenders.stagedNext`, each with immutable
credential ID, monotonic project-scoped `signerGeneration`, public credential bytes/fingerprint,
validity window, publication/witness time, policy-log checkpoint/proof, and an
`externalSendersHash`. Both credentials are pre-provisioned in the group's `external_senders`
extension, but the independently signed policy log marks exactly one active for MLS external-proposal
signing. A separate policy-head key signs the freshness head that reports that selection. Each
credential validity interval is at most 90 days; `stagedNext` must have at least 30 days
remaining at group activation. Before a staged credential may later become active, its publication and
independent witness receipt must be at least 30 days old. Current/staged-next validity may overlap for at most 14 days, but
the policy log authorizes exactly one at a time. Neither credential is a roster member or receives a
Welcome.

The response includes every recipient installation, not just accounts, as a strict discriminated
bootstrap union. Exactly one roster member is the request's creator account/installation with
`bootstrapMode: "creator"`; it omits `keyPackageRef` and `keyPackage` because that endpoint creates the
group locally. Every other member has `bootstrapMode: "welcome"` and contains one already-taken
ordinary KeyPackage. No creator KeyPackage is taken. The client MUST display the roster before sealing
sensitive fulfillment data. The service returns `409 recipient_keys_unavailable` rather than creating
a partially encrypted conversation.

A purchase-support roster contains one policy-authorized creator installation holding either the
`customer` or `project-staff` role and at least one installation for the counterparty role. The example
shows the complete two-installation minimum with a customer creator. The exact returned list is
authoritative, contains exactly one matching creator, and activation rejects any omitted, added,
substituted, reordered, or bootstrap-mode-changed installation. API `deliveryPurpose` maps exactly to
the SQL `delivery_purpose` column; `purpose` is not an accepted alias.

### 6.2 Activate

`POST /v1/conversations` requires `If-Match: <planEtag>` and idempotency.

```json
{
  "planId": "0195e5ca-e049-7d3b-aed2-5ac88e3d4df4",
  "conversationId": "c99daf46-89d8-4e84-aada-53a04fa111c9",
  "rosterHash": "base64url-sha256",
  "externalSendersHash": "base64url-32-bytes",
  "mls": {
    "cipherSuite": "0x0001",
    "groupId": "base64url",
    "epoch": "1",
    "envelopeId": "787a0328-ae6c-42c8-86be-00910fb94f6d",
    "commit": "base64url",
    "envelopeSha256": "base64url-32-bytes",
    "resultingConfirmedTranscriptHash": "base64url-32-bytes",
    "welcomeByInstallation": [
      { "installationId": "c28ef6a2-93fc-4f88-97be-fb246f50c519", "welcome": "base64url", "welcomeSha256": "base64url" }
    ]
  }
}
```

The server checks the unexpired plan, caller, exact conversation, immutable release profile/limits/
trust-root bindings, roster and external-sender hashes,
cipher-suite allowlist, artifact sizes/hashes, exact `external_senders` extension, and exact
welcome-installation set. The creator constructs the group locally and receives no Welcome. The
Welcome set is exactly the non-creator `bootstrapMode: "welcome"` installations, one each. In one
serializable transaction the service marks the plan's already-taken packages
used, creates conversation and memberships, writes the first Commit under its client UUIDv4
`envelopeId` at position
`1`, initializes roster version, epoch, and confirmed-transcript checkpoint, creates installation
mailbox entries, and persists idempotency and
outbox rows. It cannot validate MLS cryptographic correctness; each client MUST do so before accepting
the group. A bad activation is reported and quarantined rather than automatically retried with altered
bytes.

Every initial membership has inclusive `joinedPosition: "1"` and references this authoritative
initial Commit. Exactly one membership is `bootstrapMode: "creator"` and matches the plan creator;
every other initial membership is `bootstrapMode: "welcome"`. The former has no Welcome record, while
the latter has exactly one target-specific Welcome bound to position 1. These modes are immutable for
the membership lifetime.

Each initial member receives one mailbox item for that position. A creator-mode item is only the
canonical Commit. Each welcome-mode item is augmented with that installation's own Welcome from
`welcomeByInstallation`; the service does not allocate a second `welcome` item, envelope ID, mailbox
position, or conversation position.

## 7. Reading conversations and roster state

- `GET /v1/conversations?projectHash=&kind=&state=&cursor=&limit=` lists only the caller installation's active
  or historical memberships. `limit` defaults to 50 and is at most 100.
- `GET /v1/conversations/{conversationId}` returns public project reference, kind, state, the caller-
  visible epoch, roster version/hash, confirmed-transcript hash, ETag, retention deadline, the caller's
  role, and unread counters. It does not return or imply a signed current log head.
- `GET /v1/conversations/{conversationId}/roster` returns the installation credentials, installation
  kinds, closed-set roles, `bootstrapMode`, inclusive joined/removed positions, credential
  fingerprints, and roster hash visible at the caller's boundary.
  It never returns wallet signatures or eligibility evidence.

All three require active or historical membership. An active caller may receive the current
coordination/roster projection. A removed caller receives only the exact historical projection at
`removedPosition`; none of these routes reveals a later epoch, roster change, head, suffix length, or
timing. Unauthorized and nonexistent IDs return the same 404. The conversation ETag is exactly
`"e<epoch>-r<rosterVersion>"` for that caller-visible projection. Only the separately authenticated
`/log-head` route in section 10 proves caller-visible high-water and append-only consistency.

## 8. Membership intents, external proposals, and MLS CAS commits

Membership never changes merely because an account's token balance changes or a client submits an MLS
blob. It changes through an authorized intent followed by one CAS commit.

Before sealing, clients fetch
`GET /v1/conversations/{conversationId}/policy-head?afterSequence=<uint64>`. It returns the newest of
potentially many immutable heads at the same epoch/roster:

Every issuance allocates a fresh random server UUIDv4 `policyHeadId`. Ordering comes only from the
per-conversation `policyHeadSequence`; an ID is never timestamp-bearing, overwritten, or reused.

```json
{
  "policyHeadId": "a4d721f6-8af9-4d82-afbe-e509e9a3fc2f",
  "policyHeadSequence": "81",
  "previousPolicyHeadHash": "base64url-32-bytes",
  "policyHeadHash": "base64url-32-bytes",
  "conversationId": "c99daf46-89d8-4e84-aada-53a04fa111c9",
  "epoch": "20",
  "rosterVersion": "28",
  "rosterHash": "base64url-32-bytes",
  "confirmedTranscriptHash": "base64url-32-bytes",
  "policyId": "e1b531e8-1fd7-4d82-aadf-80cb29f50c35",
  "policyRevision": "7",
  "policyHash": "base64url-32-bytes",
  "authorizedSendGrantSetHash": "base64url-32-bytes",
  "authorizedQuotaPolicyDigest": "base64url-32-bytes",
  "evaluatedChainId": "eip155:1",
  "evaluatedBlock": "21900400",
  "evaluatedBlockHash": "base64url-32-bytes",
  "mandatoryProposalCount": "1",
  "mandatoryProposalSetHash": "base64url-32-bytes",
  "mandatoryProposals": [
    { "proposalId": "0195e6a2-1b7c-7a34-8d91-4c5f612a7b08", "proposalHash": "base64url-32-bytes" }
  ],
  "activeExternalSenderCredentialId": "61114b21-bec2-4c77-9250-fc99789a17aa",
  "activeExternalSenderFingerprint": "base64url-32-bytes",
  "activeSignerGeneration": "14",
  "directoryCheckpointId": "2e6c1a5a-968a-4419-8569-4b3db779f951",
  "policyLogCheckpointId": "17110339-ea5a-4af0-a84f-2bdc918307d1",
  "deliveryLogPosition": "491",
  "deliveryLogHeadHash": "base64url-32-bytes",
  "evaluationLogPosition": "491",
  "evaluationLogHeadHash": "base64url-32-bytes",
  "issuedAt": "2026-08-14T16:20:00.000Z",
  "expiresAt": "2026-08-14T16:25:00.000Z",
  "signerKeyId": "policy-head-2026q3",
  "signature": "base64url"
}
```

The unsigned body is the object above without `policyHeadHash` or `signature`; it is serialized with
RFC 8785 JCS. `policyHeadHash = SHA-256(ASCII("jb-msg-policy-head/v1") || 0x00 || JCS(body))` and the
signature covers that 32-byte hash under the versioned policy-head signer profile. The
`activeExternalSender*` fields identify the separately scoped MLS external-proposal credential; they do
not sign this head. The policy-head key signs only freshness heads, and the MLS external-sender key
signs only independently logged public proposals. Keys, credential formats, signature contexts, and
verification paths are domain-separated; a valid signature from one domain is rejected in the other.
Issuance locks the conversation and copies its exact current delivery-log position/head into the
signed delivery/evaluation anchors; the service persists those fields and the complete immutable
signed-body bytes. The shared head binds the complete `policyHash`, exact ordered mandatory-proposal
count/list/set hash (at most 100 entries), the authorization-set root
`authorizedSendGrantSetHash`, and the separately signed quota-policy anchor
`authorizedQuotaPolicyDigest`. It does not contain one sender-specific grant as the global authority
for every member. Append authorization additionally supplies and verifies the selected sender-grant
record and inclusion evidence under that set root plus the exact scoped quota bindings under the quota
anchor.
It never reconstructs a served head from current mutable conversation state.
Sequence starts at one, is
gap-free per conversation, and every head after one binds the prior hash; head one uses 32 zero bytes.
Validity is positive and at most five minutes. Epoch, roster, and policy revision need not change for a
newer evidence block, proposal set, delivery head, or expiry, so uniqueness is by conversation/sequence,
not those fields. The response includes the policy-log inclusion/consistency proof after the caller's
sequence. A client persists the highest verified sequence/hash and rejects rollback, gap, same-sequence
conflict, stale expiry, or inconsistent witness view. Application appends name `policyHeadId` and exact
hash/sequence; an unhandled mandatory proposal fails closed. Delivery counters alone are never proof
that removal is absent.

The signed `deliveryLogPosition`/`deliveryLogHeadHash` is the policy head's issuance/base prefix, not a
promise that it equals every later event-page end. Historical sync verifies that this prefix resolves
to a witnessed position Q no later than the page end P and verifies complete policy-log ordering and
effective-at-P transition evidence. It may replay a head that is now expired or superseded when that
head is the exact historical projection. New append authorization is stricter: it requires the newest
current, fresh, unexpired head at the authoritative reservation time. A client's never-lowered current
policy-log high-water is retained as a separate consistency anchor; replaying an older valid page does
not lower it or make the historical page appear to be a rollback.

### 8.1 MLS wire profile

The release manifest returned by `GET /v1/capabilities` pins the audited RFC 9420 implementation,
cipher suite `0x0001` (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`), credential profile, and
protocol minor version; no client or server negotiates a private or unlisted suite. The version-1
confirmed-transcript hash is the suite's SHA-256 output, exactly 32 bytes, and every API field carrying
it uses canonical unpadded base64url. Public MLS proposals and Commits MUST use `PublicMessage` and
`application/vnd.juicebox.messaging.mls-public-message`. This lets the delivery service order the exact
mandatory proposal set and apply CAS checks, while clients still perform authoritative MLS validation.
Application data MUST use `PrivateMessage` and
`application/vnd.juicebox.messaging.mls-private-message`; a public application message is rejected.
External-proposal `PublicMessage` bytes are at most 256 KiB, Commit `PublicMessage` bytes are at most
512 KiB, and a `Welcome` is at most 256 KiB for each target installation. `Welcome` objects are stored
as opaque, hash-checked artifacts addressed only to the newly added installation and are never
returned to existing members or treated as application history. GroupInfo,
ratchet-tree material, and other control objects are permitted only where the pinned profile requires
them and follow the same target and size restrictions. Public handshake content MUST contain no wallet,
order, case, shipping, tracking, or other application identifier.

### 8.2 Create an intent

`POST /v1/conversations/{conversationId}/membership-intents`

```json
{
  "operation": "add",
  "targetInstallationId": "c28ef6a2-93fc-4f88-97be-fb246f50c519",
  "eligibilityClaimHandle": "base64url",
  "keyPackageRef": "base64url-sha256",
  "reason": "eligible_join"
}
```

Operations are `add`, `remove`, and `replace_installation`. Project policy determines which roles may request
or approve each operation. Loss of continuous eligibility creates a server-originated `remove` intent;
it does not rewrite history. Only one non-expired intent may target an installation in a conversation. The
response binds `intentId`, base epoch, base roster version, proposed roster hash, already-taken key package,
authorized committer installation IDs, and a five-minute expiry. If this response first exposes target
KeyPackage bytes, intent creation atomically and irreversibly takes that package exactly as planning
does; intent expiry/cancel never returns it to inventory. For entitlement-driven Add or Remove,
the response also contains the MLS external-proposal credential ID/fingerprint/signer generation,
UUIDv7 `proposalId`, `proposalHash`,
exact public MLS proposal bytes, canonical authorization-record hash, and independent transparency-log
inclusion proof. `proposalId` is an opaque record locator. The authoritative content binding is
`proposalHash = SHA-256("jb-msg-external-proposal/v1" || u32be(len(publicMessage)) || publicMessage ||
authorizationRecordHash)`, where `authorizationRecordHash` is exactly 32 bytes. A policy head signs an
ordered array of both fields; neither an ID nor a hash alone satisfies the mandatory set. The response
also returns the proposal's UUIDv4 `envelopeId`, allocated log `position`, and signed delivery-log head.
The durable proposal record and that exact `external_proposal` envelope are one-to-one; there is no
hidden ID-to-envelope mapping or secondary proposal cursor.
Sync verification treats this as composite evidence: the release-pinned MLS `PublicMessage`, signed
authorization/policy proof, and immutable durable proposal/intent/envelope bindings must all agree.
A self-reported `verified` status without the authenticated record/FK evidence is insufficient.
The entitlement signer is an MLS external sender, never a group leaf. Conversation state becomes
`membership_pending` through CAS. From that transition, every later application submission is
rejected; only bounded proposal/Commit/repair traffic is accepted. An application envelope already
accepted at an earlier position remains immutable and deliverable within each recipient's existing
membership boundary. A proposal alone does not change cryptographic membership.

The proposal signer credential must be one of the two credentials fixed at group creation and must be
the single credential active in the referenced signed policy-log checkpoint. The staged-next
credential has no authority merely because it appears in the extension. External-sender credential
activation cannot be changed through an MLS GroupContextExtensions Commit or external self-update.

### 8.3 External-sender rotation and generation migration

`POST /v1/conversations/{conversationId}/signer-migrations` requires a fresh policy head, project
authorization, current ETag, idempotency, and reason `scheduled_rotation` or `emergency_compromise`.
It creates one durable resource containing `signerMigrationId`, predecessor conversation/generation,
predecessor current and staged-next credential IDs/fingerprints/signer generations, source policy-log
checkpoint/security-ledger sequence, proposed successor current/staged-next credential IDs/fingerprints/
signer generations, target checkpoint, `lastAuthorizedSignerExpiresAt`, `deadlineAt`, and
`dualOverlapEndsAt`. `lastAuthorizedSignerExpiresAt` snapshots the expiry of the last
policy-authorized signer available to the predecessor, and `deadlineAt` is no later than that timestamp
minus 30 days; suspension fires at this T−30 deadline, not credential expiry.
`dualOverlapEndsAt - successorNotBefore` is at most 14 days. The proposed successor current credential
is the predecessor's staged-next credential unless an emergency checkpoint explicitly revokes it.
Successor signer generations are strictly increasing. A `retired` or `revoked` generation is terminal,
recorded in the signed policy/security logs, and can never be staged or active again.

The state machine is:

```text
scheduled -> successor_provisioning -> successor_ready -> cutover_verified -> complete
emergency_frozen -> successor_provisioning -> successor_ready -> cutover_verified -> complete
any non-complete state -> blocked
```

For an emergency, the API publishes/checks the revocation and CASes the predecessor to `suspended`
before returning `emergency_frozen`; this must occur within five minutes of the authoritative compromise
decision. `POST /v1/signer-migrations/{id}/successor-plan` returns a normal generation `N+1` plan with
fresh member KeyPackages and exact successor current/staged-next credentials and moves
`scheduled|emergency_frozen -> successor_provisioning`. Exact retries replay; changed fingerprints,
checkpoints, or deadline conflict.

`successor_ready` means the expiring plan plus client-created group/Commit/Welcome artifacts have been
validated and durably staged; there is no successor `conversations` row, mailbox, membership, routing,
or accepted traffic yet.
`POST /v1/signer-migrations/{id}/cutover` supplies the old-member-signed migration statement bound to
both conversation/group IDs, both roster/scope-policy hashes, predecessor/successor fingerprints,
source/target policy checkpoints, reason, and deadline. The service verifies independent witness
proofs, including that the successor-current credential was published and witnessed at least 30 days
before activation. In one transaction it first CASes the predecessor to `closing`, then inserts and
activates the verified successor, then swaps the same-scope relationship pointer and records the
cutover, persists initial Commit/Welcomes/mailboxes/idempotency, and sets
`cutover_verified`; a worker marks `complete` only after the cutover head is witnessed. At the deadline,
any incomplete predecessor is suspended and the migration becomes `blocked`; authority never falls
back to an expired or compromised signer.

Only authorized member clients construct MLS groups and Commits. The server cannot use an external
GroupContextExtensions/self-update or generate a Commit. Clients join the successor with fresh
KeyPackages and state. No application ciphertext, Welcome bytes, MLS state, epoch secret, case
plaintext, or history is copied; optional retained history transfer uses the separately consented
encrypted read-only archive flow.

### 8.4 Commit an intent

`POST /v1/conversations/{conversationId}/commits` requires the base conversation ETag and idempotency.

```json
{
  "commitType": "membership",
  "intentId": "0195e69c-30c8-7db4-8a1c-761d0eca5af2",
  "expectedEpoch": "19",
  "expectedRosterVersion": "27",
  "proposedRosterHash": "base64url-sha256",
  "mandatoryProposals": [
    { "proposalId": "0195e6a2-1b7c-7a34-8d91-4c5f612a7b08", "proposalHash": "base64url-32-bytes" }
  ],
  "envelopeId": "c74427fd-5f76-49b4-b6d3-01ab6bbd91f2",
  "commit": "base64url",
  "envelopeSha256": "base64url-32-bytes",
  "baseConfirmedTranscriptHash": "base64url",
  "resultingConfirmedTranscriptHash": "base64url",
  "resultingEpoch": "20",
  "welcomeByInstallation": []
}
```

The server first handles idempotent replay, then locks the conversation row, requires the exact pending
intent, authorized committer, ETag, counters, roster hash, exact ordered mandatory `(proposalId,
proposalHash)` set from the policy head, expected
welcome set, base confirmed-transcript checkpoint, and `resultingEpoch = expectedEpoch + 1`. One
transaction appends the Commit as the exact UUIDv4 `envelopeId`, binds a committed intent to that
same `(conversationId, envelopeId, position)`, applies membership rows, sets joined or removed
position inclusively to the Commit position, updates epoch/roster/hash/state, creates
mailbox deliveries, marks the already-taken key package used, and emits an outbox event.

The accepted Commit projection and receipt bind the exact `intentId`, immutable intent hash/evidence
digest, and every ordered consumed `(proposalId, proposalHash)` pair. A status flag or mutable intent
row alone cannot satisfy the one-to-one intent-to-Commit invariant. Every post-activation Add creates a
`bootstrapMode: "welcome"` membership whose inclusive `joinedPosition` is that Commit position and
requires exactly one target Welcome; `creator` mode exists only for the initial group creator.

There is exactly one mailbox item per target for this canonical Commit. Each newly added target's item
is augmented with only that target's hash-checked Welcome. It is not accompanied by a separate Welcome
mailbox item or another cursor/log position.

For a periodic MLS Update, `commitType` is `update`, `intentId` and welcomes are absent, and the
conversation must be `active`. The proposed roster hash and roster version must equal current values;
only epoch advances. Membership commits use `commitType: membership` and the pending-intent rules above.

Concurrent or stale commits receive `412` with current counters. They MUST fetch roster and rebuild from
the accepted MLS state; they MUST NOT resend old commit bytes under a new idempotency key. An intent may
be cancelled by an authorized installation before commit. Expired non-removal intents return the conversation to active
without changing membership; any locally generated commit is discarded.

## 9. Append-only application envelopes

`POST /v1/conversations/{conversationId}/envelopes` requires the current ETag and idempotency.

```json
{
  "envelopeId": "415609f1-9662-49f6-9cda-9ef319abe51d",
  "policyHeadId": "a4d721f6-8af9-4d82-afbe-e509e9a3fc2f",
  "policyHeadSequence": "81",
  "policyHeadHash": "base64url-32-bytes",
  "expectedEpoch": "20",
  "expectedRosterVersion": "28",
  "expectedConfirmedTranscriptHash": "base64url-32-bytes",
  "contentType": "application/vnd.juicebox.messaging.mls-private-message",
  "ciphertext": "base64url",
  "envelopeSha256": "base64url-32-bytes",
  "attachmentIds": []
}
```

The absolute v1 decoded ciphertext parser cap is 64 KiB. The service decodes base64url only to enforce
strict framing, size, and hash; it never interprets decrypted content. The generation-pinned signed
application limit may be lower or zero. Zero disables new application admission. The attachment-count
limit may likewise be lower or zero; zero permits an otherwise valid application with no attachment
references and rejects every new reference. The absolute parser accepts at most ten finalized
references so an exact historical retry remains parseable.

The append acceptance machine has these ordered boundaries:

1. A hard-cap-only parse builds an immutable command binding realm, HTTP key/request commitment, full
   semantic identity and exact ciphertext/ordered attachment IDs, authenticated HTTP device credential
   ID/fingerprint/revocation version, generation-pinned release profile, complete archived limits and
   digest, and release trust-root digest. Read-only preflight performs the replay order in section 2.3.
2. Only a true replay miss enforces the current generation's immutable signed limits, active state,
   credential/membership and purpose/role grant, ETag/epoch/roster/confirmed-transcript expectations,
   finalized attachment facts, quotas, absence of pending removal/mandatory proposals, and newest
   witnessed fresh policy head. Outside database locks, the MLS wire inspector verifies only public
   framing, release profile, group-ID hash, epoch, `PrivateMessage` application kind, content type, exact
   bytes/hash. The policy verifier returns the complete current head proof, authorization-set root,
   selected sender-grant and inclusion evidence, quota-policy digest, and exact scoped quota anchors.
3. Reservation transaction A re-locks every authoritative row, CASes the complete persisted preflight
   snapshot digest, reconstructs the sole allowed current-policy authorization overlay, requires its
   exact digest, and reruns the shared pure evaluator/transition validator. It then durably records one
   invisible immutable pending intent at RPO 0. That intent fixes the original admission command and
   profile, both snapshots/evidence sets, attachments, stable authoritative `receivedAt`, sole reserved
   position, leaf/previous/head hashes, signing-key ID, checkpoint digest, and complete next state. It
   advances no visible conversation head/state/usage, envelope, mailbox, outbox, idempotency result, or
   receipt. It fences the conversation lane so no later position can pass it.
4. The checkpoint signer signs exactly the reserved digest outside database locks. A distinct active-
   key verifier then verifies the exact tuple and signature, binding realm, generation, profile, trust
   root, and key validity at `checkpointReceivedAt = pending.receivedAt`; `verifiedAt` records the real
   later verification time. The signing service maintains a durable `(conversationId, position)` fence
   that permits one digest/signature and exact retry only.
5. Finalization transaction B re-locks and revalidates the exact pending intent, unchanged state/
   attachments, common transition, signing key and verification evidence. It atomically makes visible
   the envelope/head/state/usage, attachment bindings, eligible per-installation mailbox fanout, outbox,
   HTTP and secondary-envelope idempotency results, historical admission/proof records, and immutable
   receipt including `checkpointDigest`, with RPO-0 durability before success.

Every dependency call shares one real timer-backed absolute RFC3339-millisecond deadline and
`AbortSignal`; phase retries are bounded and cannot extend it. The frozen v1 application-append
orchestrator uses a 1,000-millisecond operation deadline and at most 64 phase attempts inside that
deadline. Those values are not deployment-tunable without a new reviewed profile and fault evidence.
Database transaction callbacks are
synchronous and local-only: no MLS, policy, KMS, witness, or other remote wait occurs while locks are
held. A crash before transaction A has no durable effect. A crash, timeout, invalid signer response, or
lost result after A leaves the same intent and lane durably fenced; recovery resumes and can finalize
only its exact position/time/digest/signature tuple. No ordinary cancellation, gap skip, position/
digest reuse, or fabricated success exists. If recovery cannot finish within the request deadline, the
route returns typed unavailable. A duplicate finalize or lost-response retry returns the original
receipt and cannot duplicate fanout.

The server stamps routing sender account/installation and `receivedAt` from the authenticated HTTP
device context. Because MLS `PrivateMessage` SenderData is encrypted, the Delivery Service cannot
inspect or authenticate the inner MLS sender leaf. After decryption, each recipient's CryptoPort MUST
authenticate the MLS leaf and scoped role credential and compare them with the server-stamped routing
sender; a mismatch fails processing and records a bounded digest-only security incident.

Response:

```json
{
  "envelopeId": "415609f1-9662-49f6-9cda-9ef319abe51d",
  "conversationId": "c99daf46-89d8-4e84-aada-53a04fa111c9",
  "position": "492",
  "epoch": "20",
  "rosterVersion": "28",
  "sender": {
    "type": "installation",
    "accountId": "7f94c690-2af4-4a45-a7cc-9d85ce6cbd26",
    "installationId": "5ec2d18e-f082-48fa-8b01-55e43fed021c"
  },
  "receivedAt": "2026-08-14T16:20:45.123Z",
  "logHead": {
    "position": "492",
    "previousHeadHash": "base64url-32-bytes",
    "headHash": "base64url-32-bytes",
    "signingKeyId": "delivery-log-2026q3",
    "checkpointDigest": "base64url-32-bytes",
    "signature": "base64url"
  }
}
```

The finalized per-conversation position has no gaps. A pending reservation is not visible but blocks
the next position until exact recovery/finalization or a separately reviewed durable fresh-generation
transition abandons that generation; its fence can never be reused by a late signer or finalizer.
Cross-conversation ordering is intentionally undefined.

Each accepted envelope also extends a per-conversation tamper-evident chain. `sender` is a tagged
union with exactly one canonical form: `installation {accountId, installationId}` or
`entitlement_signer {credentialId, fingerprint, signerGeneration}`. The leaf is
`SHA-256("jb-msg-envelope-leaf/v1" || canonical_length_prefixed(conversationId, position,
envelopeId, envelopeClass, senderTag, senderFields, epoch, rosterVersion, contentType,
envelopeSha256, receivedAt))`; the head is
`SHA-256("jb-msg-log-head/v1" || previousHeadHash || leafHash)`, with an
all-zero previous hash at position one.

For this formula, `canonical_length_prefixed` encodes each listed value as `LP(value) =
u32be(byteLength(value)) || value`: UUIDs are lowercase canonical ASCII, counters are canonical decimal
ASCII, tags/classes/content types are exact UTF-8, hashes/fingerprints are raw 32 bytes, and
`receivedAt` is the exact authoritative UTC RFC 3339 millisecond string. First construct
`senderFields = LP(accountId) || LP(installationId)` for tag `installation`, or
`senderFields = LP(credentialId) || LP(rawFingerprint32) || LP(canonicalSignerGenerationDecimal)` for
tag `entitlement_signer`; the outer leaf encoder then emits `LP(senderFields)` exactly once. Omitting
that outer prefix, applying it twice, or flattening inner fields is a different and invalid leaf.
Unknown tags, missing/extra union fields, and a hash over any representation other than the stored
envelope bytes are rejected.

The signing key ID is 1–64 lowercase ASCII bytes matching `[a-z0-9][a-z0-9._-]{0,63}`. The exact
checkpoint digest is:

```text
SHA-256(
  ASCII("jb-msg-delivery-log-checkpoint/v1") ||
  LP(lowercase canonical conversation UUID ASCII) ||
  LP(canonical position decimal ASCII) ||
  LP(raw previousHeadHash[32]) ||
  LP(raw headHash[32]) ||
  LP(lowercase signingKeyId ASCII)
)
```

The delivery service uses plain Ed25519 to sign exactly this 32-byte digest; it does not sign the
tuple/JCS/base64 text directly and does not use Ed25519ph. Verification reconstructs the digest from
the stored immutable fields and rejects alternate casing, integer encoding, hash encoding, field
order, domain, key ID, or signature mode. Finalization transaction B stores the digest, head, key ID,
and signature with the envelope. Verification uses the key registry
interval at the immutable checkpoint receipt time, not wall-clock time at a later retry. Neither a
response retry, worker restart, nor late signer can produce a different checkpoint.

A delivery signature detects alteration but cannot by itself detect split views. The service therefore
submits every signed head to the independent append-log witness and clients compare witnessed heads:

- `GET /v1/conversations/{conversationId}/log-head` accepts the caller's persisted
  `fromPosition`/`fromHeadHash` and prior witness anchor and returns the latest caller-visible service-
  signed head, witness receipt, and append-only consistency proof. Its strict raw JSON response is at
  most 64 KiB. An active member receives the service high-water; a removed installation receives
  exactly its inclusive removal-boundary head and no post-removal position, hash, or timing metadata.
  The proof binds realm, account, installation, complete membership credential/bootstrap/join/removal
  window, durable prefix digest, generation/profile/trust root, prior delivery/witness anchors, current
  checkpoint/key-time, witness inclusion/freshness, and consistency. Same-position/different-hash,
  rollback, inconsistent, malformed, or unavailable evidence fails closed.
- `GET /v1/transparency/checkpoints/{checkpointId}` is independently cacheable and returns the witness
  tree head, inclusion proof for the conversation head, witness key ID, and signature.
- A client MUST persist its last verified head, verify page continuity, obtain a witness receipt before
  sensitive sealing, and surface any same-position/different-hash result as equivocation. A page's
  `hasMore: false` is not proof that no newer visible suffix exists; only this `/log-head` proof supplies
  current high-water. Clients gossip
  `(conversationId, position, headHash, witnessCheckpointId)` inside authenticated MLS application
  messages; this leaks nothing beyond the existing conversation. A missing or inconsistent witness
  fails sensitive sends closed rather than silently trusting the delivery service.

The request query is exactly `fromPosition`, `fromHeadHash`, `priorWitnessCheckpointId`,
`priorWitnessTreeSize`, `priorWitnessRootHash`, and `priorWitnessedAt`; all are required after the
release bootstrap anchor. The strict response has exactly this shape (the nested shapes are reused by
conversation pages):

```json
{
  "conversationId": "lowercase-uuidv4",
  "generation": "canonical-positive-uint63",
  "releaseProfileId": "bounded-profile-id",
  "releaseTrustRootDigest": "base64url-32-bytes",
  "visibility": "active-high-water",
  "logHead": {
    "position": "canonical-positive-uint63",
    "previousHeadHash": "base64url-32-bytes",
    "headHash": "base64url-32-bytes",
    "signingKeyId": "lowercase-key-id",
    "checkpointDigest": "base64url-32-bytes",
    "signature": "base64url-64-byte-ed25519-signature",
    "checkpointReceivedAt": "2026-08-14T16:00:00.000Z"
  },
  "witnessReceipt": {
    "conversationId": "lowercase-uuidv4",
    "position": "canonical-positive-uint63",
    "headHash": "base64url-32-bytes",
    "witnessCheckpointId": "bounded-checkpoint-id",
    "witnessTreeSize": "canonical-uint63",
    "witnessRootHash": "base64url-32-bytes",
    "witnessKeyId": "lowercase-key-id",
    "witnessSignature": "base64url-64-byte-ed25519-signature",
    "witnessedAt": "2026-08-14T16:00:00.000Z"
  }
}
```

For a removed caller `visibility` is exactly `removed-boundary`; no other visibility string exists.
The client supplies its authenticated durable prefix digest, membership credential/window, generation,
profile/trust-root binding, and prior witness anchor to the `conversation-log-head-proof.v1` verifier.
Verified evidence binds all of those values, the exact from/current positions and hashes, checkpoint,
witness, visibility status, append-only consistency evidence digest, verification time, and one final
evidence digest. Syntax-only parsing of this response is never authorization.

## 10. One ordered conversation transcript

`GET /v1/conversations/{conversationId}/events?cursor=&limit=` is the only authoritative conversation
sync stream. It returns, in one gap-free position order, `external_proposal` (`PublicMessage`),
`mls_commit` (`PublicMessage`), and `application` (`PrivateMessage`) envelopes. There are no separate
proposal, Commit, or message cursors. Each item contains common `conversationId`, `position`, UUIDv4
`envelopeId`, class, content type, exact bytes/`envelopeSha256`, epoch, roster version, the exact tagged
`sender` union, receipt time, `leafHash`, `previousHeadHash`, `headHash`, `logSigningKeyId`,
`logCheckpointDigest`, and `logHeadSignature`; Commit items also carry base/
resulting 32-byte confirmed-transcript hashes and the exact verifiable intent/proposal projection.
Only a `bootstrapMode: "welcome"` target receives the Welcome field augmenting that one canonical
initial/Add Commit item; the initial `creator` receives none. A Welcome never creates a second event,
envelope ID, position, or cursor advance.

The JSON body is parsed from strict bounded bytes before object use. Unknown fields, duplicate keys,
invalid UTF-8, noncanonical base64url/counters/UUIDs/timestamps, trailing bytes, numeric coercion, or a
profile/binding mismatch are rejected. Each event is checked against the archived immutable release
profile and limits digest pinned by its conversation generation, plus the absolute v1 parser caps.

The effective default `limit` is `min(100, conversationEventsMaxPerPage)` from the archived generation
profile. An explicit value must be at least 1 and no greater than that profile value or the absolute
500-item cap; an over-limit request is rejected as `400 invalid_request`, never silently clamped. Given an
authenticated cursor at visible position P, a nonempty page is exactly P+1 through P+N with no
omission, reordering, or class filtering. In addition to the count limit, the server stops before the
page would exceed the generation profile's decoded/serialized ceilings, which are never above 4 MiB
(`4 * 1024 * 1024`) of decoded artifact bytes or 8 MiB (`8 * 1024 * 1024`) of final uncompressed UTF-8
JSON. Decoded artifact bytes are every exact returned envelope plus the target Welcome where present;
serialized bytes include every response field and base64url expansion. The service never splits an
item. A byte-bound short page sets `hasMore: true` and advances only through its last included item.

A valid profile MUST satisfy, with uint63-safe/bigint arithmetic:

```text
pageSerializedResponseMaxBytes >=
  ceil(4 * pageDecodedArtifactsMaxBytes / 3) + 4096 +
  4096 * max(conversationEventsMaxPerPage, mailboxEntriesMaxPerPage)
```

The decoded aggregate separately MUST fit the largest of the application cap, proposal cap, or Commit
plus target-Welcome caps. At the default hard ceilings, the minimum serialized bound is 7,644,502
bytes, which fits within 8 MiB. Consequently one item legal under the archived generation profile,
including one maximum Commit plus required target Welcome, always makes progress without exceeding
that profile or the absolute hard caps. Historical pages never apply a newer lowered profile; an event
that violates its own archived profile, including an event of a zero-disabled class, is an invariant
failure rather than an unreadable or silently skipped item.

A missing cursor starts after the persisted prefix at `joinedPosition - 1`, using zero only as the
pre-position sentinel when `joinedPosition` is 1. Its first page MUST be nonempty and begin with the
authoritative initial/Add Commit at inclusive `joinedPosition`. A creator-mode member receives that
Commit with no Welcome; a welcome-mode member receives the same Commit augmented with exactly its one
target Welcome. If that Commit or required Welcome is not retained, the API returns
`410 history_gone`; it never returns an empty or skipped success. A newly joined installation cannot
retrieve earlier ciphertext or metadata. Removed installations cannot retrieve positions after
`removedPosition`; they may retrieve accepted positions through that Commit position, subject to
retention. No application accepted after the earlier pending-removal cutoff exists. At a removal
boundary the response MUST set `hasMore: false`, even if a hidden post-removal suffix exists.

Conversation cursors have exactly the ASCII prefix `cc1.` followed by one canonical unpadded base64url
blob—there are no further separators. Decoding that blob yields:

```text
u8(1) || u8(keyIdByteLength) || keyIdASCII || nonce[12] || ciphertext || tag[16]
```

`keyId` is the clear active cursor-key ID: 1–64 lowercase ASCII bytes matching
`[a-z0-9][a-z0-9._-]{0,63}`. The AES-256-GCM plaintext is exactly:

```text
u8(1) || LP(realmId) || LP(lowercaseConversationUuidASCII) ||
LP(lowercaseInstallationUuidASCII) || u64be(lastReturnedPosition) ||
u64be(issuedAtUnixMilliseconds) || u64be(expiresAtUnixMilliseconds) || LP(keyIdASCII)
```

Its authenticated associated data is exactly:

```text
ASCII("jb-msg-conversation-cursor-aad/v1") || LP(realmId) ||
LP(lowercaseAuthenticatedAccountUuidASCII) || LP(lowercaseInstallationUuidASCII) ||
LP(lowercaseConversationUuidASCII) ||
LP(ASCII("GET /v1/conversations/{conversationId}/events")) || LP(keyIdASCII)
```

Here and in mailbox cursors, `LP` is `u32be(byteLength) || exact bytes`; UUIDs and the realm/key IDs use
their release-manifest canonical ASCII forms. AES-256-GCM uses a 128-bit tag. The outer and encrypted
versions, clear and encrypted key IDs, and every plaintext/AAD binding MUST match. The 96-bit nonce is
allocated from a fenced per-key RPO-0 nonce-range allocator: a range's monotonic fence and high-water
mark are durably committed before use; lease loss, restart, rollback, or ambiguous allocation burns
the unused range. A nonce is never random-only, repeated, or reassigned under one key. Cursor keys are
encrypt-enabled for at most 90 days; retired keys are decrypt-only only for the bounded overlap in the
retention specification. The complete token is at most 1,024 ASCII characters and expires no later
than 30 days after issuance; a canonical `cc1.` token is at least 43 characters. Non-canonical
base64url, length/trailing bytes, unknown version/key,
nonce reuse, tag failure, timestamp inversion, overlong token, repeated-field mismatch, or another
realm/account/installation/conversation/route returns `400 invalid_cursor`; an otherwise valid expired
cursor returns `410 cursor_expired` with a safe `restartAtPosition` no earlier than the membership
boundary. Public error shape/timing MUST NOT reveal whether a syntactically plausible token failed AEAD,
expired, crossed retention, named another context, or approached a hidden post-removal suffix.

The response has exactly the top-level keys `events`, `nextCursor`, `hasMore`, and `snapshot`; a v1
`pageProof` top-level field is invalid. Every event is a flat object with exactly the common fields named
above. An `mls_commit` adds exactly `baseConfirmedTranscriptHash` and
`resultingConfirmedTranscriptHash`; when applicable it also adds exactly one nested `welcome` object
with `targetInstallationId`, `welcome`, and `welcomeSha256`. The strict `snapshot` has exactly:

```json
{
  "conversationId": "lowercase-uuidv4",
  "generation": "canonical-positive-uint63",
  "releaseProfileId": "bounded-profile-id",
  "deliveryLimitsDigest": "base64url-32-bytes",
  "etag": "\"e20-r28\"",
  "epoch": "20",
  "rosterVersion": "28",
  "confirmedTranscriptHash": "base64url-32-bytes",
  "policyHeadId": "lowercase-uuidv4",
  "policyRevision": "7",
  "policyMandatoryProposalCount": "1",
  "policyMandatoryProposalSetHash": "base64url-32-bytes",
  "policyMandatoryProposals": [
    { "proposalId": "lowercase-uuidv7", "proposalHash": "base64url-32-bytes" }
  ],
  "policyAuthorizedSendGrantSetHash": "base64url-32-bytes",
  "policyAuthorizedQuotaPolicyDigest": "base64url-32-bytes",
  "policyHeadSequence": "81",
  "policyHeadHash": "base64url-32-bytes",
  "policyDeliveryLogPosition": "39",
  "policyDeliveryLogHeadHash": "base64url-32-bytes",
  "policyWitnessCheckpointId": "bounded-checkpoint-id",
  "policyWitnessEvidenceDigest": "base64url-32-bytes",
  "logHead": { "...": "exact logHead shape above" },
  "witnessReceipt": { "...": "exact witnessReceipt shape above" }
}
```

The ellipses above are documentation shorthand only; they are not JSON accepted on the wire. The
actual nested objects contain every exact field from the `/log-head` schema. The ordered mandatory list
contains exactly its declared count and at most 100 entries; its set hash is recomputed over that exact
order. `snapshot` is always the exact authenticated historical projection at the page end: the last
returned event for a nonempty page, or the supplied authenticated positive cursor anchor for a later
empty page. It is never the current service state or a substitute for `/log-head`.

An empty page is valid only after an authenticated positive cursor (including a removal boundary). It
MUST set `hasMore: false`, keep `nextCursor` at the requested anchor, and reproduce the exact historical
MLS/policy/checkpoint/witness projection stored at that anchor. A first cursorless page is never empty.
For a nonempty page, `nextCursor` names the last returned position. Repeating a cursor returns the same
ordered prefix/projection unless required history has been purged, in which case the server returns
typed 410 rather than silently skipping. `hasMore` is only a continuation hint; clients use the
separate authenticated `/log-head` path for current caller-visible high-water and consistency.

Historical policy verification binds the exact page-start and page-end projections plus a complete or
cryptographically coalesced transition-range proof, so a mandatory Remove cutoff cannot be hidden by a
later cleared head. It preserves the separately persisted current policy-log high-water without
requiring an older page-exact head to be greater than it. The page proof verifies every envelope
checkpoint, page-end signed checkpoint, key validity at each `checkpointReceivedAt`, witness inclusion/
consistency/freshness, release trust root, MLS Commit projection, and required target Welcome. Commit
evidence binds exact group/profile, bytes/hash, sender credential, prior/base/result transcript state,
intent IDs/hashes/evidence, and ordered proposal consumption. External-proposal evidence binds the exact
proposal/intent durable records as well as MLS and signed policy authorization. Any authenticated fork,
cross-context, visibility-boundary, or proof substitution fails closed and emits only a bounded digest-
only incident through an independent best-effort recorder capped at 100 milliseconds and the request's
remaining deadline; ordinary syntax/tag failures do not create an amplification path.

Proof material is deliberately not trusted merely because the Delivery Service placed it in the page.
After strict page parsing, the client kernel passes the exact response fields and its previously
authenticated prefix to separately authenticated, release-profile-pinned verifier adapters. Version 1
requires all of `conversation-page-proof-bundle.v1`, `conversation-policy-head-proof.v1` with purpose
`historical-page`, `conversation-policy-replay.v1`, `mls-commit-projection.v1` for every Commit, and
`mls-external-proposal.v1` for every external proposal. Their verified evidence MUST bind, field for
field, the realm, generation/profile/trust root, complete checkpoint list and signatures, prior/current
witness anchors and consistency, page-start/end delivery and policy projections, complete/coalesced
policy transition range, current policy-log high-water without lowering it, exact mandatory list,
Welcome target, public MLS bytes/group/epoch/transcript transition, sender credential, and immutable
proposal/intent/Commit records. Missing, partial, unknown-profile, stale, substituted, or unavailable
evidence fails closed. These adapters are part of the production TCB and their authenticated endpoints,
keys, deadlines, and evidence formats are pinned by the release profile; the current repository leaves
them unconfigured and exposes no production sync route.

## 11. Installation mailbox

The mailbox is the primary cross-conversation polling API:

`GET /v1/mailbox?cursor=&limit=100&wait=25`

- `limit` is 1–100.
- `wait` is 0–25 seconds and uses long polling; servers MAY return earlier.
- A missing cursor starts at the installation's retained mailbox floor, never another installation's position.
- A mailbox entry references one immutable envelope and contains the same artifact plus conversation
  state required to process it. For an added target, the one Commit mailbox entry is augmented with
  that target's Welcome. No `welcome` delivery class, second mailbox position, second envelope ID, or
  separate cursor advance exists.
- The same 4-MiB decoded-artifact and 8-MiB final-uncompressed-UTF-8-JSON ceilings as conversation
  pages apply. The decoded total includes the target Welcome. The server stops before either ceiling,
  never splits an item, and sets continuation state from the last included mailbox position.

Mailbox positions are gap-free and monotonic per installation. A mailbox cursor has exactly the ASCII
prefix `mc1.` followed by one canonical unpadded base64url blob with the same outer grammar,
AES-256-GCM/tag, fenced nonce allocator, key lifecycle, repeated-field checks, and 1,024-character
maximum as `cc1.`. Its plaintext is exactly:

```text
u8(1) || LP(realmId) || LP(lowercaseAccountUuidASCII) ||
LP(lowercaseInstallationUuidASCII) || u64be(lastMailboxPosition) ||
u64be(issuedAtUnixMilliseconds) || u64be(expiresAtUnixMilliseconds) || LP(keyIdASCII)
```

Its authenticated associated data is exactly:

```text
ASCII("jb-msg-mailbox-cursor-aad/v1") || LP(realmId) ||
LP(lowercaseAuthenticatedAccountUuidASCII) || LP(lowercaseInstallationUuidASCII) ||
LP(ASCII("GET /v1/mailbox")) || LP(keyIdASCII)
```

The encrypted and authenticated account/installation/key values MUST match each other and the current
session. The cursor reveals no position or conversation to its holder or to logs and expires no later
than 30 days after issuance. If unacknowledged history aged out, the API returns
`410 cursor_expired` with conversation IDs requiring bounded conversation resync.

`POST /v1/mailbox/acknowledgements` accepts an idempotent array of at most 500
`{mailboxPosition, envelopeId}` pairs. Acknowledgement only permits earlier mailbox-reference cleanup; it
does not delete the source envelope or signal a read receipt. Read receipts are optional encrypted
application events.

SDK retry rules:

1. Persist the last successfully processed cursor, not merely the last fetched cursor.
2. Fetch and cryptographically validate each event in order.
3. Apply the whole page durably to local storage.
4. Atomically advance the local cursor.
5. Acknowledge asynchronously.

## 12. Encrypted attachments

Clients generate a random content key, encrypt locally with an AEAD construction defined by the client
crypto profile, and place the key and authenticated attachment manifest inside the MLS application
plaintext. The service receives only ciphertext.

### 12.1 Create upload

`POST /v1/attachments/uploads`

```json
{
  "conversationId": "c99daf46-89d8-4e84-aada-53a04fa111c9",
  "epoch": "20",
  "ciphertextBytes": 7340032,
  "ciphertextSha256": "base64url-32-bytes",
  "partSizeBytes": 8388608
}
```

The candidate hard ceiling is 25 MiB per attachment, ten attachments per message, and 100 MiB of newly
finalized attachment ciphertext per conversation per UTC day. These values are provisional and the
endpoints return `404 feature_disabled` until the attachment profile is ratified and enabled by the
signed release manifest. MIME type, filename, dimensions, and plaintext hash belong only in the
encrypted manifest. The service stores the object as `application/octet-stream`.

The response returns `attachmentId`, random object key, upload ID, exact numbered HTTPS part URLs,
required headers, part size, and a 15-minute expiry. URLs are bearer capabilities and MUST NOT be
logged or placed in analytics/referrers. Unfinished objects are deleted after 24 hours.

### 12.2 Finalize and bind

`POST /v1/attachments/{attachmentId}/finalize` supplies ordered part numbers/ETags. The service performs
an object-store head/checksum verification and moves state from `uploading` to `ready`. Finalization is
idempotent. A later envelope append atomically changes referenced attachments to `bound`; an attachment
can bind to exactly one envelope in its original conversation and epoch.

`POST /v1/attachments/{attachmentId}/download` returns a single-use or 60-second signed HTTPS URL only
if the requesting installation was a recipient of the bound envelope and remains permitted by deletion policy.
Range reads are allowed. The response and URL carry `Referrer-Policy: no-referrer` and no cacheable
plaintext metadata.

## 13. Private announcement campaigns

An announcement campaign is an authorization snapshot and resumable fanout job, never a shared MLS
roster. Only a currently authorized `publisher` installation may create one; `subscriber` is
receive/read-only.

`POST /v1/campaigns` takes idempotency plus:

```json
{
  "projectRef": {
    "protocol": "juicebox",
    "protocolVersion": "v6",
    "chainId": "eip155:1",
    "projectsContract": "0x...",
    "projectId": "42"
  },
  "policyId": "e1b531e8-1fd7-4d82-aadf-80cb29f50c35",
  "policyRevision": "7",
  "policyHash": "base64url-32-bytes",
  "consentClass": "transactional",
  "relationshipScopePolicyProfileId": "project-announcement-v2",
  "scheduledAt": "2026-08-14T17:00:00.000Z"
}
```

The service evaluates the immutable policy at a recorded finalized block/hash and includes only an
eligible account with a registered encryption endpoint, affirmative consent for that class, and no
project block. For each account it derives the exact announcement
`readerHistoryRetentionPolicyHash`. Among active scopes with that hash, it selects exactly one by
ascending canonical `relationshipScopeId`; if none exists, it records `scope_pending` and permits one
dedicated announcement scope to be provisioned after consent. The ordered compatible-candidate hashes,
selected scope/hash (or absence), and algorithm version form `scopeSelectionHash`. A selected target
starts `pending`; one without a compatible scope starts `scope_pending`. A database uniqueness rule
allows exactly one target per `(campaignId, accountId)`. The service returns `campaignId`,
`audienceSnapshotHash`, target count, evaluated block/hash, and state `audience_snapshotted`. It never
returns the target list to recipients.

The authorized business endpoint generates a fresh 256-bit campaign content key and encrypts the body
and shared attachments once. `POST /v1/campaigns/{campaignId}/body/uploads` creates an upload capability
from declared ciphertext bytes/hash; `POST .../finalize` verifies the object and fixes the immutable
descriptor hash. Neither endpoint accepts the key. Campaign body objects remain disabled until the
attachment/campaign size profile is ratified in the release manifest.

`GET /v1/campaigns/{campaignId}/targets?cursor=&limit=` is restricted to the creating project role and
returns at most 100 opaque targets with `targetId`, exactly one selected `relationshipId`/
`relationshipScopeId`/policy hash/conversation (or `scope_pending`), `scopeSelectionHash`, current
coordination state, and policy-head reference. For a `scope_pending` target,
`POST /v1/campaigns/{campaignId}/targets/{targetId}/scope-plans` requires idempotency, rechecks consent,
block and eligibility, and returns an ordinary dedicated relationship plan bound to the target and
derived policy hash. Activating that plan atomically records the new scope/conversation and CASes only
`scope_pending -> pending`; an exact retry returns the same plan or activated scope, and a changed
request is `409 idempotency_conflict`. A policy failure CASes to `skipped_policy` without creating a
scope. No route can attach a second scope to a target.

The business endpoint wraps the campaign key and body
descriptor in a new MLS `PrivateMessage` for that scope only. A pending target may provision exactly one
dedicated announcement scope from the recipient's published KeyPackage after rechecking recorded
consent; it may not treat eligibility as consent. Provisioning CASes the target from `scope_pending` to
the new scope/generation and cannot attach a second scope.

`POST /v1/campaigns/{campaignId}/deliveries` accepts at most 50 exact `pending` target envelopes. Each item has
its own random UUIDv4 `envelopeId`, target ID, ETag, epoch, roster version, policy-head ID, ciphertext,
`envelopeSha256`, and
idempotency key. Each target commits through the ordinary single-conversation append transaction; the
batch is resumable, not atomic across conversations, and returns one stable result per target. Here
"append transaction" means the staged reservation/sign/verification/finalization machine in section 9,
not one database transaction containing a remote signing call. Target
and envelope uniqueness prevent a target from accepting twice or one envelope from satisfying two
targets. Before
each commit the service rechecks block/unsubscribe and consent, requires the target's recorded single
scope/policy hash and conversation to equal the envelope route, and rejects any other-scope roster. A
target becoming ineligible is
`skipped_policy`, never sent anyway. Retrying exact items returns their original position; changed bytes
conflict. `POST /v1/campaigns/{campaignId}/cancel` prevents not-yet-accepted deliveries but cannot retract
an already delivered key or ciphertext. A tenant-operated sender agent is permitted only when presented
as a plaintext-capable business endpoint, because it can see the campaign body and key.

## 14. Push wakeups

- `PUT /v1/installations/{installationId}/push-endpoints/{endpointId}` registers `webpush`, `apns`, or
  `fcm` delivery material, encrypted at rest. The path installation must equal the DPoP installation.
- `DELETE /v1/installations/{installationId}/push-endpoints/{endpointId}` unregisters it.
- Provider tokens, Web Push endpoints, `p256dh`, and auth secrets are never returned after creation.

A push contains only protocol version, a random wakeup ID, and a randomized installation-bound opaque
sync hint that expires after use or 24 hours. It has no stable collapse key. It MUST NOT contain
conversation/project IDs, sender, role, eligibility, message preview, ciphertext, shipping state,
exact unread count, or attachment metadata. Push means “poll your mailbox,” not “this message was
delivered.” Provider success is not a read or installation-delivery receipt.

## 15. Quotas and abuse controls

The numeric values below are provisional launch safety ceilings, not accepted capacity claims. They
MUST be ratified with the load, mobile, churn, and cryptographic evidence required by
[verification.md](./verification.md) and pinned in the signed release manifest. A deployment exposes
the active values and feature flags through `GET /v1/capabilities`; it MUST refuse startup if a value is
absent, exceeds its tested value, or disagrees across API pods. Projects may lower, but never raise,
these hard ceilings only through a new immutable signed profile and any policy-required
fresh-generation migration; they never edit a profile already pinned by a generation. Historical
replay/read uses that generation's archived profile. Attachments and campaign body uploads default to
disabled until their open launch decisions are closed.

| Limit | Provisional launch ceiling |
| --- | --- |
| Decoded application ciphertext | 64 KiB per envelope |
| MLS external-proposal artifact | 256 KiB |
| MLS public Commit artifact | 512 KiB |
| MLS Welcome artifact | 256 KiB per target installation |
| Attachment references | 10 per application envelope |
| Event/mailbox page decoded artifacts | 4 MiB; stop before the ceiling without splitting an item |
| Event/mailbox page serialized response | 8 MiB of final uncompressed UTF-8 JSON; stop before the ceiling without splitting an item |
| Envelope append rate | 10/second burst, 600/hour per installation; 6,000/hour per conversation |
| Membership intents | 30/hour per conversation; one pending per target installation |
| Active installations per account per project | 10 |
| Community accounts | 250 |
| Recipient installations in one conversation generation | Positive signed-manifest value, never above the reviewed 2,500 ceiling |
| Attachment, when enabled | 25 MiB each, 10/envelope, 100 MiB/conversation/day |
| Unfinalized attachment storage, when enabled | 250 MiB/installation and 24 hours |
| Campaign fanout | 50 deliveries/request; 100 targets/page; tenant/hour limit in release manifest |
| Idempotency record | Seven days |

An artifact ceiling of zero explicitly disables new admission for that artifact class. A zero
attachment-reference ceiling disables references, not an application with an empty reference list.
Page byte/count ceilings remain positive; the decoded and serialized sizing relations in section 10
are startup invariants, not aspirational capacity guidance.

Rate-limit decisions combine installation, account, project, recipient, campaign, conversation, tenant,
and privacy-preserving IP-prefix buckets. The service does not inspect ciphertext for spam. Users can
block an account/installation or report a transport `envelopeId` and category. An application `eventId`
is inside ciphertext and is disclosed only if the user explicitly selects decrypted report material.
Supplying plaintext is a separate consent flow and is never required for a basic metadata report. A
block prevents future membership/delivery where policy allows but cannot revoke previously downloaded
plaintext.

Over-limit responses include `Retry-After` and a bounded quota name, never another user's usage. Hard
row, ciphertext-byte, attachment-byte, target, and active-membership limits are checked transactionally
before allocating a conversation or mailbox position.

## 16. Export, close, and deletion API

- `POST /v1/conversations/{id}/close` is available to authorized policy roles. Closing rejects new
  application messages but permits a final removal commit and export during the retention window.
- `POST /v1/conversations/{id}/deletion-requests` schedules deletion and returns deadline, scope, and
  cancellation rules. Authorization depends on kind and jurisdiction; a customer cannot erase another
  member's required project records without policy evaluation.
- `POST /v1/accounts/me/exports` requires a fresh wallet proof and an X25519 export public key. The
  asynchronous export contains ciphertext, the caller-visible roster/metadata, and integrity hashes,
  encrypted to that export key. The service never creates a plaintext chat export.
- `GET /v1/jobs/{jobId}` returns state without embedding a signed object URL. A separate authenticated
  POST obtains a 60-second download URL.

Deletion and retention behavior is defined in
[storage-and-retention.md](./storage-and-retention.md). Deletion cannot retract data already decrypted,
copied, bridged, screenshotted, or backed up by another participant; clients must state this plainly.

## 17. Metadata visible to the service

| Data | Service visibility | Client E2EE property |
| --- | --- | --- |
| Wallet/account and project reference | Visible for authentication and eligibility | Not hidden by MLS |
| Enrollment profile, P-256 JKT, MLS credential fingerprint/KeyPackage ref, finalized proof metadata | Visible to identity authority; submitted wallet/possession signatures are transient and not retained after verification | Device credential and directory let clients verify the bound public keys; private keys never leave the device |
| Installation ID, credential fingerprint, roster role | Visible for delivery and membership CAS | Roster is cryptographically verified by clients |
| Embed tenant, exact parent origin, audience/purpose, channel commitments, timing | Visible short-lived metadata; opaque integration ref is encrypted and purged, provider/business plaintext is forbidden | Embed bootstrap is not MLS or authority; authorized chat content remains native E2EE after independent auth |
| Conversation kind, state, policy hash | Visible | Message meaning remains encrypted |
| HTTP-authenticated routing sender installation, recipient installation set | Visible | After decrypting encrypted SenderData, the recipient authenticates the MLS leaf/credential and requires it to match the stamped routing sender |
| Times, sizes, positions, epoch, roster version | Visible | Ciphertext integrity is verified end to end |
| Application event kind and fields | Opaque | Encrypted to the approved MLS roster |
| Shipping address, delivery note, tracking | Opaque unless intentionally bridged/reported | Must live only inside MLS application plaintext |
| Attachment bytes, filename, MIME type | Ciphertext/size/hash visible; filename and type hidden | Content key and manifest stay inside MLS plaintext |
| Push endpoint and wakeup timing | Visible to service/provider | Push contains no conversation content or identity |
| Announcement audience/fanout correlation | Visible to service and business sender | Recipient list is not exposed to other recipients; body/key remain endpoint-only |
| WhatsApp/Telegram relay message | Plaintext visible to relay business endpoint and platform | Separate relay thread; never part of the native MLS transcript |

The service MUST NOT advertise “zero metadata” or imply that bridge-delivered content retains the same
end-to-end boundary as an all-native roster.

## 18. Compatibility and conformance

All production clients MUST pass a shared conformance suite covering canonical encoding, DPoP replay,
wallet/installation binding, idempotent response loss, concurrent CAS commits, stale epochs, exact
installation rosters, forward-only joins, removal boundaries, cursor replay/cross-binding, log-head
continuity, witness split-view detection, retention gaps, attachment hash mismatch, push-content
prohibition, campaign consent, and relay disclosure.

The service supports the current and immediately previous client protocol minor version. A major wire
change uses a new base path. MLS cipher-suite changes use an explicit group migration conversation;
they are never silently negotiated by the delivery server.

## 19. Intentional departures from the development lab

Production does not upgrade, import, or reinterpret the SQLite lab. The boundaries are deliberate:

| Concern | Development lab | Production v1 |
| --- | --- | --- |
| Namespace/transport | `/api/dev/messaging`, explicitly enabled LAN HTTP | `/v1`, fixed production origin and HTTPS only |
| Authentication | One-use customer/staff invitations and cookie sessions | Wallet enrollment, linked opaque account, independent installation key, DPoP, short rotating sessions |
| Device identity | No wallet/device credential or transparency directory | Paired terminal wallet/P-256 possession proof, suite-`0x0001` MLS key binding, signed expiring credential and witnessed directory |
| Embedding | None; localhost/LAN page only | Configured tenant/origin/issuer, two-minute one-use context, partitioned ten-minute bootstrap session, independent wallet/eligibility checks |
| Cryptography | Clearly labelled simulated opaque base64 JSON | Audited RFC 9420 profile; `PrivateMessage` application data and `PublicMessage` handshake data |
| Topology | One fixed two-role room | Relationship generations/cases, bounded communities, and per-relationship announcement fanout |
| Authorization | Bootstrap role and fixed roster epoch | Finalized entitlement policy, consent/block precedence, external proposals, policy heads, transparency |
| Ordering/sync | SQLite integer cursor | Append-only PostgreSQL log, opaque installation-bound cursors, signed heads, independent witness |
| Membership | Fixed M1 roster; invitations disabled after bootstrap | Per-installation leaves, CAS commits, mandatory Add/Remove proposal handling, forward-only joins |
| Storage | Single-process SQLite opaque envelope log, 24-hour lab TTL | PostgreSQL/object storage/outbox, product retention schedules, deletion ledger, backup erasure window |
| Quotas | Small fixed room byte/count limits | Signed release-manifest ceilings and transactional multi-scope quotas |
| Connectors | None | Notification-only deep link or separately disclosed plaintext relay service; never a native group leaf |

Production uses separate DNS, credentials, signing/KMS/cursor keys, databases, buckets, queues, and
telemetry. Lab invitation tokens, cookies, conversation IDs, envelopes, and SQLite rows are invalid in
production and there is no migration endpoint for them.
