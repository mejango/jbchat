import { Buffer } from "node:buffer";
import { createHash, randomBytes } from "node:crypto";
import type { Sql, TransactionSql } from "postgres";
import {
  ENROLLMENT_PROTOCOL_PROFILE,
  SIWE_PROOF_PROFILE,
  buildSiweEnrollmentMessage,
  computeJwkThumbprint,
  computeKeyPackageRef,
  computeMlsCredentialFingerprint,
  computePossessionChallengeDigest,
  parseP256PublicJwk,
  parseWalletRef,
  verifyPossessionSignature,
  type P256PublicJwk,
} from "./identityCrypto";
import type { IdentityKeyedCryptoPort } from "./identityKeyedCrypto";
import type { WalletProofVerifierPort } from "./walletProofVerifier";

const ATTEMPT_TTL_MILLISECONDS = 5 * 60 * 1_000;
const ACCESS_TTL_MILLISECONDS = 15 * 60 * 1_000;
const REFRESH_TTL_MILLISECONDS = 30 * 24 * 60 * 60 * 1_000;
const CREDENTIAL_TTL_MILLISECONDS = 30 * 24 * 60 * 60 * 1_000;
const RESULT_PURGE_MILLISECONDS = 15 * 60 * 1_000;
const HANDLE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const CLIENT_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}$/;
const PURPOSES = ["enroll-messaging-device"] as const;

export interface DeviceCredentialSignerPort {
  readonly signerKeyId: string;
  readonly sign: (payload: Buffer) => Buffer;
}

export interface EnrollmentStoreContext {
  readonly sql: Sql;
  readonly now: () => string;
  readonly crypto: IdentityKeyedCryptoPort;
  readonly walletProofVerifier: WalletProofVerifierPort;
  readonly credentialSigner: DeviceCredentialSignerPort;
  readonly allowedChainIds: readonly string[];
}

export type EnrollmentAllocation =
  | {
      readonly status: "allocated";
      readonly enrollmentId: string;
      readonly enrollmentResultHandle: string;
      readonly expiresAt: string;
    }
  | { readonly status: "refused"; readonly reasonCode: "enrollment_refused" };

export interface DeviceKeyBinding {
  readonly walletRef: string;
  readonly installationAuthPublicJwk: unknown;
  readonly mlsCredentialPublic: string;
  readonly keyPackage: string;
}

export type EnrollmentChallenges =
  | {
      readonly status: "challenges_issued";
      readonly walletChallengeId: string;
      readonly possessionChallengeId: string;
      readonly siweMessage: string;
      readonly possessionChallengeDigest: string;
      readonly notBefore: string;
      readonly expiresAt: string;
    }
  | {
      readonly status: "refused";
      readonly reasonCode: "enrollment_invalid" | "enrollment_expired";
    };

export type EnrollmentCompletion =
  | {
      readonly status: "issued";
      readonly accountId: string;
      readonly installationId: string;
      readonly deviceCredentialId: string;
      readonly walletVerificationMethod: "eoa" | "erc1271" | "erc6492";
    }
  | { readonly status: "invalid"; readonly reasonCode: "enrollment_invalid" }
  | {
      readonly status: "unavailable";
      readonly reasonCode: "enrollment_verification_unavailable";
    }
  | { readonly status: "conflict"; readonly reasonCode: "idempotency_conflict" };

export type EnrollmentReadResult = {
  readonly status:
    | "pending"
    | "issued"
    | "invalid"
    | "unavailable"
    | "expired"
    | "unknown";
};

export type SessionIssueResult =
  | {
      readonly status: "issued";
      readonly sessionId: string;
      readonly accessToken: string;
      readonly refreshToken: string;
      readonly accessExpiresAt: string;
      readonly refreshExpiresAt: string;
    }
  | { readonly status: "refused"; readonly reasonCode: "credential_invalid" };

export type SessionRefreshResult =
  | SessionIssueResult
  | { readonly status: "revoked"; readonly reasonCode: "token_family_revoked" };

export interface EnrollmentStore {
  readonly allocateEnrollment: (input: unknown) => Promise<EnrollmentAllocation>;
  readonly issueChallenges: (
    handle: unknown,
    binding: unknown,
  ) => Promise<EnrollmentChallenges>;
  readonly completeEnrollment: (
    handle: unknown,
    proof: unknown,
  ) => Promise<EnrollmentCompletion>;
  readonly readEnrollment: (handle: unknown) => Promise<EnrollmentReadResult>;
  readonly issueSession: (input: unknown) => Promise<SessionIssueResult>;
  readonly refreshSession: (refreshToken: unknown) => Promise<SessionRefreshResult>;
  readonly revokeSessionFamily: (refreshToken: unknown) => Promise<void>;
}

/**
 * PostgreSQL state machine for paired wallet/possession device enrollment
 * (service-api.md sections 3.1-3.5). Both challenges are claimed by exactly
 * one completion in one transaction before any verification work, claims are
 * terminal forever, wallet proofs dispatch through the verifier port with no
 * cross-method fallback, and an unavailable verification is a terminal
 * fail-closed outcome. Session tokens exist only as purpose-separated keyed
 * hashes; refresh rotation is per-family, and rotated-token reuse revokes
 * the whole family. HTTP capability headers, DPoP proof checking, and rate
 * bounds live in the HTTP layer above this store.
 */
export function createEnrollmentStore(
  context: EnrollmentStoreContext,
): EnrollmentStore {
  const { sql, crypto } = context;
  const nowIso = (): string => {
    const value = context.now();
    if (new Date(value).toISOString() !== value) {
      throw new TypeError("Enrollment clock must be canonical UTC ISO time.");
    }
    return value;
  };

  const locateAttempt = async (
    tx: TransactionSql,
    handle: string,
  ): Promise<Record<string, unknown> | null> => {
    const rows = await tx`
      SELECT * FROM device_enrollment_attempts
      WHERE result_handle_hash = ${crypto.hmacResultHandle(handle)}
      FOR UPDATE`;
    return rows.length === 1 ? (rows[0] as Record<string, unknown>) : null;
  };

  const expireAttempt = async (
    tx: TransactionSql,
    enrollmentId: string,
  ): Promise<void> => {
    await tx`
      UPDATE device_enrollment_attempts SET state = 'expired',
        terminal_reason_code = 'enrollment_expired'
      WHERE enrollment_id = ${enrollmentId}
        AND state IN ('allocated', 'challenges_issued')`;
  };

  const buildSiweFields = (attempt: Record<string, unknown>, extras: {
    challengeId: string;
    possessionChallengeId: string;
    accountId: string;
    nonce: string;
    notBefore: string;
    expiresAt: string;
    jkt: Buffer;
    fingerprint: Buffer;
    keyPackageRef: Buffer;
    keyPackageSha256: Buffer;
    address: string;
  }) => {
    const origin = String(attempt.exact_https_origin);
    return {
      domain: new URL(origin).host,
      address: extras.address,
      uri: String(attempt.audience),
      chainReference: String(attempt.chain_id).split(":")[1],
      nonce: extras.nonce,
      issuedAt: extras.notBefore,
      notBefore: extras.notBefore,
      expirationTime: extras.expiresAt,
      requestId: extras.challengeId,
      resources: {
        enrollmentId: String(attempt.enrollment_id),
        accountId: extras.accountId,
        installationId: String(attempt.preallocated_installation_id),
        deviceCredentialId: String(attempt.preallocated_device_credential_id),
        audience: String(attempt.audience),
        clientId: String(attempt.client_id),
        scopeDigest: b64(attempt.scope_hash as Uint8Array),
        installationAuthJkt: b64(extras.jkt),
        mlsCredentialFingerprint: b64(extras.fingerprint),
        keyPackageRef: b64(extras.keyPackageRef),
        keyPackageSha256: b64(extras.keyPackageSha256),
        protocolProfile: ENROLLMENT_PROTOCOL_PROFILE,
        possessionChallengeId: extras.possessionChallengeId,
      },
    };
  };

  return Object.freeze({
    async allocateEnrollment(inputValue: unknown): Promise<EnrollmentAllocation> {
      let input: {
        wallet: ReturnType<typeof parseWalletRef>;
        clientId: string;
        origin: string;
        audience: string;
        purpose: string;
        scopeCanonical: string;
        scopeHash: Buffer;
        platform: "web" | "ios" | "android" | "desktop";
      };
      try {
        const record = expectRecord(inputValue, [
          "walletRef",
          "proofProfile",
          "client",
          "purpose",
          "scope",
          "installationKind",
          "platform",
        ]);
        if (record.proofProfile !== SIWE_PROOF_PROFILE) {
          throw new TypeError("Only the SIWE proof profile is implemented.");
        }
        if (record.installationKind !== "native") {
          throw new TypeError("Installation kind must be native.");
        }
        const client = expectRecord(record.client, ["clientId", "origin", "audience"]);
        const scope = expectRecord(record.scope, ["kind", "project", "action"]);
        if (scope.kind !== "wallet-challenge-scope.v1") {
          throw new TypeError("Scope kind is unsupported.");
        }
        if (scope.action !== record.purpose) {
          throw new TypeError("Scope action must equal the purpose.");
        }
        if (
          !PURPOSES.includes(record.purpose as (typeof PURPOSES)[number]) ||
          typeof scope.project !== "string" ||
          !CLIENT_ID_PATTERN.test(String(client.clientId))
        ) {
          throw new TypeError("Enrollment input is malformed.");
        }
        assertCanonicalHttpsOrigin(String(client.origin));
        assertCanonicalAudience(String(client.audience));
        const scopeCanonical = JSON.stringify({
          kind: scope.kind,
          project: scope.project,
          action: scope.action,
        });
        input = {
          wallet: parseWalletRef(record.walletRef, context.allowedChainIds),
          clientId: String(client.clientId),
          origin: String(client.origin),
          audience: String(client.audience),
          purpose: String(record.purpose),
          scopeCanonical,
          scopeHash: sha256(scopeCanonical),
          platform: parseOneOf(record.platform, ["web", "ios", "android", "desktop"]),
        };
      } catch {
        return Object.freeze({ status: "refused", reasonCode: "enrollment_refused" });
      }
      const now = nowIso();
      const expiresAt = addMilliseconds(now, ATTEMPT_TTL_MILLISECONDS);
      const enrollmentId = uuidV7(now);
      const handle = randomBytes(32).toString("base64url");
      const walletRefLookup = crypto.hmacWalletRefLookup(input.wallet.caip10);
      await sql.begin(async (tx) => {
        const links = await tx`
          SELECT account_id FROM wallet_links
          WHERE wallet_ref_lookup = ${walletRefLookup} AND status = 'active'`;
        let accountId: string;
        if (links.length === 1) {
          accountId = String(links[0].account_id);
        } else {
          accountId = uuidV4();
          await tx`
            INSERT INTO accounts (account_id, status, created_at)
            VALUES (${accountId}, 'pending_enrollment', ${now}::timestamptz)`;
        }
        await tx`
          INSERT INTO device_enrollment_attempts (
            enrollment_id, account_id, preallocated_installation_id,
            preallocated_device_credential_id, wallet_ref_lookup, chain_id,
            proof_profile, client_id, exact_https_origin, audience, purpose,
            scope_canonical, scope_hash, installation_kind, platform,
            storage_partition_class, result_handle_hash, state, issued_at,
            expires_at
          ) VALUES (
            ${enrollmentId}, ${accountId}, ${uuidV4()}, ${uuidV4()},
            ${walletRefLookup}, ${input.wallet.chainId}, ${SIWE_PROOF_PROFILE},
            ${input.clientId}, ${input.origin}, ${input.audience},
            ${input.purpose}, ${input.scopeCanonical}::jsonb, ${input.scopeHash},
            'native', ${input.platform}, 'top_level',
            ${crypto.hmacResultHandle(handle)}, 'allocated',
            ${now}::timestamptz, ${expiresAt}::timestamptz
          )`;
      });
      return Object.freeze({
        status: "allocated",
        enrollmentId,
        enrollmentResultHandle: handle,
        expiresAt,
      });
    },

    async issueChallenges(
      handleValue: unknown,
      bindingValue: unknown,
    ): Promise<EnrollmentChallenges> {
      if (typeof handleValue !== "string" || !HANDLE_PATTERN.test(handleValue)) {
        return refusedChallenges("enrollment_invalid");
      }
      let jwk: P256PublicJwk;
      let mlsPublic: Buffer;
      let keyPackageBytes: Buffer;
      let wallet: ReturnType<typeof parseWalletRef>;
      try {
        const binding = expectRecord(bindingValue, [
          "walletRef",
          "installationAuthPublicJwk",
          "mlsCredentialPublic",
          "keyPackage",
        ]);
        wallet = parseWalletRef(binding.walletRef, context.allowedChainIds);
        jwk = parseP256PublicJwk(binding.installationAuthPublicJwk);
        mlsPublic = exactBytes(binding.mlsCredentialPublic, 32);
        keyPackageBytes = boundedBytes(binding.keyPackage, 1, 262_144);
      } catch {
        return refusedChallenges("enrollment_invalid");
      }
      const now = nowIso();
      return sql.begin(async (tx) => {
        const attempt = await locateAttempt(tx, handleValue);
        if (!attempt) return refusedChallenges("enrollment_invalid");
        const enrollmentId = String(attempt.enrollment_id);
        if (now >= iso(attempt.expires_at)) {
          await expireAttempt(tx, enrollmentId);
          return refusedChallenges("enrollment_expired");
        }
        const jkt = computeJwkThumbprint(jwk);
        if (attempt.state === "challenges_issued") {
          if (!Buffer.from(attempt.installation_auth_jkt as Uint8Array).equals(jkt)) {
            return refusedChallenges("enrollment_invalid");
          }
          const [walletRow] = await tx`
            SELECT challenge_id, possession_challenge_id, exact_payload_ciphertext,
                   not_before, expires_at
            FROM enrollment_wallet_challenges WHERE enrollment_id = ${enrollmentId}`;
          const [possessionRow] = await tx`
            SELECT challenge_digest FROM device_possession_challenges
            WHERE enrollment_id = ${enrollmentId}`;
          return Object.freeze({
            status: "challenges_issued",
            walletChallengeId: String(walletRow.challenge_id),
            possessionChallengeId: String(walletRow.possession_challenge_id),
            siweMessage: crypto.openPayload(
              Buffer.from(walletRow.exact_payload_ciphertext as Uint8Array),
              "keyed-lab-v1",
            ),
            possessionChallengeDigest: b64(possessionRow.challenge_digest as Uint8Array),
            notBefore: iso(walletRow.not_before),
            expiresAt: iso(walletRow.expires_at),
          });
        }
        if (attempt.state !== "allocated") {
          return refusedChallenges("enrollment_invalid");
        }
        const fingerprint = computeMlsCredentialFingerprint(mlsPublic);
        const keyPackageRef = computeKeyPackageRef(keyPackageBytes);
        const keyPackageSha256 = sha256Bytes(keyPackageBytes);
        const walletChallengeId = uuidV7(now);
        const possessionChallengeId = uuidV7(now);
        const accountId = String(attempt.account_id);
        const nonce = randomBytes(16).toString("hex");
        const serverNonce = randomBytes(32).toString("base64url");
        const notBefore = now;
        const expiresAt = iso(attempt.expires_at);
        if (
          !Buffer.from(attempt.wallet_ref_lookup as Uint8Array).equals(
            crypto.hmacWalletRefLookup(wallet.caip10),
          ) ||
          wallet.chainId !== String(attempt.chain_id)
        ) {
          return refusedChallenges("enrollment_invalid");
        }
        const address = wallet.address;
        const siweMessage = buildSiweEnrollmentMessage(
          buildSiweFields(attempt, {
            challengeId: walletChallengeId,
            possessionChallengeId,
            accountId,
            nonce,
            notBefore,
            expiresAt,
            jkt,
            fingerprint,
            keyPackageRef,
            keyPackageSha256,
            address,
          }),
        );
        const payloadDigest = sha256(siweMessage);
        const possessionDigest = computePossessionChallengeDigest({
          walletChallengeId,
          walletPayloadDigest: payloadDigest,
          possessionChallengeId,
          serverNonce,
          enrollmentId,
          accountId,
          chainId: String(attempt.chain_id),
          installationId: String(attempt.preallocated_installation_id),
          deviceCredentialId: String(attempt.preallocated_device_credential_id),
          installationAuthJkt: jkt,
          mlsCredentialFingerprint: fingerprint,
          keyPackageRef,
          keyPackageSha256,
          audience: String(attempt.audience),
          clientId: String(attempt.client_id),
          exactHttpsOrigin: String(attempt.exact_https_origin),
          purpose: String(attempt.purpose),
          scopeDigest: Buffer.from(attempt.scope_hash as Uint8Array),
          notBefore,
          expiresAt,
        });
        const bindingCanonical = JSON.stringify({
          installationAuthPublicJwk: jwk,
          mlsCredentialPublic: b64(mlsPublic),
          keyPackage: b64(keyPackageBytes),
          keyPackageSha256: b64(keyPackageSha256),
        });
        const sealed = crypto.sealPayload(siweMessage);
        await tx`
          UPDATE device_enrollment_attempts SET
            state = 'challenges_issued',
            preallocated_wallet_challenge_id = ${walletChallengeId},
            preallocated_possession_challenge_id = ${possessionChallengeId},
            device_key_binding_canonical = ${bindingCanonical}::jsonb,
            installation_auth_jkt = ${jkt},
            mls_credential_fingerprint = ${fingerprint},
            initial_key_package_ref = ${keyPackageRef},
            initial_key_package_sha256 = ${keyPackageSha256}
          WHERE enrollment_id = ${enrollmentId} AND state = 'allocated'`;
        await tx`
          INSERT INTO enrollment_wallet_challenges (
            challenge_id, enrollment_id, account_id, chain_id, installation_id,
            device_credential_id, possession_challenge_id, profile,
            protocol_profile, exact_payload_ciphertext, payload_digest,
            nonce_hash, audience, client_id, exact_https_origin, purpose,
            scope_hash, installation_auth_jkt, mls_credential_fingerprint,
            key_package_ref, key_package_sha256, issued_at, not_before,
            expires_at, state
          ) VALUES (
            ${walletChallengeId}, ${enrollmentId}, ${accountId},
            ${String(attempt.chain_id)},
            ${String(attempt.preallocated_installation_id)},
            ${String(attempt.preallocated_device_credential_id)},
            ${possessionChallengeId}, ${SIWE_PROOF_PROFILE},
            ${ENROLLMENT_PROTOCOL_PROFILE}, ${sealed.ciphertext},
            ${payloadDigest}, ${crypto.hmacChallengeNonce(nonce)},
            ${String(attempt.audience)}, ${String(attempt.client_id)},
            ${String(attempt.exact_https_origin)}, ${String(attempt.purpose)},
            ${Buffer.from(attempt.scope_hash as Uint8Array)}, ${jkt},
            ${fingerprint}, ${keyPackageRef}, ${keyPackageSha256},
            ${now}::timestamptz, ${notBefore}::timestamptz,
            ${expiresAt}::timestamptz, 'issued'
          )`;
        await tx`
          INSERT INTO device_possession_challenges (
            possession_challenge_id, enrollment_id, wallet_challenge_id,
            wallet_payload_digest, challenge_digest, server_nonce_hash,
            installation_id, device_credential_id, installation_auth_jkt,
            mls_credential_fingerprint, key_package_ref, key_package_sha256,
            account_id, chain_id, audience, client_id, exact_https_origin,
            purpose, scope_hash, issued_at, not_before, expires_at, state
          ) VALUES (
            ${possessionChallengeId}, ${enrollmentId}, ${walletChallengeId},
            ${payloadDigest}, ${possessionDigest},
            ${crypto.hmacChallengeNonce(serverNonce)},
            ${String(attempt.preallocated_installation_id)},
            ${String(attempt.preallocated_device_credential_id)}, ${jkt},
            ${fingerprint}, ${keyPackageRef}, ${keyPackageSha256}, ${accountId},
            ${String(attempt.chain_id)}, ${String(attempt.audience)},
            ${String(attempt.client_id)}, ${String(attempt.exact_https_origin)},
            ${String(attempt.purpose)},
            ${Buffer.from(attempt.scope_hash as Uint8Array)},
            ${now}::timestamptz, ${notBefore}::timestamptz,
            ${expiresAt}::timestamptz, 'issued'
          )`;
        return Object.freeze({
          status: "challenges_issued",
          walletChallengeId,
          possessionChallengeId,
          siweMessage,
          possessionChallengeDigest: b64(possessionDigest),
          notBefore,
          expiresAt,
        });
      });
    },

    async completeEnrollment(
      handleValue: unknown,
      proofValue: unknown,
    ): Promise<EnrollmentCompletion> {
      if (typeof handleValue !== "string" || !HANDLE_PATTERN.test(handleValue)) {
        return Object.freeze({ status: "invalid", reasonCode: "enrollment_invalid" });
      }
      let walletSignature: string;
      let possessionSignature: string;
      try {
        const proof = expectRecord(proofValue, [
          "walletSignature",
          "possessionSignature",
        ]);
        walletSignature = String(proof.walletSignature);
        possessionSignature = String(proof.possessionSignature);
      } catch {
        return Object.freeze({ status: "invalid", reasonCode: "enrollment_invalid" });
      }
      const requestSha256 = sha256(
        JSON.stringify({ walletSignature, possessionSignature }),
      );
      const now = nowIso();

      const claim = await sql.begin(async (tx) => {
        const attempt = await locateAttempt(tx, handleValue);
        if (!attempt) {
          return { kind: "result" as const, result: invalidCompletion() };
        }
        const enrollmentId = String(attempt.enrollment_id);
        const completions = await tx`
          SELECT * FROM enrollment_completion_requests
          WHERE enrollment_id = ${enrollmentId} FOR UPDATE`;
        if (completions.length === 1) {
          const completion = completions[0] as Record<string, unknown>;
          if (
            !Buffer.from(completion.request_sha256 as Uint8Array).equals(requestSha256)
          ) {
            return {
              kind: "result" as const,
              result: Object.freeze({
                status: "conflict" as const,
                reasonCode: "idempotency_conflict" as const,
              }),
            };
          }
          if (completion.state === "claimed" || completion.state === "verifying") {
            return {
              kind: "verify" as const,
              enrollmentId,
              completionId: String(completion.completion_id),
              attempt,
            };
          }
          return {
            kind: "result" as const,
            result: terminalCompletionResult(completion, attempt),
          };
        }
        if (attempt.state !== "challenges_issued") {
          if (
            attempt.state === "allocated" ||
            attempt.state === "expired" ||
            now >= iso(attempt.expires_at)
          ) {
            await expireAttempt(tx, enrollmentId);
            return { kind: "result" as const, result: invalidCompletion() };
          }
          return { kind: "result" as const, result: invalidCompletion() };
        }
        if (now >= iso(attempt.expires_at)) {
          await expireAttempt(tx, enrollmentId);
          return { kind: "result" as const, result: invalidCompletion() };
        }
        const completionId = uuidV7(now);
        await tx`
          INSERT INTO enrollment_completion_requests (
            completion_id, enrollment_id, request_sha256, wallet_challenge_id,
            possession_challenge_id, state, claimed_at
          ) VALUES (
            ${completionId}, ${enrollmentId}, ${requestSha256},
            ${String(attempt.preallocated_wallet_challenge_id)},
            ${String(attempt.preallocated_possession_challenge_id)}, 'claimed',
            ${now}::timestamptz
          )`;
        await tx`
          UPDATE enrollment_wallet_challenges SET state = 'claimed',
            claimed_at = ${now}::timestamptz, claimed_by_completion_id = ${completionId}
          WHERE enrollment_id = ${enrollmentId} AND state = 'issued'`;
        await tx`
          UPDATE device_possession_challenges SET state = 'claimed',
            claimed_at = ${now}::timestamptz, claimed_by_completion_id = ${completionId}
          WHERE enrollment_id = ${enrollmentId} AND state = 'issued'`;
        await tx`
          UPDATE device_enrollment_attempts SET state = 'claimed',
            claimed_at = ${now}::timestamptz
          WHERE enrollment_id = ${enrollmentId} AND state = 'challenges_issued'`;
        return {
          kind: "verify" as const,
          enrollmentId,
          completionId,
          attempt,
        };
      });
      if (claim.kind === "result") return claim.result;

      // Verification happens after the terminal claim commits, never inside it.
      const verdict = await verifyClaim(
        sql,
        context,
        claim.enrollmentId,
        walletSignature,
        possessionSignature,
      );
      return finalizeCompletion(
        sql,
        context,
        claim.enrollmentId,
        claim.completionId,
        verdict,
        nowIso(),
      );
    },

    async readEnrollment(handleValue: unknown): Promise<EnrollmentReadResult> {
      if (typeof handleValue !== "string" || !HANDLE_PATTERN.test(handleValue)) {
        return Object.freeze({ status: "unknown" });
      }
      const rows = await sql`
        SELECT state, expires_at FROM device_enrollment_attempts
        WHERE result_handle_hash = ${crypto.hmacResultHandle(handleValue)}`;
      if (rows.length !== 1) return Object.freeze({ status: "unknown" });
      const state = String(rows[0].state);
      if (["issued", "invalid", "unavailable", "expired"].includes(state)) {
        return Object.freeze({
          status: state as "issued" | "invalid" | "unavailable" | "expired",
        });
      }
      if (nowIso() >= iso(rows[0].expires_at)) {
        return Object.freeze({ status: "expired" });
      }
      return Object.freeze({ status: "pending" });
    },

    async issueSession(inputValue: unknown): Promise<SessionIssueResult> {
      let installationId: string;
      let audience: string;
      let clientId: string;
      try {
        const record = expectRecord(inputValue, [
          "installationId",
          "audience",
          "clientId",
        ]);
        installationId = String(record.installationId);
        audience = String(record.audience);
        clientId = String(record.clientId);
        assertCanonicalAudience(audience);
        if (!CLIENT_ID_PATTERN.test(clientId)) {
          throw new TypeError("Client ID is malformed.");
        }
      } catch {
        return Object.freeze({ status: "refused", reasonCode: "credential_invalid" });
      }
      const now = nowIso();
      return sql.begin(async (tx) => {
        const rows = await tx`
          SELECT c.device_credential_id, c.account_id, c.installation_auth_jkt,
                 c.revocation_version, c.expires_at
          FROM device_credentials c
          WHERE c.installation_id = ${installationId} AND c.status = 'active'
            AND c.expires_at > ${now}::timestamptz`;
        if (rows.length !== 1) {
          return Object.freeze({
            status: "refused" as const,
            reasonCode: "credential_invalid" as const,
          });
        }
        const credential = rows[0];
        const sessionId = uuidV4();
        const tokenFamilyId = uuidV4();
        const accessToken = randomBytes(32).toString("base64url");
        const refreshToken = randomBytes(32).toString("base64url");
        const accessExpiresAt = minIso(
          addMilliseconds(now, ACCESS_TTL_MILLISECONDS),
          iso(credential.expires_at),
        );
        const refreshExpiresAt = minIso(
          addMilliseconds(now, REFRESH_TTL_MILLISECONDS),
          iso(credential.expires_at),
        );
        await tx`
          INSERT INTO auth_sessions (
            session_id, token_family_id, account_id, installation_id,
            device_credential_id, installation_auth_jkt,
            device_credential_revocation_version, audience, client_id,
            session_profile, installation_partition_class, access_token_hash,
            refresh_token_hash, refresh_generation, state, created_at,
            access_expires_at, refresh_expires_at
          ) VALUES (
            ${sessionId}, ${tokenFamilyId}, ${String(credential.account_id)},
            ${installationId}, ${String(credential.device_credential_id)},
            ${Buffer.from(credential.installation_auth_jkt as Uint8Array)},
            ${String(credential.revocation_version)}, ${audience}, ${clientId},
            'native_dpop', 'top_level', ${crypto.hmacAccessToken(accessToken)},
            ${crypto.hmacRefreshToken(refreshToken)}, 0, 'active',
            ${now}::timestamptz, ${accessExpiresAt}::timestamptz,
            ${refreshExpiresAt}::timestamptz
          )`;
        return Object.freeze({
          status: "issued" as const,
          sessionId,
          accessToken,
          refreshToken,
          accessExpiresAt,
          refreshExpiresAt,
        });
      });
    },

    async refreshSession(refreshTokenValue: unknown): Promise<SessionRefreshResult> {
      if (
        typeof refreshTokenValue !== "string" ||
        !HANDLE_PATTERN.test(refreshTokenValue)
      ) {
        return Object.freeze({ status: "refused", reasonCode: "credential_invalid" });
      }
      const now = nowIso();
      return sql.begin(async (tx) => {
        const rows = await tx`
          SELECT s.*, c.status AS credential_status, c.expires_at AS credential_expires_at
          FROM auth_sessions s
          JOIN device_credentials c ON c.device_credential_id = s.device_credential_id
          WHERE s.refresh_token_hash = ${crypto.hmacRefreshToken(refreshTokenValue)}
          FOR UPDATE OF s`;
        if (rows.length !== 1) {
          return Object.freeze({
            status: "refused" as const,
            reasonCode: "credential_invalid" as const,
          });
        }
        const session = rows[0] as Record<string, unknown>;
        if (session.state === "rotated" || session.state === "revoked") {
          await tx`
            UPDATE auth_sessions SET state = 'revoked',
              revoked_at = ${now}::timestamptz,
              revoke_reason = 'refresh-token-reuse'
            WHERE token_family_id = ${String(session.token_family_id)}
              AND state IN ('active', 'rotated')`;
          return Object.freeze({
            status: "revoked" as const,
            reasonCode: "token_family_revoked" as const,
          });
        }
        if (
          session.state !== "active" ||
          now >= iso(session.refresh_expires_at) ||
          session.credential_status !== "active" ||
          now >= iso(session.credential_expires_at)
        ) {
          return Object.freeze({
            status: "refused" as const,
            reasonCode: "credential_invalid" as const,
          });
        }
        await tx`
          UPDATE auth_sessions SET state = 'rotated', rotated_at = ${now}::timestamptz
          WHERE session_id = ${String(session.session_id)}`;
        const sessionId = uuidV4();
        const accessToken = randomBytes(32).toString("base64url");
        const refreshToken = randomBytes(32).toString("base64url");
        const accessExpiresAt = minIso(
          addMilliseconds(now, ACCESS_TTL_MILLISECONDS),
          iso(session.credential_expires_at),
        );
        const refreshExpiresAt = minIso(
          addMilliseconds(now, REFRESH_TTL_MILLISECONDS),
          iso(session.credential_expires_at),
        );
        await tx`
          INSERT INTO auth_sessions (
            session_id, token_family_id, account_id, installation_id,
            device_credential_id, installation_auth_jkt,
            device_credential_revocation_version, audience, client_id,
            session_profile, installation_partition_class, access_token_hash,
            refresh_token_hash, refresh_generation, state, created_at,
            access_expires_at, refresh_expires_at
          ) VALUES (
            ${sessionId}, ${String(session.token_family_id)},
            ${String(session.account_id)}, ${String(session.installation_id)},
            ${String(session.device_credential_id)},
            ${Buffer.from(session.installation_auth_jkt as Uint8Array)},
            ${String(session.device_credential_revocation_version)},
            ${String(session.audience)}, ${String(session.client_id)},
            'native_dpop', 'top_level', ${crypto.hmacAccessToken(accessToken)},
            ${crypto.hmacRefreshToken(refreshToken)},
            ${String(BigInt(String(session.refresh_generation)) + 1n)}, 'active',
            ${now}::timestamptz, ${accessExpiresAt}::timestamptz,
            ${refreshExpiresAt}::timestamptz
          )`;
        return Object.freeze({
          status: "issued" as const,
          sessionId,
          accessToken,
          refreshToken,
          accessExpiresAt,
          refreshExpiresAt,
        });
      });
    },

    async revokeSessionFamily(refreshTokenValue: unknown): Promise<void> {
      if (
        typeof refreshTokenValue !== "string" ||
        !HANDLE_PATTERN.test(refreshTokenValue)
      ) {
        return;
      }
      const now = nowIso();
      await sql`
        UPDATE auth_sessions SET state = 'revoked',
          revoked_at = ${now}::timestamptz, revoke_reason = 'explicit-logout'
        WHERE token_family_id = (
          SELECT token_family_id FROM auth_sessions
          WHERE refresh_token_hash = ${crypto.hmacRefreshToken(refreshTokenValue)}
        ) AND state IN ('active', 'rotated')`;
    },
  });

  async function verifyClaim(
    sqlInstance: Sql,
    storeContext: EnrollmentStoreContext,
    enrollmentId: string,
    walletSignature: string,
    possessionSignature: string,
  ): Promise<
    | { status: "verified"; method: "eoa" | "erc1271" | "erc6492"; finality: NonNullable<unknown>; walletEvidence: Buffer; possessionEvidence: Buffer }
    | { status: "invalid" }
    | { status: "unavailable" }
  > {
    const [attemptRow] = await sqlInstance`
      SELECT * FROM device_enrollment_attempts WHERE enrollment_id = ${enrollmentId}`;
    const attempt = attemptRow as Record<string, unknown>;
    const [walletRow] = await sqlInstance`
      SELECT * FROM enrollment_wallet_challenges WHERE enrollment_id = ${enrollmentId}`;
    const [possessionRow] = await sqlInstance`
      SELECT * FROM device_possession_challenges WHERE enrollment_id = ${enrollmentId}`;
    const bindingCanonical = attempt.device_key_binding_canonical;
    const binding = (
      typeof bindingCanonical === "string"
        ? JSON.parse(bindingCanonical)
        : bindingCanonical
    ) as { installationAuthPublicJwk: unknown };
    const jwk = parseP256PublicJwk(binding.installationAuthPublicJwk);
    const possessionOk = verifyPossessionSignature(
      jwk,
      Buffer.from(possessionRow.challenge_digest as Uint8Array),
      possessionSignature,
    );
    if (!possessionOk) return { status: "invalid" };
    const siweMessage = storeContext.crypto.openPayload(
      Buffer.from(walletRow.exact_payload_ciphertext as Uint8Array),
      "keyed-lab-v1",
    );
    if (!sha256(siweMessage).equals(Buffer.from(walletRow.payload_digest as Uint8Array))) {
      return { status: "invalid" };
    }
    const address = extractSiweAddress(siweMessage);
    const verdict = await storeContext.walletProofVerifier.verify({
      chainId: String(attempt.chain_id),
      address,
      message: siweMessage,
      signature: walletSignature,
    });
    if (verdict.status !== "verified") return { status: verdict.status };
    return {
      status: "verified",
      method: verdict.method,
      finality: verdict.finality,
      walletEvidence: sha256(`wallet:${walletSignature}`),
      possessionEvidence: sha256(`possession:${possessionSignature}`),
    };
  }

  async function finalizeCompletion(
    sqlInstance: Sql,
    storeContext: EnrollmentStoreContext,
    enrollmentId: string,
    completionId: string,
    verdict: Awaited<ReturnType<typeof verifyClaim>>,
    now: string,
  ): Promise<EnrollmentCompletion> {
    return sqlInstance.begin(async (tx) => {
      const [attemptRow] = await tx`
        SELECT * FROM device_enrollment_attempts
        WHERE enrollment_id = ${enrollmentId} FOR UPDATE`;
      const attempt = attemptRow as Record<string, unknown>;
      if (["issued", "invalid", "unavailable"].includes(String(attempt.state))) {
        const [completion] = await tx`
          SELECT * FROM enrollment_completion_requests
          WHERE enrollment_id = ${enrollmentId}`;
        return terminalCompletionResult(
          completion as Record<string, unknown>,
          attempt,
        );
      }
      const purgeAfter = addMilliseconds(now, RESULT_PURGE_MILLISECONDS);
      if (verdict.status !== "verified") {
        const terminalState = verdict.status === "invalid" ? "invalid" : "unavailable";
        const body = storeContext.crypto.sealPayload(
          JSON.stringify({ status: terminalState }),
        );
        await tx`
          UPDATE enrollment_completion_requests SET state = ${terminalState},
            completed_at = ${now}::timestamptz,
            result_status = ${terminalState === "invalid" ? 403 : 503},
            result_body_ciphertext = ${body.ciphertext},
            result_body_sha256 = ${sha256(JSON.stringify({ status: terminalState }))},
            result_kms_key_version = ${body.kmsKeyVersion},
            result_purge_after = ${purgeAfter}::timestamptz
          WHERE completion_id = ${completionId}`;
        await tx`
          UPDATE device_enrollment_attempts SET state = ${terminalState},
            terminal_reason_code = ${
              terminalState === "invalid"
                ? "enrollment_invalid"
                : "enrollment_verification_unavailable"
            },
            completed_at = ${now}::timestamptz
          WHERE enrollment_id = ${enrollmentId}`;
        return terminalState === "invalid"
          ? Object.freeze({
              status: "invalid" as const,
              reasonCode: "enrollment_invalid" as const,
            })
          : Object.freeze({
              status: "unavailable" as const,
              reasonCode: "enrollment_verification_unavailable" as const,
            });
      }

      const accountId = String(attempt.account_id);
      const installationId = String(attempt.preallocated_installation_id);
      const deviceCredentialId = String(attempt.preallocated_device_credential_id);
      const finality = verdict.finality as {
        finalityProfileId: string;
        finalityProfileRevision: string;
        finalityProfileHash: Buffer;
        finalizedChainId: string;
        finalizedBlock: string;
        finalizedBlockHash: Buffer;
        providerQuorumHash: Buffer;
      };
      const binding = attempt.device_key_binding_canonical as
        | string
        | Record<string, unknown>;
      const bindingCanonicalText =
        typeof binding === "string" ? binding : JSON.stringify(binding);
      const bindingRecord = JSON.parse(bindingCanonicalText) as {
        installationAuthPublicJwk: Record<string, string>;
        mlsCredentialPublic: string;
        keyPackage: string;
      };
      const links = await tx`
        SELECT wallet_link_id, account_id FROM wallet_links
        WHERE wallet_ref_lookup = ${Buffer.from(attempt.wallet_ref_lookup as Uint8Array)}`;
      let walletLinkId: string;
      if (links.length === 1) {
        if (String(links[0].account_id) !== accountId) {
          return Object.freeze({
            status: "invalid" as const,
            reasonCode: "enrollment_invalid" as const,
          });
        }
        walletLinkId = String(links[0].wallet_link_id);
      } else {
        walletLinkId = uuidV4();
        await tx`
          INSERT INTO wallet_links (
            wallet_link_id, account_id, wallet_ref_lookup,
            wallet_ref_ciphertext, kms_key_version, status, verified_at
          ) VALUES (
            ${walletLinkId}, ${accountId},
            ${Buffer.from(attempt.wallet_ref_lookup as Uint8Array)},
            ${storeContext.crypto.sealPayload(String(attempt.chain_id)).ciphertext},
            'keyed-lab-v1', 'active', ${now}::timestamptz
          )`;
      }
      await tx`
        UPDATE accounts SET status = 'active'
        WHERE account_id = ${accountId} AND status = 'pending_enrollment'`;
      await tx`
        INSERT INTO installations (
          installation_id, account_id, platform, storage_partition_class,
          installation_auth_profile, installation_auth_public_jwk,
          installation_auth_jkt, mls_credential_profile, mls_credential_public,
          mls_credential_fingerprint, status, created_at, last_seen_at
        ) VALUES (
          ${installationId}, ${accountId}, ${String(attempt.platform)},
          'top_level', 'p256-es256-dpop.v1',
          ${JSON.stringify(bindingRecord.installationAuthPublicJwk)}::jsonb,
          ${Buffer.from(attempt.installation_auth_jkt as Uint8Array)},
          'mls-credential-ed25519-suite-0x0001.v1',
          ${Buffer.from(bindingRecord.mlsCredentialPublic, "base64url")},
          ${Buffer.from(attempt.mls_credential_fingerprint as Uint8Array)},
          'active', ${now}::timestamptz, ${now}::timestamptz
        )`;
      const credentialExpiresAt = addMilliseconds(now, CREDENTIAL_TTL_MILLISECONDS);
      const credentialPayload = Buffer.from(
        JSON.stringify({
          profile: "device-credential.v1",
          deviceCredentialId,
          installationId,
          accountId,
          chainId: String(attempt.chain_id),
          installationAuthJkt: b64(attempt.installation_auth_jkt as Uint8Array),
          mlsCredentialFingerprint: b64(
            attempt.mls_credential_fingerprint as Uint8Array,
          ),
          issuedAt: now,
          expiresAt: credentialExpiresAt,
          revocationVersion: "1",
        }),
        "utf8",
      );
      const credentialSignature =
        storeContext.credentialSigner.sign(credentialPayload);
      await tx`
        INSERT INTO device_credentials (
          device_credential_id, enrollment_id, enrollment_completion_id,
          installation_id, account_id, wallet_link_id, chain_id,
          credential_profile, installation_auth_jkt, mls_credential_fingerprint,
          initial_key_package_ref, initial_key_package_sha256,
          device_key_binding_canonical, device_key_binding_hash,
          wallet_evidence_digest, possession_evidence_digest, issued_at,
          expires_at, revocation_version, signer_key_id,
          canonical_payload_bytes, canonical_payload_digest, signature, status,
          created_at
        ) VALUES (
          ${deviceCredentialId}, ${enrollmentId}, ${completionId},
          ${installationId}, ${accountId}, ${walletLinkId},
          ${String(attempt.chain_id)}, 'device-credential.v1',
          ${Buffer.from(attempt.installation_auth_jkt as Uint8Array)},
          ${Buffer.from(attempt.mls_credential_fingerprint as Uint8Array)},
          ${Buffer.from(attempt.initial_key_package_ref as Uint8Array)},
          ${Buffer.from(attempt.initial_key_package_sha256 as Uint8Array)},
          ${bindingCanonicalText}::jsonb, ${sha256(bindingCanonicalText)},
          ${verdict.walletEvidence}, ${verdict.possessionEvidence},
          ${now}::timestamptz, ${credentialExpiresAt}::timestamptz, 1,
          ${storeContext.credentialSigner.signerKeyId}, ${credentialPayload},
          ${sha256Bytes(credentialPayload)}, ${credentialSignature}, 'active',
          ${now}::timestamptz
        )`;
      await tx`
        INSERT INTO key_packages (
          key_package_ref, installation_id, device_credential_id,
          device_credential_revocation_version, release_profile_id,
          package_bytes, package_sha256, mls_credential_fingerprint, state,
          created_at, expires_at
        ) VALUES (
          ${Buffer.from(attempt.initial_key_package_ref as Uint8Array)},
          ${installationId}, ${deviceCredentialId}, 1,
          'device-enrollment-initial.v1',
          ${Buffer.from(bindingRecord.keyPackage, "base64url")},
          ${Buffer.from(attempt.initial_key_package_sha256 as Uint8Array)},
          ${Buffer.from(attempt.mls_credential_fingerprint as Uint8Array)},
          'available', ${now}::timestamptz, ${credentialExpiresAt}::timestamptz
        )`;
      const resultBody = JSON.stringify({
        status: "issued",
        accountId,
        installationId,
        deviceCredentialId,
      });
      const sealedResult = storeContext.crypto.sealPayload(resultBody);
      await tx`
        UPDATE enrollment_completion_requests SET state = 'issued',
          completed_at = ${now}::timestamptz,
          wallet_verification_method = ${verdict.method},
          finality_status = 'verified-finalized',
          finality_profile_id = ${finality.finalityProfileId},
          finality_profile_revision = ${finality.finalityProfileRevision},
          finality_profile_hash = ${finality.finalityProfileHash},
          finalized_chain_id = ${finality.finalizedChainId},
          finalized_block = ${finality.finalizedBlock},
          finalized_block_hash = ${finality.finalizedBlockHash},
          provider_quorum_hash = ${finality.providerQuorumHash},
          wallet_evidence_digest = ${verdict.walletEvidence},
          possession_evidence_digest = ${verdict.possessionEvidence},
          result_status = 200, result_body_ciphertext = ${sealedResult.ciphertext},
          result_body_sha256 = ${sha256(resultBody)},
          result_kms_key_version = ${sealedResult.kmsKeyVersion},
          result_purge_after = ${purgeAfter}::timestamptz
        WHERE completion_id = ${completionId}`;
      await tx`
        UPDATE device_enrollment_attempts SET state = 'issued',
          terminal_reason_code = 'issued', completed_at = ${now}::timestamptz
        WHERE enrollment_id = ${enrollmentId}`;
      return Object.freeze({
        status: "issued" as const,
        accountId,
        installationId,
        deviceCredentialId,
        walletVerificationMethod: verdict.method,
      });
    });
  }

  function terminalCompletionResult(
    completion: Record<string, unknown>,
    attempt: Record<string, unknown>,
  ): EnrollmentCompletion {
    const state = String(completion.state);
    if (state === "issued") {
      const body = JSON.parse(
        crypto.openPayload(
          Buffer.from(completion.result_body_ciphertext as Uint8Array),
          String(completion.result_kms_key_version),
        ),
      ) as { accountId: string; installationId: string; deviceCredentialId: string };
      return Object.freeze({
        status: "issued",
        accountId: body.accountId,
        installationId: body.installationId,
        deviceCredentialId: body.deviceCredentialId,
        walletVerificationMethod: String(
          completion.wallet_verification_method,
        ) as "eoa" | "erc1271" | "erc6492",
      });
    }
    if (state === "unavailable") {
      return Object.freeze({
        status: "unavailable",
        reasonCode: "enrollment_verification_unavailable",
      });
    }
    void attempt;
    return invalidCompletion();
  }
}

function invalidCompletion(): EnrollmentCompletion {
  return Object.freeze({ status: "invalid", reasonCode: "enrollment_invalid" });
}

function refusedChallenges(
  reasonCode: "enrollment_invalid" | "enrollment_expired",
): EnrollmentChallenges {
  return Object.freeze({ status: "refused", reasonCode });
}

function expectRecord(
  value: unknown,
  keys: readonly string[],
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("Enrollment input must be a plain record.");
  }
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== keys.length ||
    keys.some((key) => !Object.prototype.hasOwnProperty.call(value, key))
  ) {
    throw new TypeError("Enrollment input has an unexpected shape.");
  }
  return value as Record<string, unknown>;
}

function parseOneOf<const T extends string>(
  value: unknown,
  values: readonly T[],
): T {
  if (!values.includes(value as T)) {
    throw new TypeError("Enrollment input value is unsupported.");
  }
  return value as T;
}

function assertCanonicalHttpsOrigin(value: string): void {
  const url = new URL(value);
  if (
    url.origin !== value ||
    url.protocol !== "https:" ||
    url.port !== "" ||
    url.username !== "" ||
    url.password !== "" ||
    !/^[a-z0-9.-]+$/.test(url.hostname) ||
    !url.hostname.includes(".")
  ) {
    throw new TypeError("Origin is not a canonical HTTPS origin.");
  }
}

function assertCanonicalAudience(value: string): void {
  const url = new URL(value);
  assertCanonicalHttpsOrigin(url.origin);
  if (url.search !== "" || url.hash !== "" || `${url.origin}${url.pathname}` !== value) {
    throw new TypeError("Audience is not a canonical HTTPS URL path.");
  }
}

function extractSiweAddress(message: string): string {
  const line = message.split("\n")[1] ?? "";
  if (!/^0x[0-9a-fA-F]{40}$/.test(line)) {
    throw new TypeError("The stored SIWE payload is malformed.");
  }
  return line.toLowerCase();
}

function sha256(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

function sha256Bytes(value: Buffer): Buffer {
  return createHash("sha256").update(value).digest();
}

function exactBytes(value: unknown, length: number): Buffer {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new TypeError("Expected base64url bytes.");
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.byteLength !== length) {
    throw new TypeError("Byte payload has the wrong length.");
  }
  return bytes;
}

function boundedBytes(value: unknown, minimum: number, maximum: number): Buffer {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new TypeError("Expected base64url bytes.");
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.byteLength < minimum || bytes.byteLength > maximum) {
    throw new TypeError("Byte payload is outside its bounds.");
  }
  return bytes;
}

function b64(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

function iso(value: unknown): string {
  return new Date(value as string | Date).toISOString();
}

function addMilliseconds(value: string, milliseconds: number): string {
  return new Date(Date.parse(value) + milliseconds).toISOString();
}

function minIso(left: string, right: string): string {
  return left < right ? left : right;
}

function uuidV4(): string {
  const bytes = randomBytes(16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  return formatUuid(bytes);
}

function uuidV7(nowIsoValue: string): string {
  const bytes = randomBytes(16);
  const milliseconds = BigInt(Date.parse(nowIsoValue));
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = Number((milliseconds >> BigInt((5 - index) * 8)) & 0xffn);
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  return formatUuid(bytes);
}

function formatUuid(bytes: Buffer): string {
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
