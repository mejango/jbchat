import { Buffer } from "node:buffer";
import { createHash, generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import type { Sql, TransactionSql } from "postgres";
import {
  computeKeyPackageRef,
  computeMlsCredentialFingerprint,
} from "../identity/identityCrypto";

/**
 * ADR 0006 relay installations: one service-operated MLS member per
 * (served account, channel kind). The relay is a REAL installation - its
 * credential and KeyPackages live in the normal tables (migration 0025
 * shapes the KeyPackage row for an installation without a device
 * credential) - owned by its own service account; its MLS client state is
 * the bridge's snapshot, sealed with the identity secret in
 * relay_installations. Every state mutation runs under FOR UPDATE of that
 * row and replaces the whole snapshot (the bridge is stateless).
 */

export const RELAY_KEY_PACKAGE_KIND = "relay-mls-key-package.v1";
export const RELAY_RELEASE_PROFILE_ID = "relay-mls-v1";
const KEY_PACKAGE_TTL_MILLISECONDS = 7 * 24 * 60 * 60 * 1_000;
export const RELAY_CHANNEL_KINDS = ["telegram", "email", "whatsapp"] as const;
export type RelayChannelKind = (typeof RELAY_CHANNEL_KINDS)[number];

/** The state-threading bridge verbs a relay drives (bridgeClient.ts). */
export interface RelayBridgePort {
  readonly createIdentity: (
    label: string,
  ) => Promise<{ state: string; signaturePublicKey: string }>;
  readonly generateKeyPackage: (
    state: string,
  ) => Promise<{ state: string; keyPackage: string }>;
  readonly joinWelcome: (
    state: string,
    welcomeBase64Url: string,
  ) => Promise<{ state: string; groupId: string }>;
  readonly sealApplication: (
    state: string,
    groupIdBase64Url: string,
    plaintext: Uint8Array,
  ) => Promise<{ state: string; message: string }>;
  readonly openApplication: (
    state: string,
    groupIdBase64Url: string,
    messageBase64Url: string,
  ) => Promise<{ state: string; plaintext: Uint8Array }>;
  readonly processCommit: (
    state: string,
    groupIdBase64Url: string,
    commitBase64Url: string,
  ) => Promise<{ state: string }>;
}

/** The sealed snapshot is bound to its relay_installation_id as AAD. */
export interface RelaySealPort {
  readonly sealPayloadBound: (
    plaintext: string,
    associatedData: string,
  ) => { readonly ciphertext: Buffer; readonly kmsKeyVersion: string };
  readonly openPayloadBound: (
    ciphertext: Buffer,
    kmsKeyVersion: string,
    associatedData: string,
  ) => string;
}

export function relayStateAad(relayInstallationId: string): string {
  return `jbm-relay-mls-state/v1:${relayInstallationId}`;
}

export interface RelayInstallationStoreContext {
  readonly sql: Sql;
  readonly bridge: RelayBridgePort;
  readonly seal: RelaySealPort;
}

export interface RelaySeat {
  readonly installationId: string;
  readonly servedAccountId: string;
  readonly channelKind: string;
  readonly role: string;
}

export interface RelayInstallationStore {
  readonly provision: (input: {
    readonly servedAccountId: string;
    readonly channelKind: RelayChannelKind;
  }) => Promise<{
    readonly relayInstallationId: string;
    readonly relayAccountId: string;
    readonly created: boolean;
  }>;
  readonly activeFor: (
    servedAccountId: string,
    channelKind: string,
  ) => Promise<{ relayInstallationId: string; relayAccountId: string } | null>;
  /** Live relay members of a conversation, whoever they serve. */
  readonly seatsForConversation: (conversationId: string) => Promise<RelaySeat[]>;
  readonly revoke: (relayInstallationId: string) => Promise<boolean>;
  /** Every active relay with the account it serves. */
  readonly listActive: () => Promise<
    { relayInstallationId: string; servedAccountId: string; channelKind: string }[]
  >;
  /**
   * Runs `mutate` against the relay's unsealed MLS state under FOR UPDATE
   * of its row and reseals whatever state comes back - the only way relay
   * state ever changes (0024: keeper drain and webhook serialize here).
   */
  readonly withState: <T>(
    relayInstallationId: string,
    mutate: (state: string, tx: TransactionSql) => Promise<{ state: string; result: T }>,
  ) => Promise<T>;
}

export function createRelayInstallationStore(
  context: RelayInstallationStoreContext,
): RelayInstallationStore {
  const { sql, bridge, seal } = context;

  const dbNow = async (tx: TransactionSql): Promise<string> => {
    const rows = await tx`SELECT delivery_db_now() AS db_now`;
    return new Date(rows[0].db_now as Date).toISOString();
  };

  const insertKeyPackage = async (
    tx: TransactionSql,
    relayInstallationId: string,
    fingerprint: Buffer,
    keyPackageBase64Url: string,
    now: string,
  ): Promise<void> => {
    const bytes = Buffer.from(keyPackageBase64Url, "base64url");
    if (bytes.length === 0 || bytes.length > 65536) {
      throw new Error("The bridge returned an out-of-range KeyPackage.");
    }
    const expiresAt = new Date(
      Date.parse(now) + KEY_PACKAGE_TTL_MILLISECONDS,
    ).toISOString();
    await tx`
      INSERT INTO key_packages (
        key_package_ref, installation_id, device_credential_id,
        device_credential_revocation_version, release_profile_id,
        package_bytes, package_sha256, mls_credential_fingerprint,
        package_kind, state, created_at, expires_at
      ) VALUES (
        ${computeKeyPackageRef(bytes)}, ${relayInstallationId}, ${null},
        ${null}, ${RELAY_RELEASE_PROFILE_ID}, ${bytes},
        ${createHash("sha256").update(bytes).digest()}, ${fingerprint},
        ${RELAY_KEY_PACKAGE_KIND}, 'available', ${now}::timestamptz,
        ${expiresAt}::timestamptz
      ) ON CONFLICT (key_package_ref) DO NOTHING`;
  };

  return Object.freeze({
    async provision(input: {
      readonly servedAccountId: string;
      readonly channelKind: RelayChannelKind;
    }) {
      if (!RELAY_CHANNEL_KINDS.includes(input.channelKind)) {
        throw new TypeError("Unsupported relay channel kind.");
      }
      return sql.begin(async (tx) => {
        const now = await dbNow(tx);
        const existing = await tx`
          SELECT r.relay_installation_id, r.mls_state_ciphertext,
                 r.kms_key_version, i.account_id, i.mls_credential_fingerprint
          FROM relay_installations r
          JOIN installations i ON i.installation_id = r.relay_installation_id
          WHERE r.served_account_id = ${input.servedAccountId}
            AND r.channel_kind = ${input.channelKind}
            AND r.state = 'active'
          FOR UPDATE OF r`;
        if (existing.length === 1) {
          const relay = existing[0];
          const relayInstallationId = String(relay.relay_installation_id);
          // Intents consume KeyPackages irreversibly; keep one on the shelf.
          const shelf = await tx`
            SELECT 1 FROM key_packages
            WHERE installation_id = ${relayInstallationId}
              AND state = 'available' AND taken_at IS NULL
              AND expires_at > ${now}::timestamptz`;
          if (shelf.length === 0) {
            if (relay.mls_state_ciphertext === null) {
              throw new Error("Relay installation has no sealed MLS state.");
            }
            const state = seal.openPayloadBound(
              Buffer.from(relay.mls_state_ciphertext as Uint8Array),
              String(relay.kms_key_version),
              relayStateAad(relayInstallationId),
            );
            const generated = await bridge.generateKeyPackage(state);
            await insertKeyPackage(
              tx,
              relayInstallationId,
              Buffer.from(relay.mls_credential_fingerprint as Uint8Array),
              generated.keyPackage,
              now,
            );
            const sealed = seal.sealPayloadBound(
              generated.state,
              relayStateAad(relayInstallationId),
            );
            await tx`
              UPDATE relay_installations SET
                mls_state_ciphertext = ${sealed.ciphertext},
                kms_key_version = ${sealed.kmsKeyVersion},
                updated_at = ${now}::timestamptz
              WHERE relay_installation_id = ${relayInstallationId}`;
          }
          return Object.freeze({
            relayInstallationId,
            relayAccountId: String(relay.account_id),
            created: false,
          });
        }

        const relayAccountId = randomUUID();
        const relayInstallationId = randomUUID();
        // Bridge label: [a-z0-9-]{1,24}; the suffix keeps labels distinct
        // without leaking the served account.
        const label = `relay-${input.channelKind.slice(0, 2)}-${randomBytes(6).toString("hex")}`;
        const identity = await bridge.createIdentity(label);
        const signaturePublicKey = Buffer.from(
          identity.signaturePublicKey,
          "base64url",
        );
        if (signaturePublicKey.length !== 32) {
          throw new Error("The bridge returned a malformed signature key.");
        }
        const fingerprint = computeMlsCredentialFingerprint(signaturePublicKey);
        const generated = await bridge.generateKeyPackage(identity.state);
        // The installation row demands a DPoP auth key; the relay never
        // opens a session, so the key is minted and discarded.
        const authKey = generateKeyPairSync("ec", { namedCurve: "P-256" });
        const authJwk = authKey.publicKey.export({ format: "jwk" });
        const jkt = createHash("sha256")
          .update(
            JSON.stringify({
              crv: authJwk.crv,
              kty: authJwk.kty,
              x: authJwk.x,
              y: authJwk.y,
            }),
          )
          .digest();
        await tx`
          INSERT INTO accounts (account_id, status, created_at)
          VALUES (${relayAccountId}, 'active', ${now}::timestamptz)`;
        await tx`
          INSERT INTO installations (
            installation_id, account_id, platform, storage_partition_class,
            installation_auth_profile, installation_auth_public_jwk,
            installation_auth_jkt, mls_credential_profile, mls_credential_public,
            mls_credential_fingerprint, status, created_at, last_seen_at
          ) VALUES (
            ${relayInstallationId}, ${relayAccountId}, 'desktop', 'top_level',
            'p256-es256-dpop.v1', ${JSON.stringify(authJwk)}::jsonb, ${jkt},
            'mls-credential-ed25519-suite-0x0001.v1', ${signaturePublicKey},
            ${fingerprint}, 'active', ${now}::timestamptz, ${now}::timestamptz
          )`;
        await insertKeyPackage(
          tx,
          relayInstallationId,
          fingerprint,
          generated.keyPackage,
          now,
        );
        const sealed = seal.sealPayloadBound(
          generated.state,
          relayStateAad(relayInstallationId),
        );
        await tx`
          INSERT INTO relay_installations (
            relay_installation_id, served_account_id, channel_kind,
            mls_state_ciphertext, kms_key_version, state, created_at,
            updated_at
          ) VALUES (
            ${relayInstallationId}, ${input.servedAccountId},
            ${input.channelKind}, ${sealed.ciphertext}, ${sealed.kmsKeyVersion},
            'active', ${now}::timestamptz, ${now}::timestamptz
          )`;
        return Object.freeze({
          relayInstallationId,
          relayAccountId,
          created: true,
        });
      });
    },

    async activeFor(servedAccountId: string, channelKind: string) {
      const rows = await sql`
        SELECT r.relay_installation_id, i.account_id
        FROM relay_installations r
        JOIN installations i ON i.installation_id = r.relay_installation_id
        WHERE r.served_account_id = ${servedAccountId}
          AND r.channel_kind = ${channelKind}
          AND r.state = 'active'`;
      if (rows.length !== 1) return null;
      return {
        relayInstallationId: String(rows[0].relay_installation_id),
        relayAccountId: String(rows[0].account_id),
      };
    },

    async seatsForConversation(conversationId: string) {
      const rows = await sql`
        SELECT m.installation_id, m.role, r.served_account_id, r.channel_kind
        FROM memberships m
        JOIN relay_installations r
          ON r.relay_installation_id = m.installation_id
        WHERE m.conversation_id = ${conversationId}
          AND m.removed_at IS NULL
          AND r.state = 'active'
        ORDER BY m.installation_id`;
      return rows.map((row) =>
        Object.freeze({
          installationId: String(row.installation_id),
          servedAccountId: String(row.served_account_id),
          channelKind: String(row.channel_kind),
          role: String(row.role),
        }),
      );
    },

    async listActive() {
      const rows = await sql`
        SELECT relay_installation_id, served_account_id, channel_kind
        FROM relay_installations WHERE state = 'active'
        ORDER BY created_at`;
      return rows.map((row) => ({
        relayInstallationId: String(row.relay_installation_id),
        servedAccountId: String(row.served_account_id),
        channelKind: String(row.channel_kind),
      }));
    },

    async withState<T>(
      relayInstallationId: string,
      mutate: (state: string, tx: TransactionSql) => Promise<{ state: string; result: T }>,
    ): Promise<T> {
      const outcome = await sql.begin(async (tx) => {
        const now = await dbNow(tx);
        const rows = await tx`
          SELECT mls_state_ciphertext, kms_key_version FROM relay_installations
          WHERE relay_installation_id = ${relayInstallationId}
            AND state = 'active'
          FOR UPDATE`;
        if (rows.length !== 1 || rows[0].mls_state_ciphertext === null) {
          throw new Error("Relay installation has no sealed MLS state.");
        }
        const state = seal.openPayloadBound(
          Buffer.from(rows[0].mls_state_ciphertext as Uint8Array),
          String(rows[0].kms_key_version),
          relayStateAad(relayInstallationId),
        );
        const mutated = await mutate(state, tx);
        if (mutated.state !== state) {
          const sealed = seal.sealPayloadBound(
            mutated.state,
            relayStateAad(relayInstallationId),
          );
          await tx`
            UPDATE relay_installations SET
              mls_state_ciphertext = ${sealed.ciphertext},
              kms_key_version = ${sealed.kmsKeyVersion},
              updated_at = ${now}::timestamptz
            WHERE relay_installation_id = ${relayInstallationId}`;
        }
        return { result: mutated.result };
      });
      return (outcome as { result: T }).result;
    },

    async revoke(relayInstallationId: string) {
      return sql.begin(async (tx) => {
        const now = await dbNow(tx);
        const revoked = await tx`
          UPDATE relay_installations SET
            state = 'revoked', revoked_at = ${now}::timestamptz,
            updated_at = ${now}::timestamptz
          WHERE relay_installation_id = ${relayInstallationId}
            AND state = 'active'
          RETURNING relay_installation_id`;
        if (revoked.length !== 1) return false;
        await tx`
          UPDATE installations SET
            status = 'revoked', revoked_at = ${now}::timestamptz
          WHERE installation_id = ${relayInstallationId}`;
        await tx`
          UPDATE key_packages SET
            state = 'revoked', package_bytes = NULL,
            destroyed_at = ${now}::timestamptz, revoked_at = ${now}::timestamptz
          WHERE installation_id = ${relayInstallationId}
            AND state = 'available'`;
        return true;
      });
    },
  });
}
