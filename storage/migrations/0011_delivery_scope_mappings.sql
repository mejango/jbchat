-- 0011: Authoritative realm/project/tenant/quota-scope mappings.
--
-- The storage spec requires authoritative realm/project/tenant/quota-scope
-- mappings rather than caller-supplied or mutable JSON convention.
-- delivery_realms is the realm registry; conversations carry their realm
-- and scope identifiers relationally, and a composite unique lets every
-- append-lane row be fenced to its conversation's exact realm by foreign
-- key, so a caller-supplied realm that disagrees with the conversation's
-- registration is a constraint violation, not a code-path convention.
-- quota_scopes resolves each quota counter's scope hash to the realm-bound
-- subject it was derived from, making the keyed hash recomputable evidence
-- instead of an opaque byte string.
--
-- Every altered table is empty in a pre-G2 database. This migration asserts
-- that instead of silently skipping the expand/backfill/contract pattern a
-- populated database would require.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM conversations)
    OR EXISTS (SELECT 1 FROM quota_counters) THEN
    RAISE EXCEPTION
      'migration 0011 requires an expand/backfill/contract plan for populated databases';
  END IF;
END $$;

CREATE TABLE delivery_realms (
  realm_id text PRIMARY KEY CHECK (octet_length(realm_id) BETWEEN 1 AND 64),
  tenant_id uuid NOT NULL REFERENCES tenants(tenant_id),
  created_at timestamptz NOT NULL
);

ALTER TABLE conversations
  ADD COLUMN realm_id text NOT NULL REFERENCES delivery_realms(realm_id),
  ADD COLUMN project_scope_id text NOT NULL
    CHECK (octet_length(project_scope_id) BETWEEN 1 AND 64),
  ADD COLUMN tenant_scope_id text NOT NULL
    CHECK (octet_length(tenant_scope_id) BETWEEN 1 AND 64),
  ADD CONSTRAINT conversations_realm_binding UNIQUE (conversation_id, realm_id);

ALTER TABLE delivery_conversation_authority
  ADD CONSTRAINT delivery_conversation_authority_realm_fk
    FOREIGN KEY (realm_id) REFERENCES delivery_realms(realm_id),
  ADD CONSTRAINT delivery_conversation_authority_conversation_realm_fk
    FOREIGN KEY (conversation_id, realm_id)
    REFERENCES conversations(conversation_id, realm_id);

ALTER TABLE application_append_pendings
  ADD CONSTRAINT application_append_pendings_realm_fk
    FOREIGN KEY (realm_id) REFERENCES delivery_realms(realm_id),
  ADD CONSTRAINT application_append_pendings_conversation_realm_fk
    FOREIGN KEY (conversation_id, realm_id)
    REFERENCES conversations(conversation_id, realm_id);

ALTER TABLE application_append_acceptances
  ADD CONSTRAINT application_append_acceptances_realm_fk
    FOREIGN KEY (realm_id) REFERENCES delivery_realms(realm_id),
  ADD CONSTRAINT application_append_acceptances_conversation_realm_fk
    FOREIGN KEY (conversation_id, realm_id)
    REFERENCES conversations(conversation_id, realm_id);

ALTER TABLE application_append_http_idempotency
  ADD CONSTRAINT application_append_http_idempotency_realm_fk
    FOREIGN KEY (realm_id) REFERENCES delivery_realms(realm_id),
  ADD CONSTRAINT application_append_http_idempotency_conversation_realm_fk
    FOREIGN KEY (conversation_id, realm_id)
    REFERENCES conversations(conversation_id, realm_id);

CREATE TABLE quota_scopes (
  scope_type text NOT NULL CHECK (scope_type IN (
    'installation', 'account', 'project', 'conversation', 'tenant'
  )),
  scope_hash bytea NOT NULL CHECK (octet_length(scope_hash) = 32),
  realm_id text NOT NULL REFERENCES delivery_realms(realm_id),
  subject_id text NOT NULL CHECK (octet_length(subject_id) BETWEEN 1 AND 128),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (scope_type, scope_hash),
  UNIQUE (realm_id, scope_type, subject_id)
);

ALTER TABLE quota_counters
  ADD CONSTRAINT quota_counters_scope_fk
    FOREIGN KEY (scope_type, scope_hash)
    REFERENCES quota_scopes(scope_type, scope_hash);
