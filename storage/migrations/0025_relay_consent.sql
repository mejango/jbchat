-- 0025: relay-shaped rows for ADR 0006 phase 2.
--
-- A relay is a service-operated installation: it has an MLS credential and
-- KeyPackages but no device credential (it never enrolls a wallet and
-- never holds a DPoP session), and it is admitted to a conversation by a
-- consent grant the served member mints - not by chain-finality evidence.
-- Rather than fabricating an enrollment chain or a finality anchor, the
-- schema says what a relay row is: a KeyPackage of kind
-- 'relay-mls-key-package.v1' carries no device credential, and a grant of
-- capability 'channel-relay' carries no finality anchor and a
-- finality_status of 'not-applicable'. Every other row keeps every
-- existing constraint.

-- key_packages: the relay kind, and the credential columns nullable ONLY
-- for that kind. The composite FK to device_credentials is MATCH SIMPLE,
-- so NULL credential columns are not checked against it.
DO $$
DECLARE
  name text;
BEGIN
  SELECT conname INTO name FROM pg_constraint
  WHERE conrelid = 'key_packages'::regclass
    AND pg_get_constraintdef(oid) LIKE '%ordinary-mls-key-package.v1%';
  IF name IS NOT NULL THEN
    EXECUTE format('ALTER TABLE key_packages DROP CONSTRAINT %I', name);
  END IF;
END $$;
ALTER TABLE key_packages
  ALTER COLUMN device_credential_id DROP NOT NULL,
  ALTER COLUMN device_credential_revocation_version DROP NOT NULL,
  ADD CONSTRAINT key_packages_package_kind_check CHECK (
    package_kind IN ('ordinary-mls-key-package.v1', 'relay-mls-key-package.v1')
  ),
  ADD CONSTRAINT key_packages_relay_kind_has_no_credential_check CHECK (
    (package_kind = 'relay-mls-key-package.v1') = (device_credential_id IS NULL)
  ),
  ADD CONSTRAINT key_packages_credential_columns_paired_check CHECK (
    (device_credential_id IS NULL) = (device_credential_revocation_version IS NULL)
  );

-- eligibility_grants: the channel-relay capability, and the finality
-- anchor absent ONLY for it.
DO $$
DECLARE
  name text;
BEGIN
  FOR name IN
    SELECT conname FROM pg_constraint
    WHERE conrelid = 'eligibility_grants'::regclass
      AND contype = 'c'
      AND (
        pg_get_constraintdef(oid) LIKE '%purchase-support%'
        OR pg_get_constraintdef(oid) LIKE '%verified-finalized%'
      )
  LOOP
    EXECUTE format('ALTER TABLE eligibility_grants DROP CONSTRAINT %I', name);
  END LOOP;
END $$;
ALTER TABLE eligibility_grants
  ALTER COLUMN finality_profile_id DROP NOT NULL,
  ALTER COLUMN finality_profile_revision DROP NOT NULL,
  ALTER COLUMN finality_profile_hash DROP NOT NULL,
  ALTER COLUMN finality_evidence_digest DROP NOT NULL,
  ALTER COLUMN source_chain_id DROP NOT NULL,
  ALTER COLUMN source_block DROP NOT NULL,
  ALTER COLUMN source_block_hash DROP NOT NULL,
  ADD CONSTRAINT eligibility_grants_capability_check CHECK (
    capability IN (
      'purchase-support', 'project-staff', 'token-holder', 'item-set-buyer',
      'channel-relay'
    )
  ),
  ADD CONSTRAINT eligibility_grants_finality_status_check CHECK (
    finality_status IN ('verified-finalized', 'unavailable', 'orphaned', 'not-applicable')
  ),
  ADD CONSTRAINT eligibility_grants_active_is_finalized_check CHECK (
    state <> 'active' OR finality_status IN ('verified-finalized', 'not-applicable')
  ),
  ADD CONSTRAINT eligibility_grants_relay_has_no_anchor_check CHECK (
    (capability = 'channel-relay') = (finality_status = 'not-applicable')
  ),
  ADD CONSTRAINT eligibility_grants_anchor_columns_check CHECK (
    (finality_status = 'not-applicable') = (
      finality_profile_id IS NULL AND finality_profile_revision IS NULL
      AND finality_profile_hash IS NULL AND finality_evidence_digest IS NULL
      AND source_chain_id IS NULL AND source_block IS NULL
      AND source_block_hash IS NULL
    )
  );
