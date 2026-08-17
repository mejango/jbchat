-- storage-and-retention.md section 3 requires normalizing roster_canonical
-- into relational plan members keyed by (plan_id, installation_id): a closed
-- role set, creator/no-package or welcome/non-null-package shape, welcome
-- KeyPackage takes bound to this exact plan, and a composite deferred
-- constraint binding the plan's creator tuple to exactly one creator row.

ALTER TABLE key_packages ADD CONSTRAINT key_packages_ref_taken_plan_key
  UNIQUE (key_package_ref, taken_by_plan_id);

CREATE TABLE conversation_plan_members (
  plan_id uuid NOT NULL REFERENCES conversation_plans(plan_id),
  installation_id uuid NOT NULL REFERENCES installations(installation_id),
  account_id uuid NOT NULL REFERENCES accounts(account_id),
  role text NOT NULL CHECK (role IN (
    'customer', 'project-staff', 'publisher', 'subscriber', 'member', 'moderator'
  )),
  bootstrap_mode text NOT NULL CHECK (bootstrap_mode IN ('creator', 'welcome')),
  mls_credential_fingerprint bytea NOT NULL
    CHECK (octet_length(mls_credential_fingerprint) = 32),
  key_package_ref bytea CHECK (
    key_package_ref IS NULL OR octet_length(key_package_ref) = 32
  ),
  PRIMARY KEY (plan_id, installation_id),
  UNIQUE (plan_id, installation_id, bootstrap_mode),
  CHECK ((bootstrap_mode = 'creator') = (key_package_ref IS NULL)),
  FOREIGN KEY (installation_id, account_id)
    REFERENCES installations(installation_id, account_id),
  FOREIGN KEY (key_package_ref, plan_id)
    REFERENCES key_packages(key_package_ref, taken_by_plan_id)
);

CREATE UNIQUE INDEX conversation_plan_members_one_creator_idx
  ON conversation_plan_members(plan_id) WHERE bootstrap_mode = 'creator';

-- The constant-valued column lets the plan row hold a composite deferred
-- foreign key onto its own creator member row, so a plan cannot commit
-- without exactly one creator-mode member for its creator installation.
ALTER TABLE conversation_plans ADD COLUMN creator_bootstrap_mode text
  NOT NULL DEFAULT 'creator' CHECK (creator_bootstrap_mode = 'creator');

ALTER TABLE conversation_plans
  ADD CONSTRAINT conversation_plans_exactly_one_creator_member_fk
  FOREIGN KEY (plan_id, creator_installation_id, creator_bootstrap_mode)
  REFERENCES conversation_plan_members(plan_id, installation_id, bootstrap_mode)
  DEFERRABLE INITIALLY DEFERRED;
