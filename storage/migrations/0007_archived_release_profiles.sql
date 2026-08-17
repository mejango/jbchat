-- storage-and-retention.md section 1 and the conversations-table note: an
-- immutable archived release-profile/full-DeliveryLimits registry, with
-- digest/trust-root foreign keys from plans and generations. Accepted
-- envelopes and staged intents inherit the pin through their generation row.

CREATE TABLE archived_release_profiles (
  release_profile_id text NOT NULL CHECK (octet_length(release_profile_id) BETWEEN 1 AND 64),
  delivery_limits_digest bytea NOT NULL CHECK (octet_length(delivery_limits_digest) = 32),
  release_trust_root_digest bytea NOT NULL CHECK (octet_length(release_trust_root_digest) = 32),
  delivery_limits_canonical jsonb NOT NULL,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (release_profile_id, delivery_limits_digest, release_trust_root_digest)
);

CREATE FUNCTION archived_release_profiles_are_immutable() RETURNS trigger
LANGUAGE plpgsql AS $immutable$
BEGIN
  RAISE EXCEPTION 'archived_release_profiles rows are immutable';
END;
$immutable$;

CREATE TRIGGER archived_release_profiles_immutable_trigger
  BEFORE UPDATE OR DELETE ON archived_release_profiles
  FOR EACH ROW EXECUTE FUNCTION archived_release_profiles_are_immutable();

ALTER TABLE conversation_plans ADD CONSTRAINT conversation_plans_release_profile_fk
  FOREIGN KEY (release_profile_id, delivery_limits_digest, release_trust_root_digest)
  REFERENCES archived_release_profiles(release_profile_id, delivery_limits_digest, release_trust_root_digest);

ALTER TABLE conversations ADD CONSTRAINT conversations_release_profile_fk
  FOREIGN KEY (release_profile_id, delivery_limits_digest, release_trust_root_digest)
  REFERENCES archived_release_profiles(release_profile_id, delivery_limits_digest, release_trust_root_digest);
