-- storage-and-retention.md section 1: every Welcome is bound to the exact
-- target, the canonical Commit envelope, and the mls_commit class. The
-- baseline bound Welcomes to a position only; these columns bind the exact
-- envelope identity and class. Both tables are empty pre-production, so the
-- columns can be added NOT NULL without a backfill phase.

ALTER TABLE mls_welcomes ADD COLUMN commit_envelope_id uuid NOT NULL;
ALTER TABLE mls_welcomes ADD COLUMN commit_envelope_class text NOT NULL
  DEFAULT 'mls_commit' CHECK (commit_envelope_class = 'mls_commit');

ALTER TABLE mls_welcomes ADD CONSTRAINT mls_welcomes_commit_envelope_fk
  FOREIGN KEY (conversation_id, commit_position, commit_envelope_id)
  REFERENCES envelopes(conversation_id, position, envelope_id);

ALTER TABLE mls_welcomes ADD CONSTRAINT mls_welcomes_commit_class_fk
  FOREIGN KEY (conversation_id, commit_position, commit_envelope_class)
  REFERENCES envelopes(conversation_id, position, envelope_class);
