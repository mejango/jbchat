-- Queued chat requests. A paid customer can request a conversation with a
-- project before any project staff has enrolled; the request sits pending
-- until an owner attends to it. No message content is queued here — only
-- the request — so nothing leaves the end-to-end boundary. On accept the
-- owner's client activates the MLS conversation and conversation_id is set.
CREATE TABLE conversation_requests (
  request_id uuid PRIMARY KEY,
  project_ref_id uuid NOT NULL REFERENCES project_refs(project_ref_id),
  requester_account_id uuid NOT NULL REFERENCES accounts(account_id),
  requester_installation_id uuid NOT NULL REFERENCES installations(installation_id),
  eligibility_grant_id uuid NOT NULL REFERENCES eligibility_grants(grant_id),
  status text NOT NULL CHECK (status IN ('pending', 'accepted', 'declined', 'expired')),
  created_at timestamptz NOT NULL,
  resolved_at timestamptz,
  resolved_by_installation_id uuid REFERENCES installations(installation_id),
  conversation_id uuid REFERENCES conversations(conversation_id),
  CHECK ((status = 'accepted') = (conversation_id IS NOT NULL)),
  CHECK ((status IN ('accepted', 'declined')) = (resolved_at IS NOT NULL))
);

-- At most one live (pending) request per customer per project.
CREATE UNIQUE INDEX conversation_requests_one_pending
  ON conversation_requests (project_ref_id, requester_account_id)
  WHERE status = 'pending';

-- Owner queue read: pending requests for a project, newest first.
CREATE INDEX conversation_requests_project_pending
  ON conversation_requests (project_ref_id, created_at DESC)
  WHERE status = 'pending';
