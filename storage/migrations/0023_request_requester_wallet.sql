-- The requester's wallet, for the owner's queue display. Stored only after
-- the server verifies it against the eligibility grant's subject_hash
-- (HMAC of the CAIP-10 ref), so it is the same wallet that verifiably paid
-- the project — public on-chain information the owner needs to triage.
ALTER TABLE conversation_requests
  ADD COLUMN requester_wallet text;
