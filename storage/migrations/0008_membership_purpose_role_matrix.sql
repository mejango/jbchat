-- storage-and-retention.md section 1 and service-api.md's admission matrix:
-- delivery purpose is immutable, and a membership role must be legal for the
-- conversation's purpose (purchase_support: customer/project-staff;
-- announcement: publisher plus read-only subscriber; community:
-- member/moderator). memberships is empty pre-production, so the purpose
-- column can be added NOT NULL without a backfill phase.

ALTER TABLE conversations ADD CONSTRAINT conversations_id_delivery_purpose_key
  UNIQUE (conversation_id, delivery_purpose);

CREATE FUNCTION conversation_delivery_purpose_is_immutable() RETURNS trigger
LANGUAGE plpgsql AS $immutable$
BEGIN
  IF NEW.delivery_purpose <> OLD.delivery_purpose THEN
    RAISE EXCEPTION 'conversations.delivery_purpose is immutable';
  END IF;
  RETURN NEW;
END;
$immutable$;

CREATE TRIGGER conversations_delivery_purpose_immutable_trigger
  BEFORE UPDATE OF delivery_purpose ON conversations
  FOR EACH ROW EXECUTE FUNCTION conversation_delivery_purpose_is_immutable();

ALTER TABLE memberships ADD COLUMN delivery_purpose text NOT NULL CHECK (
  delivery_purpose IN ('purchase_support', 'announcement', 'community')
);

ALTER TABLE memberships ADD CONSTRAINT memberships_conversation_purpose_fk
  FOREIGN KEY (conversation_id, delivery_purpose)
  REFERENCES conversations(conversation_id, delivery_purpose);

ALTER TABLE memberships ADD CONSTRAINT memberships_purpose_role_matrix_check CHECK (
  (delivery_purpose = 'purchase_support' AND role IN ('customer', 'project-staff'))
  OR (delivery_purpose = 'announcement' AND role IN ('publisher', 'subscriber'))
  OR (delivery_purpose = 'community' AND role IN ('member', 'moderator'))
);
