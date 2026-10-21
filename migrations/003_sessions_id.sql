-- 003: sessions get a random opaque id (list/revoke identifier). token_hash
-- stays the storage key; the id appears in URLs, the hash never does.
ALTER TABLE sessions ADD COLUMN id uuid NOT NULL DEFAULT gen_random_uuid();
