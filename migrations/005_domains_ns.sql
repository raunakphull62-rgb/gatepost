-- 005: nameserver-mode claims carry their assigned nameserver pair
-- (GP_NS1/GP_NS2 for now; per-account pairs can replace these later).
ALTER TABLE domains ADD COLUMN ns1 text;
ALTER TABLE domains ADD COLUMN ns2 text;
