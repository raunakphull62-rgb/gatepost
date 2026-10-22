-- 006: B2 item 12. One zone per nameserver-mode domain; the customer
-- manages records through the API; every mutation leaves a history row
-- (who/when/old/new) so a later rollback is possible. record_changes does
-- NOT foreign-key records: deleted records keep their trail.
CREATE TABLE zones (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  domain_id uuid NOT NULL UNIQUE REFERENCES domains(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE records (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  zone_id uuid NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
  type text NOT NULL CHECK (type IN ('A','AAAA','CNAME','MX','TXT','NS','SRV','CAA')),
  value text NOT NULL CHECK (length(value) BETWEEN 1 AND 4096),
  ttl int NOT NULL DEFAULT 3600 CHECK (ttl BETWEEN 60 AND 86400),
  priority int CHECK (priority BETWEEN 0 AND 65535),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX records_zone_idx ON records(zone_id);
CREATE INDEX records_zone_name_idx ON records(zone_id, name);
-- a CNAME name carries nothing else, even under concurrent writes:
CREATE UNIQUE INDEX records_cname_uniq ON records (zone_id, name) WHERE type = 'CNAME';

CREATE TABLE record_changes (
  id bigserial PRIMARY KEY,
  record_id uuid NOT NULL,
  zone_id uuid NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
  changed_by uuid NOT NULL REFERENCES users(id),
  action text NOT NULL CHECK (action IN ('create','update','delete')),
  old_value text,
  new_value text,
  changed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX record_changes_record_idx ON record_changes(record_id);
