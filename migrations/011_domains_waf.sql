-- 011: B3c item 2 — per-domain WAF mode and rule exclusions.
-- New domains default to "detection" (the edge ships detection-only by default).
-- The change trail (domain_waf_changes) records every write for auditability.
ALTER TABLE domains ADD COLUMN waf_mode text NOT NULL DEFAULT 'detection'
  CHECK (waf_mode IN ('off','detection','blocking'));
ALTER TABLE domains ADD COLUMN excluded_rule_ids integer[] NOT NULL DEFAULT '{}';

CREATE TABLE domain_waf_changes (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  domain_id       uuid NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  changed_by      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  action          text NOT NULL CHECK (action IN ('mode','exclude_add','exclude_remove')),
  old_value       text,
  new_value       text,
  changed_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX domain_waf_changes_domain_idx ON domain_waf_changes(domain_id, changed_at DESC);
