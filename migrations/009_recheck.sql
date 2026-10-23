-- 009: B3a, re-check bookkeeping (addition to 008). The alert kinds widen:
-- an origin that cannot be re-checked (timeout/SERVFAIL/NXDOMAIN) keeps its
-- snapshot entry, and only after GP_ORIGIN_UNRESOLVED_BUILDS consecutive such
-- builds does it raise origin_unresolved — persistence gets noticed too, but
-- "unresolvable" is still never a removal. A per-origin counter tracks the
-- consecutive unresolved builds; a build that finds the origin safe again
-- auto-resolves that domain's open alerts.
ALTER TABLE operator_alerts DROP CONSTRAINT operator_alerts_kind_check;
ALTER TABLE operator_alerts ADD CONSTRAINT operator_alerts_kind_check
  CHECK (kind IN ('origin_unsafe','origin_unresolved'));

CREATE TABLE origin_unresolved (
  domain_id  uuid PRIMARY KEY REFERENCES domains(id) ON DELETE CASCADE,
  streak     int NOT NULL DEFAULT 0,
  updated_at timestamptz NOT NULL DEFAULT now()
);
