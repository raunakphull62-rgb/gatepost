-- 012: B3c item 2b. The alert kinds widen again: a snapshot build that FAILS
-- (size cap, database trouble) must never be silent — the pollers keep their
-- last good artifact, but the operator gets one open snapshot_build_failed
-- alert (deduped per 008) that the next successful build auto-resolves.
ALTER TABLE operator_alerts DROP CONSTRAINT operator_alerts_kind_check;
ALTER TABLE operator_alerts ADD CONSTRAINT operator_alerts_kind_check
  CHECK (kind IN ('origin_unsafe','origin_unresolved','snapshot_build_failed'));
