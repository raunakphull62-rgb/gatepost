-- 014: B3c item 4. Widens operator_alerts.kind CHECK to include
-- waf_config_failed so the poller's heartbeat can record/resolve it. Applied
-- as a new migration because 013 was already applied in production/dev
-- databases and must never be edited after application.
ALTER TABLE operator_alerts DROP CONSTRAINT IF EXISTS operator_alerts_kind_check;
ALTER TABLE operator_alerts ADD CONSTRAINT operator_alerts_kind_check
  CHECK (kind IN ('origin_unsafe','origin_unresolved','snapshot_build_failed','node_stale','waf_config_failed'));
