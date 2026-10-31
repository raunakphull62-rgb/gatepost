-- 013: B3c item 2c / Q7a. Stale-node operator alert: an ACTIVE node that has
-- checked in (last_seen IS NOT NULL) but has gone silent for longer than
-- GP_NODE_STALE_MINUTES (default 10) opens one node_stale alert, deduped by
-- (kind, subject) per 008's open-unique index. The next successful
-- /node/v1/heartbeat stamps last_seen and auto-resolves it. Nodes that have
-- NEVER connected (last_seen IS NULL) are never alerted — "never seen" is
-- not "gone silent", and a brand-new node provisioned but not yet booted
-- must not page.
ALTER TABLE operator_alerts DROP CONSTRAINT operator_alerts_kind_check;
ALTER TABLE operator_alerts ADD CONSTRAINT operator_alerts_kind_check
  CHECK (kind IN ('origin_unsafe','origin_unresolved','snapshot_build_failed','node_stale','waf_config_failed'));
