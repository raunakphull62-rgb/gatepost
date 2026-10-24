-- 010: time-based unresolved persistence. Consecutive-build counters
-- measure nothing once the polling cadence changes; wall-clock time does.
-- An origin that cannot be re-checked keeps its snapshot entry and raises
-- the origin_unresolved alert only after it has been unresolvable for
-- GP_ORIGIN_UNRESOLVED_MINUTES (default 60) — a successful re-check clears
-- the timestamp (and auto-resolves the alert).
ALTER TABLE origin_unresolved ADD COLUMN first_unresolved_at timestamptz;
ALTER TABLE origin_unresolved DROP COLUMN streak;
