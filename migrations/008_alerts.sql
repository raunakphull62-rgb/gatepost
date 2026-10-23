-- 008: B3a, build-time origin re-check. Operator alerts: exactly one OPEN
-- row per (kind, subject) — the snapshot builder raises origin_unsafe when
-- a stored origin resolves into a blocked range, and a repeated violation
-- must not spam rows (lessons.md: dedupe state lives in the database).
-- resolved_at clears the way for a future alert on the same pair.
CREATE TABLE operator_alerts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind text NOT NULL CHECK (kind IN ('origin_unsafe')),
  subject text NOT NULL,
  detail text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  resolved_at timestamptz
);
CREATE UNIQUE INDEX operator_alerts_open_uniq
  ON operator_alerts (kind, subject) WHERE resolved_at IS NULL;
