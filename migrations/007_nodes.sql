-- 007: B3a item 1. Edge and DNS nodes authenticate with their own bearer
-- token — random 256 bits, echoed once at create time, only the SHA-256
-- stored here, revocable by flipping status. Nodes never touch the database
-- themselves; they poll the signed config snapshot, so snapshot_versions
-- houses the monotonic generation: one row per distinct content hash,
-- insertion order is the generation, and the version only moves when the
-- content actually changes.
CREATE TABLE nodes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 50),
  role text NOT NULL CHECK (role IN ('edge','dns')),
  token_hash text NOT NULL UNIQUE,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
  last_seen timestamptz,
  applied_version bigint,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE snapshot_versions (
  generation bigserial PRIMARY KEY,
  content_hash text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now()
);
