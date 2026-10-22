-- 004: customer domains + origin settings (B2 item 1).
-- Domains belong to a user for NOW; a later migration adds org_id and
-- backfills from personal orgs, so the column is named owner_user_id and
-- nothing else references "personal" here.
CREATE TABLE domains (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  hostname      text NOT NULL,
  status        text NOT NULL DEFAULT 'pending' CHECK (status IN
    ('pending','verified','rejected','expired','disabled')),
  verify_token  text NOT NULL,
  claimed_at    timestamptz NOT NULL DEFAULT now(),
  verified_at   timestamptz,
  expires_at    timestamptz,
  setup_type    text NOT NULL DEFAULT 'cname'
        CHECK (setup_type IN ('cname','nameserver'))
);

-- many users may hold pending claims on the same hostname; exactly one of
-- them may ever be verified.
CREATE UNIQUE INDEX domains_hostname_verified_uq
  ON domains(hostname) WHERE status = 'verified';
-- one live claim per (user, hostname): a re-claim flips the old row back.
CREATE UNIQUE INDEX domains_owner_hostname_uq
  ON domains(owner_user_id, hostname);
CREATE UNIQUE INDEX domains_token_uq ON domains(verify_token);
CREATE INDEX domains_owner_idx    ON domains(owner_user_id);
CREATE INDEX domains_hostname_idx ON domains(hostname, status);

-- exactly one origin per domain.
CREATE TABLE origins (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  domain_id            uuid NOT NULL UNIQUE REFERENCES domains(id) ON DELETE CASCADE,
  scheme               text NOT NULL CHECK (scheme IN ('http','https')),
  address              text NOT NULL,
  port                 int  NOT NULL CHECK (port BETWEEN 1 AND 65535),
  host_header          text,
  tls_verify           bool NOT NULL DEFAULT true,
  health_path          text NOT NULL DEFAULT '/',
  health_interval_secs int  NOT NULL DEFAULT 60
        CHECK (health_interval_secs BETWEEN 10 AND 86400),
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now()
);
