-- 002: OAuth identities, API keys, user data, oauth states, rate limits
CREATE TABLE auth_identities (
  user_id                 uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider                text NOT NULL,
  provider_account_id     text NOT NULL,
  provider_email          text NOT NULL,
  provider_email_verified boolean NOT NULL,
  created_at              timestamptz NOT NULL DEFAULT now(),
  UNIQUE (provider, provider_account_id)
);
CREATE INDEX auth_identities_user_idx ON auth_identities (user_id);

CREATE TABLE api_keys (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name         text NOT NULL,
  key_hash     text NOT NULL UNIQUE,
  prefix       text NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  revoked_at   timestamptz
);

CREATE TABLE user_data (
  user_id    uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  data       jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE oauth_states (
  state         text PRIMARY KEY,
  provider      text NOT NULL,
  code_verifier text NOT NULL,
  redirect_uri  text NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,
  used_at       timestamptz
);

CREATE TABLE rate_limits (
  key          text PRIMARY KEY,
  count        integer NOT NULL,
  window_start timestamptz NOT NULL
);
