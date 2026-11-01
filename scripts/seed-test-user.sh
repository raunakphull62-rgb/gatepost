#!/usr/bin/env bash
# scripts/seed-test-user.sh
#
# Creates a throwaway test user and a sample domain for frontend tests,
# using only test values. It inserts directly into a throwaway Postgres
# database (SEED_DATABASE_URL) so it does not depend on email delivery or
# the OAuth providers.
#
# Required env:
#   SEED_DATABASE_URL  postgres://user:pass@host:port/db  (throwaway DB only)
#
# Prints to stdout (shell-evaluable):
#   SEED_USER_EMAIL=...
#   SEED_DOMAIN_ID=...      uuid of the sample verified domain
#   SEED_DOMAIN_HOSTNAME=...
#   SESSION_COOKIE="gp_session=<value>"   Cookie header value for a signed-in caller
#
# The database is expected to be empty/fresh (migrations already applied).
# Nothing here is secret: every value is randomly generated for this run.
set -euo pipefail

DB="${SEED_DATABASE_URL:?SEED_DATABASE_URL must be set to a throwaway postgres URL}"
PSQL=(psql -q -t -A "$DB")

rand() { openssl rand -hex 6; }

EMAIL="seed-$(rand)@example.test"
DOMAIN="seed-$(rand).example.test"
SESS_TOKEN="sess-$(openssl rand -hex 24)"
SESS_HASH=$(printf '%s' "$SESS_TOKEN" | sha256sum | cut -d' ' -f1)
VERIFY_TOKEN="vtok-$(openssl rand -hex 12)"

# 1) Verified user (password_hash NULL: session-based, no password login needed).
USER_ID=$("${PSQL[@]}" -c "
  INSERT INTO users (email, email_verified, password_hash, welcome_sent_at, created_at, updated_at)
  VALUES ('$EMAIL', true, NULL, now(), now(), now())
  RETURNING id::text;")

# 2) A live session for the user (cookie value shown once here).
SESSION_ID=$("${PSQL[@]}" -c "
  INSERT INTO sessions (token_hash, user_id, created_at, expires_at)
  VALUES ('$SESS_HASH', '$USER_ID', now(), now() + interval '7 days')
  RETURNING id::text;")

# 3) Sample verified domain (cname setup) owned by the user.
DOMAIN_ID=$("${PSQL[@]}" -c "
  INSERT INTO domains
    (owner_user_id, hostname, status, setup_type, verify_token, claimed_at, verified_at, expires_at,
     ns1, ns2, waf_mode, excluded_rule_ids)
  VALUES
    ('$USER_ID', '$DOMAIN', 'verified', 'cname', '$VERIFY_TOKEN', now(), now(), NULL,
     '', '', 'detection', '{}')
  RETURNING id::text;")

# 4) Sample origin for the domain (loopback origin; needs GP_TEST_ALLOW_LOOPBACK).
"${PSQL[@]}" -c "
  INSERT INTO origins
    (domain_id, scheme, address, port, host_header, tls_verify, health_path, health_interval_secs)
  VALUES
    ('$DOMAIN_ID', 'http', '127.0.0.1', 18090, NULL, true, '/', 60);"

cat <<EOF
SEED_USER_EMAIL='$EMAIL'
SEED_DOMAIN_HOSTNAME='$DOMAIN'
SEED_DOMAIN_ID='$DOMAIN_ID'
SEED_USER_ID='$USER_ID'
SESSION_COOKIE='gp_session=$SESS_TOKEN'
EOF

echo "# Seed complete: user $EMAIL, domain $DOMAIN (id $DOMAIN_ID), session cookie ready." >&2
