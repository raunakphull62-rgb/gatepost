# Lessons from the first build (do not relearn these)

## Edge and TLS
- Build Caddy with xcaddy: coraza-caddy v2 (OWASP CRS), Souin cache,
  caddy-ratelimit.
- Caddy logs to stderr. Telemetry readers must merge stderr into the
  log stream.
- A restart with an identical config must still start Caddy.
- On-demand TLS: the "ask" check must be answered locally from the
  last-good config. A live API call fails cold-start TLS during an API
  outage.
- Two nodes sharing one hostname: Let's Encrypt HTTP-01 can hit either
  node. Pick a certificate strategy (shared storage or challenge
  forwarding) and test it with a new domain from both node IPs.
- Do not advertise HTTP/3 unless UDP 443 is open.
- Preserve the real client IP. Behind any proxy, trust only that
  proxy's addresses. The Docker bridge (172.18.0.1) shows up for
  server-local tests.
- Config apply is atomic with last-good fallback. Health-driven
  reloads at least 60 s apart. Flap damping: 3 failures to trip, 2
  successes to recover.
- Cache keys carry a generation tag so purge is instant.

## Firewall and blocklist
- Never blocklist private, loopback or Docker-range addresses.
- The shared blocklist is the first handle in every site and overrides
  customer allow lists. Threshold 10 failed logins in 2 minutes, 1 hour
  expiry, matcher cap 400 IPs.
- IP reputation lists (Tor, datacentre, known-bad) only tag and apply a
  stricter limit. They never block by themselves.
- GeoIP uses DB-IP Lite (CC BY 4.0, attribute in the README). The file
  once ended up 0 bytes. Validate it at startup and hourly, and alert
  if it is missing, under 1 MB or older than 45 days.

## Bot detection
- Scoring must fail open: with the API down, visitors still get 200.
- Start in log-only mode. The 30 and 70 score bands are guesses to be
  tuned on real traffic.
- Humans must never be challenged or blocked. Test with 30 human and
  30 bot sessions at once, and fail if fewer than 25 bots are caught.

## Tests
- Test fixtures must send a correct Content-Length (a wrong one hung
  POSTs). Use a realistic multi-page origin with assets, not a one-line
  page.
- Time-window tests race. Check live windows, not fixed sleeps.
- Reset login limiters between runs, clean up test rows and schemas,
  and never loop the production Let's Encrypt test (it has rate limits).
- Keep alert cooldown and dedupe state in the database or Redis, never
  in API memory (multiple instances would send duplicates).

## Infrastructure
- Neon: pooled string for the app, direct string for migrations.
  Disable prepared statements through the pooler. The free tier
  suspends when idle, so edge nodes must poll the API, never the
  database.
- Nodes: 2 vCPU, 4 GB RAM, 25 GB disk, Docker log rotation, a disk
  alert at 80 percent. AWS security groups must allow inbound 80 and 443
  or Let's Encrypt fails. Use Elastic IPs.
- Current test nodes are in AWS us-east-2, not India.
- Keep the control plane API on a node we control. Zoho Catalyst
  AppSail is a poor fit (30-second request limit, short-lived instances).

## Process
- One agent at a time. Stop at each gate and show evidence.
- Never paste secrets into the agent. They go into .env by hand.
- If the agent produces content unrelated to Gatepost, ignore it and
  start a fresh session.
