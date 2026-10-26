# Gatepost — Decision Ledger

One entry per deliberate protocol-level commitment, newest last. Anything
not written here is fair game to reconsider. Each entry states the rule, the
mechanics, and why.

## 2026-10-23 — Snapshot versions compare against the LATEST content hash only (B3a)

**Rule.** The snapshot generation is a strictly monotonic counter over real
content changes. On every build, the recorder compares the new content hash
with the LATEST row's hash alone and inserts the next number when they
differ. It never searches history for an equal hash.

**Mechanics.** `snapshot_versions(generation bigserial PK, content_hash)` —
no UNIQUE on the hash. An advisory-locked transaction reads `ORDER BY
generation DESC LIMIT 1`: equal → return that generation (an identical
rebuild keeps its version); different → `INSERT … RETURNING generation`.
Content hashes exclude volatile bookkeeping (`generation`, `built_at`), so
identical content hashes identically every time.

**Consequence worth stating.** A→B→A takes versions 1, 2, 3 with version 3
equal in content to version 1; a verifier MUST accept 3 after 2, and MUST
refuse any generation ≤ the last one it applied.

**Why.** Pollers can only reason with "strictly beyond what I already
applied". If version 3 could collapse back to version 1's number, that check
would mean nothing — a node would believe it already has the newest config
precisely when content looped back to an old shape.

**Original bad idea recorded deliberately.** The first cut (commit `897eadb`)
keyed rows UNIQUE by content hash and reused old generations. That reused
number breaks every poller's monotonicity rule the moment content reverts;
replaced same day.

## 2026-10-24 — The ask check is answered locally by the poller, never live (B3b item 2)

**Rule.** The edge poller (`cmd/gatepost-edge`) serves the on-demand-TLS ask
check on `GP_EDGE_ASK_ADDR` (default loopback `127.0.0.1:8099`): `GET
/check?domain=…` answers `200` only for a hostname inside the APPLIED
snapshot's allowed list (port stripped, case-insensitive), `421` for
everything else — including "nothing applied", where every host is refused.
The persisted artifact is the VERIFIED ENVELOPE itself (`snapshot.json`,
mode `0600`, replaced atomically via temp+fsync+rename+dir-fsync), not a
re-marshalled document, and boot re-verifies it with the same rules as the
wire path: corrupt, tampered or foreign-key files mean "no snapshot", never
a crash.

**Mechanics.** The check consults the in-memory applied document, which is
only ever populated by `snapshot.Verify` (signature + key ID + strictly
newer generation + size cap) — from either a poll or the boot load. A
Caddyfile points on-demand ask at the poller (item 3); the envelopes that
become the applied document can only come from a key the node holds.

**Why.** lessons.md: a live API call for the ask would fail cold-start TLS
during an API outage, stranding every new hostname behind a dead check. The
file must stay fully self-authenticating so a restart can apply it with zero
trust in the disk it came from; deleting untrustworthy-looking files there
would destroy evidence and the last good state alike.

## 2026-10-25 — Ponytail is adopted as the working discipline for this repo

**Rule.** All coding work in gatepost runs under the ponytail plugin
(`@dietrichgebert/ponytail`, v5.3.2, installed globally). The smallest
change that fully solves the task wins; unused options, abstractions and
"for later" code stay out. Levels: lite / full (default) / ultra.

**Mechanics.** The plugin supplies the `ponytail` skill and its companions
(`-review`, `-audit`, `-debt`, `-gain`, `-help`). Two conventions matter to
readers of this repo: a deliberate, known-limit shortcut is marked inline as
`shortcut: <the limit>, <when to upgrade>` and is listed by `/ponytail-debt`;
`shortcut:` comments are the debt ledger, not TODOs. The rule never cuts
input validation, error handling that prevents data loss, security,
accessibility or calibration — only the code nobody needed.

**Why.** The user asked for it by name after repeated over-built changes.
The ledger stays honest this way: skipped scope is visible in one line
instead of hiding in a diff.

## 2026-10-25 — Edge config is generated as JSON, tunnelled through a dial-guarded forwarder, and reloaded only on content change (B3b item 3)

**Rule.** One pure function (`Generate`) turns a verified snapshot into the
Caddy JSON pushed to the admin API. It emits structured JSON, never a text
template, so a hostile hostname or origin can only ever be a string VALUE in
one JSON string — it cannot splice itself into a second route, matcher or
handler. The generated config is the only config the edge serves after boot;
Caddy validates it itself on `POST /load` (200 = validated AND applied, any
other status = rejected, last-good keeps running untouched).

**Mechanics.** Every domain gets a route matching its hostname with
`request_body.max_size` and a `reverse_proxy`; the catch-all LAST answers
421 for every other host. TLS uses the internal issuer with a managed
fallback certificate (`edge.invalid`) and `tls_connection_policies.
fallback_sni`, so unknown SNI completes the handshake and then gets the 421
instead of a reset. The server carries the limits (16 KiB headers, 32 MiB
bodies, 10s/60s/60s/2m header/read/write/idle) and h1+h2 only — HTTP/3
stays off. Because Caddy's `reverse_proxy` has no dial hook, the poller runs
one loopback TCP forwarder per origin: each connection resolves the origin
FRESH and runs every resolved IP through the same `domains.CheckIP` ranges
the API enforces (private, loopback, link-local incl. metadata, CGNAT, …),
dialling the VALIDATED IP directly — no check/dial TOCTOU window. Reloads
are gated by the content hash with generation/built_at stripped
(`snapshot.Hash(ToContent())`), so A→B→A never reloads, and by a 60s
cooldown (`GP_EDGE_RELOAD_COOLDOWN`) that gates every attempt, failures
included. The forwarder Swap happens BEFORE the `/load`, and a dropped
origin keeps its port one extra swap to cover Caddy's reload window.
HTTPS upstreams get an explicit Host header: Caddy 2.11.7 injects
`Host: {upstream hostport}` for every TLS transport
(`httptransport.RequestHeaderOps`), and user header ops apply after
transport ops, so the public hostname (or the configured `HostHeader`)
wins.

**Why.** The config is remote-controlled from a signed snapshot; a text
template would turn one hostile hostname into arbitrary proxy config.
Caddy's own validator is the only implementation that can be trusted to
accept what it will actually run. And a dial-time IP check is the only
check that holds when DNS changes after build time.

## 2026-10-25 — On-demand TLS: issuance is gated by the poller's ask, subjects are the snapshot's hostnames, and staging is the default issuer (B3b item 4)

**Rule.** The edge mints a certificate only when Caddy's on-demand
permission check — the poller's loopback ask — answers 200 for a hostname
inside the last-good APPLIED snapshot. The generated config scopes the
on-demand automation policy to the snapshot's hostnames (invalid names
skipped, fail closed to the fallback cert) and REFUSES to emit any
on-demand policy without the ask endpoint: `Generate` errors when the
document has hostnames but `AskURL` is empty. The issuer is explicit:
`GP_EDGE_ISSUER` = `staging` (the default — a missing setting must never
burn production Let's Encrypt rate limits), `internal`, or `production`
(opt-in only, and refused at boot together with the loopback test hook).
`GP_EDGE_CERT_HOURLY_CAP` (default 50) caps certificate approvals per node
per hour-window; over-cap asks answer 429, which Caddy treats as a denial.
Certificates live in Caddy's data dir — `XDG_DATA_HOME` on the `caddy_data`
volume — so they survive restarts.

**Mechanics.** `apps.tls.automation.on_demand.permission` is Caddy's `http`
module pointed at the poller's `/check`. Subject-scoping is load-bearing: a
default (subject-less) on-demand policy matches every SNI, so an unknown
host would reach the ask and a denial aborts its handshake before the
fallback certificate can answer — probed against 2.11.7: an ask denial for
a subject SNI aborts the handshake (`remote error: tls: internal error`),
while an SNI outside the subjects completes on the `edge.invalid` fallback
cert and gets the catch-all 421. So known hosts gate through the ask and
unknown hosts keep the 421 path. The ask normalization is deliberately
strict — surrounding whitespace, trailing dots, colons (ports, IPv6
literals), IP literals and non-hostnames are 421; **case is NOT refused
(flagged deviation from an early sketch that wanted 421 there): DNS
hostnames are case-insensitive and rejecting a differently-cased SNI would
break legitimate handshakes.** The hourly cap window is fixed from the
first approval (`shortcut: fixed hour window, upgrade to a sliding log if
exact-per-hour enforcement ever matters`); denials cost nothing. The
internal CA is kept out of the host trust store
(`pki.certificate_authorities.local.install_trust=false`) — nothing outside
this node trusts the edge's internal certs. Origin (upstream) TLS is a
different path from edge (client-facing) TLS: the generated transport pins
`server_name` to the origin's configured address, never emits
`insecure_skip_verify`, and refuses `tls_verify=false` origins outright;
extra roots for origin verification are the platform's standard mechanism
(`SSL_CERT_FILE` on Linux), which the real-caddy e2e exercises with a
CA-signed origin and proves refusal with a wrong-name certificate (502,
origin handler never runs).

**HTTP-01 across nodes — documented, deliberately not built.** With the
ACME issuers (staging/production), Caddy solves HTTP-01 by serving the
challenge on port 80 of the node that initiated issuance. On-demand
issuance is per node, so a hostname behind several edge nodes needs the
challenge request to reach the SAME node that asked for the certificate:
either DNS/balancing routes per node, or the nodes share one certificate
store. Neither is built at this stage — today's shape is correct for
one edge node per hostname (and for the internal issuer, which needs no
challenge). Revisit when multi-node HA lands.

**Why.** The ask must be answered from the last-good applied snapshot
(lessons.md: a live API call fails cold-start TLS during an API outage), a
node must never mint certificates for names its signed config does not
carry, and no default may touch production Let's Encrypt.

## 2026-10-25 — Edge egress firewall: DOCKER-USER plus a scoped INPUT hook, REJECT not DROP, one explicit allowlist (B3b item 5)

**Rule.** `scripts/edge-egress.sh` blocks everything the edge containers
send to private, loopback, link-local and metadata space — 10/8, 172.16/12,
192.168/16, 169.254/16 (metadata), 100.64/10, 127/8, the docker bridge
gateway, every address the host itself owns, and the IPv6 equivalents
(fc00::/7, fe80::/10, ::1, plus the v4-mapped ::ffff:0:0/96 to mirror
`domains.CheckIP`'s To4 path). The only deliberate exception is the
control-plane API at `EDGE_EGRESS_API` (explicit IP:PORT, required — on the
dev server the API is a private address, so the exception is one visible
rule, never a blanket allow). Public internet is what remains: public DNS,
ACME and origins pass through the final RETURN. Rules live in one dedicated
chain (`GATEPOST-EGRESS`) entered from TWO jump points: DOCKER-USER for
routed container traffic, and INPUT — because traffic the edge sends to
addresses the HOST owns is locally delivered, not forwarded, so
DOCKER-USER alone can never block the bridge gateway or the host's IPs
(br_netfilter is not loaded on this box, and local delivery hits INPUT even
where it is). Both jumps are scoped (`-s` the compose subnet for v4, `-i`
the pinned bridge for v6), so SSH, the host itself and every other container
— gatepost-auth-pg — are untouched, and inbound ACME HTTP-01 never matches.
The compose network's subnet (172.28.0.0/24) and bridge name (br-gpedge) are
PINNED in compose.yaml: pool-assigned settings drift across recreations and
would strand the persisted rules.

**Mechanics.** REJECT, not DROP: fail fast and visibly (an instant refusal)
rather than a black-hole timeout — the in-container probes show
"Connection refused" in milliseconds where the unfirewalled baseline reaches
metadata and answers. Idempotency is remove-then-install (`apply` first
deletes every rule that jumps to our chain, whatever its match spec);
`remove` reverses completely, including disabling the systemd unit;
`dry-run` prints the exact commands without touching anything; `persist`
installs a oneshot systemd unit (`After=docker.service`, settings baked
into `Environment=` lines) that re-applies at boot. This is the OUTER ring:
the forwarder's dial-time `domains.CheckIP` remains the rule that actually
protects the edge; the firewall is what holds if that process is ever
bypassed (a bug, a stray config, a replaced binary).

**Why.** The edge is the one component that executes remote-controlled
configuration; a second, independent layer must hold when the first fails.
DOCKER-USER is docker's reserved hook for exactly this; and a firewall whose
rules silently drift with DHCP-assigned pool subnets is not a firewall —
hence the pins.

## 2026-10-26 — The unit must never run `remove` on its own stop (reconcile after the box rebooted)

**Rule.** `gatepost-edge-egress.service` has no ExecStop. The unit installed
on 2026-10-25 survived until the box powered off (02:24, boot back 03:08 —
the poweroff was not one of our sudo commands). systemd stops every active
unit at shutdown, so our own `ExecStop=…edge-egress.sh remove` ran as the
unit's stop: `remove` calls `systemctl disable --now` on the unit from
inside its own stop — deadlock, 90s timeout, unit left DISABLED — and at
boot the firewall never re-applied. Fixed by removing ExecStop entirely:
stopping the unit must not un-install protection; rules live in kernel
state and die with a power cut anyway, and the next boot re-applies via
ExecStart. Removal stays an explicit operator action (`edge-egress.sh
remove`), safe now that nothing hands it the unit's own lifecycle.

**Why.** A firewall whose persistence mechanism disables itself during a
clean shutdown looks enabled in the repo while the box boots unprotected.

