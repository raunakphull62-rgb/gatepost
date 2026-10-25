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

