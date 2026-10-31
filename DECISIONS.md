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

## 2026-10-26 — The egress chain never filters reply traffic, and access logs are caddy config, not edge code (B3b item 6)

**Reply rule.** The FIRST rule of `GATEPOST-EGRESS` (v4 and v6) is
`conntrack ESTABLISHED,RELATED → RETURN`. The original chain filtered
every packet from the edge subnet, including the reply legs of
connections the HOST initiated — with the firewall applied, every
host-published edge port (8081/8445) hung: the docker-proxy/DNAT return
packet (`src 172.28.0.2 → dst 172.28.0.1`) matched the host-IP pin
`REJECT` and died. Kernel-tracked reply state is not an address the edge
mints; NEW connections it initiates stay filtered. Found by hitting the
published port from the host while the demo'd access logging was live
(from inside the container everything looked fine).

**Access logging.** Structured edge access logs are CADDY CONFIG, not
edge code — zero changes to the caddy image, no new process:

  - one `logging.logs.http.log.access` custom log, file writer rolled at
    10 MB × 5 (caddy MkdirAll's the dir), and the key can never be
    `default` — that is caddy's GLOBAL runtime logger, and defining it
    redirects all runtime logs into the access file (the real-caddy e2e
    caught this). The `include: ["http.log.access"]` guard keeps runtime
    lines (admin.api, tls) out.
  - a `filter` encoder wrapping `json` DELETES the credential headers by
    name — `request>headers>Authorization`,
    `request>headers>Proxy-Authorization`, `request>headers>Cookie`,
    `resp_headers>Set-Cookie`, `resp_headers>Proxy-Authorization`, and
    the auto-added top-level `uuid` duplicate of the referenced
    `{http.request.uuid}`. Deletion, not caddy's default `REDACTED`
    mask: "never log" is stricter than "never leak", and no name or
    shape of the credential survives in the line.
  - per-route `http.handlers.vars` stamps the origin identity
    (`gatepost_origin`); `http.handlers.log_append` (late-evaluated on
    the way back up) appends `request_id` (caddy's per-request uuid),
    `path` (`{http.request.uri.path}` — no query; the query stays in
    caddy's native `uri` field) and `origin` (the vars value; the
    catch-all logs the constant `-`). A path percent-encoding a newline
    + a whole forged `{"level":"critical"}` payload stays ONE JSON
    string in ONE physical line (zap escapes it; proven in the e2e and
    live on the box).
  - the poller names the destination (`GP_EDGE_ACCESS_LOG`, default
    `data/logs/access.json`; empty = logging off — the knob flows into
    every generated config); docker stdout/stderr rotations live in
    compose (`json-file` 10m × 3 on edge and poller).
  - repeated IDENTICAL failure lines are throttled per brand
    (`GP_EDGE_ERROR_LOG_GAP`, default 30s): a down API would otherwise
    write one line per poll tick forever. First line always passes; the
    backoff-cap crossing is announced exactly once per outage; recovery
    lines (`applied snapshot …`) are never throttled.

**Why.** A log that leaks credentials or can be forged by the thing it
observes is worse than no log; a poller that logs 86,400 identical lines
a day hides the one line that matters.

## 2026-10-26 — Access logs log no headers and no URI at all, and the default logger is redefined to keep them off stderr (item 6 correction)

**What.** The generated logging config deletes three things whole:
`request>headers`, `resp_headers` and `request>uri` (plus the auto-added
`uuid` duplicate). The only header value that survives is `user_agent`,
appended deliberately via `log_append`. Separately, the config now
defines a `default` log with exactly one key — `exclude:
["http.log.access"]`.

**Why.** The first half is the correction's rule made structural: a
credential deny-list only holds until the next credential-bearing header
name appears, and caddy's native `uri` is the only field a query string
can ride. Deleting the objects (not masking names) makes "never logged"
a property of the shape, not of a list. Source-verified against caddy
2.11.7: the filter encoder's `AddObject` matches the nested path and
drops the object itself.

The second half closes a leak the deny-list era could never see: caddy
tees every log entry to every custom log whose include/exclude matches —
and the DEFAULT log, shapeless, matches everything. The access FILE was
filtered; caddy's stderr — the edge container's docker json-file log —
received an unfiltered twin of every access entry, query strings and
headers included (standalone probe against 2.11.7: file filtered, stderr
carrying `?token=SECRET123&code=abc` and `X-Api-Key`). Redefining
`default` with only an exclude keeps provision's vanilla fallbacks
(nil writer → stderr, nil encoder → production JSON, Info level) so
runtime lines (admin, tls, http errors) still flow, while the per-entry
`filteringCore` refuses the `http.log.access*` prefix. Defining `default`
is safe exactly because it names no writer: the earlier trap — naming it
`default` with the FILE writer — redirected all of caddy's stderr into
the access file.

**Evidence.** E2E with real caddy: the correction's query request and
four credential headers leave no value or name in the file; every line
structurally lacks `uri`/`headers`/`resp_headers`; `user_agent` present;
and the harness's captured caddy stderr contains zero access entries
while runtime lines persist. `scripts/edge-accept.sh` (item 7) sweeps
the production file and the production container log the same way.

## 2026-10-26 — A cold start with no snapshot pushes the deny-all shape, and an unreachable admin retries in seconds (B3b items 3+7)

**What.** Two poller boot behaviors. (1) At the end of every tick with
nothing applied (`appliedGeneration() == 0`), the poller enqueues the
zero document — `Generate`'s deny-all shape: both listeners, only the
421 catch-all. (2) A `/load` that fails on TRANSPORT (caddy's admin not
answering) opens no cooldown window and retries every 2s; a config
caddy REJECTED (an HTTP answer) still stamps the window and retries at
the 60s cooldown pace.

**Why.** (1) The poller's own header claimed "cold start with no
snapshot: 421 for every host", but nothing ever pushed that shape — a
no-snapshot edge sat on its bootstrap Caddyfile (which serves a
localhost responder and empty 200s, not 421). Acceptance point (b) is
the wire claim; the push makes it true. The content-hash gate makes the
push once-only and invisible to any node that has (or then gets) a real
snapshot. (2) `depends_on` orders container starts, not readiness: a
joint edge+poller restart is a race the poller usually loses — its first
`/load` gets connection-refused, and the old bookkeeping stamped
`lastLoad` on the failed attempt, turning the retry into a full 60s
cooldown. Every joint cold start risked a minute of blindness
(acceptance point (a) hit exactly this). A failed-to-reach-caddy
attempt never touched caddy, so it opens no window; the first attempt
caddy answers — accepted or rejected — opens it.

**Evidence.** `TestApplyColdStartNoSnapshotServesDenyAll` (exactly one
deny-all /load across many failed ticks; the first real config replaces
it) and `TestApplyAdminNotUpRetriesFast` (admin up 1.5s after the
poller; first /load within seconds, not the 60s cooldown), both with the
production cooldown. `scripts/edge-accept.sh` proves both on the real
stack: (a) restarts edge+poller with the API down, (b) boots with a
wiped state volume.

## 2026-10-26 — The item-7 origin fixture lives on 192.88.99.0/24, the deprecated 6to4 relay anycast range

**What.** The dev compose stack carries a realistic test origin
(stdlib-only python, ports 9001/9002 for blue/green visibility, all the
acceptance endpoints) on its own pinned bridge `br-gporigin`, subnet
`192.88.99.0/24`, static IP `192.88.99.10`, with the edge attached to
both networks.

**Why.** The origin must pass the API's SSRF rules as a PUBLIC address —
`domains.forbidV4Nets` covers every private, CGNAT, link-local,
metadata, multicast, reserved AND RFC 5737/198.18 documentation range,
so none of the "safe to squat" ranges can host it. 192.88.99.0/24 is
the 6to4 relay anycast prefix (RFC 3068), formally deprecated and
returned to IANA (RFC 7526): unannounced on the real internet, public
to CheckIP, and its traffic never leaves the host. Edge→origin is
same-bridge L2 (br_netfilter off: no FORWARD traversal), so the egress
firewall is not even consulted — and would pass it as public anyway.
The API stores the literal IP; no DNS is involved. A preflight in the
acceptance script refuses to run if the host already routes that range.

## 2026-10-28 — A killed edge container resurrects BOTH containers with no manual commands (B3b item 8)

**Rule.** `docker kill` on the edge container must end with the edge AND the
poller serving again on their own. The edge recovers by docker's own
`restart: unless-stopped`; the poller — which shares the edge's network
namespace (`network_mode: service:edge`) — recovers by EXITING and letting
the same policy restart it into the edge's fresh namespace.

**Mechanics.** When the edge container dies, docker recreates its network
namespace on restart, but the poller keeps running inside the ORPHANED old
one: loopback 2019 (the admin API) can never answer again, and no docker
mechanism notices (restart policies fire on process exit; healthchecks only
report). So the poller watches the admin on two paths: every apply attempt
classifies its failure (`adminTransport` — dial errors only; a `caddy
/load:` rejection or a local forwarder/caddygen error says nothing about
reachability), and — because a fully-applied poller has NO pending work and
would never dial at all — an idle watchdog probes the admin every
min(5s, AdminGrace/3) (`adminProbe`: any HTTP answer = alive). Both feed one
window: transport failures are tolerated for `GP_EDGE_ADMIN_GRACE` (default
15s — the joint cold start's caddy answers in ~2s, an orphaned namespace
never answers), any answer resets it, and the breach returns `errAdminGone`
→ `Run` → main `log.Fatalf` (exit 1) → docker's `restart: unless-stopped`
starts the container again — this time joining the edge's CURRENT namespace,
where the boot load re-applies the saved snapshot. The same grace covers
`docker restart edge`, which orphans the poller identically.

**Mechanics, compose.** Both services carry healthchecks (edge: caddy admin
`/config`; poller: the ask listener's new `/health` route — any answer means
the process and its loopback are alive), and the poller's `depends_on` is
the long form `edge: {condition: service_healthy, restart: true}`, so
compose-driven restarts/recreations of the edge also restart the poller in
order. The daemon-level kill case is the grace exit; the compose-level case
is `restart: true`.

**Why.** The acceptance script had to stop/recreate the poller BY HAND
around every edge restart (its section a) — evidence that no automatic
path existed. An edge that needs an operator after a crash is not crash
resilient; the one process that can notice the dead namespace is the poller
itself, and exit-with-restart-policy is the only mechanism docker offers
for it.

**Poller downtime is a 502 window — accepted, documented (2026-10-28).**
The egress forwarder listeners live in the poller process (they must: the
dial guard runs at accept time in Go, not in caddy config), so any poller
downtime 502s, and the listeners' ephemeral ports mean a restarted poller
cannot serve before its first apply pushes the new ports (~0.3s after
start). Measured on this box: a crashed poller (self-exit) restarts via
docker's own policy and 502s for ~0.3s total; a `docker kill`ed poller
bypasses the restart policy entirely (RestartCount stays 0, dockerd logs
"stopping restart-manager") and waits for the supervisor timer — 0.8-0.9s
when a tick coincides with the kill, 13.7s worst case on the 15s cadence.
Deterministic forwarder ports were considered and rejected: they only
remove the ~0.3s post-boot apply gap, not the downtime, which the
supervisor bounds either way.

## 2026-10-31 — A missing node token degrades to last-good serving, not a fatal boot (B3c item 2c)

**Rule.** A missing/empty/unreadable node token is a POLLING-credential failure,
not a trust-anchor failure: the poller boots, loads and verifies its saved
snapshot, and serves last-good instead of exiting. It does not poll (no 401
flood), does not climb the backoff streak (a missing token is not a connection
failure), and re-reads the token file on every cycle so a refilled secret
restores polling with **no restart**. `/health` returns **200** with the
degraded reason in the body — a 503 would just restart the loop into the same
empty-token state (the exact crash/loop the `.supervise-off` trap exists to
avoid during tests). After `GP_EDGE_STALE_LIMIT` (default **24h**) the poller
logs a **CRITICAL** line every hour until recovery; the node is never
auto-taken down.

**Mechanics.** `bootToken` (main.go) resolves the token with DISTINCT reasons
for missing / empty / unreadable so a deploy typo is diagnosable.
`bootStateDir` / `stateDirProbe` classify the state dir: writable → normal; a
read-only mount that still holds a saved snapshot → degrade (load read-only,
never write back, persist gated on `!ReadOnlyFS`); missing dir AND no snapshot
→ fatal. The signing key, API base, issuer, WAF mode, features, and admin
address stay fatal via `envOrFile` — they are trust anchors, not polling
credentials, and a node that can't correctly verify/identify cannot correctly
serve.

**Boot conditions — fatal vs. degrade.** The poller splits its boot inputs by
trust role, not by "all secrets":

| Input | Role | Boot |
|---|---|---|
| node token | poll credential (ephemeral) | **degrade** — serve last-good, no poll |
| snapshot signing key | verification (trust anchor) | fatal |
| API base | control-plane identity | fatal |
| issuer | cert issuance identity | fatal |
| WAF mode | policy posture | fatal |
| features | capability gate (B3c item 2b) | fatal — unknown features rejected at boot |
| admin address | ask endpoint | fatal |
| state dir (writable / creatable) | writeback location | normal |
| state dir (read-only, with snapshot) | same | **degrade** (read-only) |
| state dir (missing, no snapshot) | nothing to serve | fatal |

**Why.** Serving last-good is strictly safer than 502-for-everyone, and a
missing token keeps the node SERVING while a missing trust anchor means it
cannot CORRECTLY serve (failed verification, wrong plane, wrong policy). The
downside is a stale config, bounded by the `GP_EDGE_STALE_LIMIT` CRITICAL log:
an operator is paged before staleness becomes unbounded, and the node keeps
answering from a known-good artifact. Determined by the schema-gate work
(B3c item 2b) which established that the poller owns the egress forwarders in
the edge's shared network namespace, so a boot-fatal poller takes down served
hosts even with a good snapshot on disk.

**Evidence.** `TestTokenFileEmptyThenRestoredDegradesServesLastGood` boots a
real poller with an empty token file: the ask endpoint stays 200 from boot
(last-good applies at boot, 0 non-200 during the blip), 0 poll requests and 0
backoff-streak lines while degraded, then a refilled token resumes polling
within one poll cycle with no restart. `TestDegradedStalenessLogsCritical`
confirms the CRITICAL staleness line fires past `StaleLimit` while `/health`
stays 200. Production-pace acceptance (170 passed / 0 failed) and the 5-min
soak (zero non-200) pass against the item-2c binary.

