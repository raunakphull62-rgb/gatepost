# Decisions

## B3c item 2c — boot degrade and stale last-good serving

### Context

A node can reach a state where it has a valid saved snapshot on disk but **no
node token** to authenticate with the control plane (empty/unreadable token
file, secret not yet mounted, revoked token pending re-issue). The previous
behavior was to make this **fatal at boot**: the poller never started, and
because the poller owns the egress forwarders + Caddy reload in the shared edge
network namespace, a boot-fatal poller also took down the served hosts — even
though a good last-good config was sitting on disk.

The new behavior **degrades instead of exiting**:

- The poller boots, loads and verifies the saved snapshot, applies it to the
  edge, and serves the last-good config.
- It does **not** poll the API (no 401 flood, no backoff streak climb — a
  missing token is not a connection failure).
- It re-reads the token file on every poll cycle. Refilling the secret restores
  polling with **no restart**.

### The staleness trade-off

| dimension             | choice                                                                 |
|-----------------------|------------------------------------------------------------------------|
| Take the node down?   | **No.** `/health` returns **200** with a `degraded` reason in the body. An auto-takedown here just restarts the loop into the same empty-token state — the exact crash/loop the `.supervise-off` trap exists to avoid during tests. |
| How loud?             | `error`-level "no node token: serving last-good config, not polling" at boot, then one repeat every `GP_EDGE_ERROR_LOG_GAP` (default 5 min, see `degradedLogGap`). |
| Stale guard?          | After `GP_EDGE_STALE_LIMIT` (default **24h**) in degraded mode, a `CRITICAL` line fires every hour (`criticalStalenessGap`) until recovery. |
| Default stale limit   | 24h. A node serving last-good for a full day with no token almost certainly has an operator-side problem; 24h is long enough to ride out a deploy window but short enough that something pages someone. |

**Why not fail faster?** Serving last-good is strictly safer than 502-for-everyone.
The downside is a **stale config** — the edge keeps answering with origins/rules
that may have moved in the control plane. That is the explicit trade-off the
`GP_EDGE_STALE_LIMIT` knob and the CRITICAL log exist to bound: correctness is
eventually consistent, availability is not sacrificed to it.

**Why 200, not 503, on `/health`?** The supervise timer reconciles by
`docker compose up -d`. A 503 (with the default `restart: no` policy the
dev stack uses — see `scripts/edge-supervise.sh`) would not be acted on, but a
503 *would* flip alerting that keys off health and could prompt a manual
restart that just re-enters the same degraded state. A 200-with-degraded-reason
lets the node keep serving while still surfacing the condition to a probe that
parses the body. Production alerting is expected to key on the `degraded` body
string + the CRITICAL staleness line, not the HTTP status.

### Boot conditions — fatal vs. degrade

The poller now splits its boot inputs by trust role, not by "all secrets":

| Input            | Role                         | Behavior at boot                              |
|------------------|------------------------------|-----------------------------------------------|
| Node token       | Polling credential (ephemeral) | **Degrade** — serve last-good, no poll.    |
| Snapshot key     | Snapshot verification (trust anchor) | **Fatal** — can't verify anything.    |
| API base        | Control plane identity      | **Fatal** — would talk to the wrong plane.    |
| Issuer          | Cert issuance identity      | **Fatal** — wrong issuer = wrong certs.       |
| WAF mode        | Policy posture              | **Fatal** — detection-vs-blocking is a safety choice. |
| Features        | Capability set for the gate | **Fatal** — unknown features must not be claimed (B3c Fix 1). |
| Admin address   | Ask endpoint                | **Fatal** — the ask is how HTTP routes resolve. |
| State dir (writable) | Writeback location       | **Fatal** if missing AND no snapshot exists.  |
| State dir (read-only mount) | Same, with a snapshot | **Degrade** — load read-only, never write back. |

The rationale: a missing token keeps the node **serving**, but a missing trust
anchor (key/API/issuer/WAF-mode/features/admin) means it can't **correctly**
serve — it would either fail verification, talk to the wrong plane, or apply a
policy posture the operator didn't choose. Those stay fatal.
