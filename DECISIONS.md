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
