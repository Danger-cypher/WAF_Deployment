# Active-passive HA — status and runbook

Target architecture: 2 nodes, one active at a time, automatic failover via a
floating VIP. Chosen over a full active-active cluster because the codebase
has real, confirmed assumptions that would need to change first for
multi-instance (see "Why not active-active yet" below) — an active-passive
pair sidesteps all of them, since only one node is ever writing.

## Phase A — done, works on one box today

- **`configs/litestream/litestream.yml`** + the `litestream` service in
  `docker-compose.yml`: continuously streams the WAL of all 5 live
  control-plane SQLite databases (`users.db`, `alerts.db`, `api_keys.db`,
  `ml_events.db`, `false_positives.db`) to a local replica. `type: file`
  only — no external target configured. This deployment's traffic is
  internal-only; nothing here leaves the host until Phase B deliberately
  points it at node 2 (one field to change per db — see the comment in
  that file).
- **`scripts/ha/waf-health-check.sh`**: the compound health check Phase B's
  keepalived will poll. Reuses the backend's real `GET /health` (already
  folds ClickHouse + SQLite connectivity into one `status` field) rather
  than a new liveness probe. **Live-tested against the running system**,
  not just written: returns exit 0 against the real `/health` right now,
  and exit 1 when pointed at an unreachable URL.
- **`configs/keepalived/keepalived.conf.example`**: a fully-commented
  template for Phase B. 4 placeholders to fill in once node 2 exists
  (interface name, priority, VIP, VRRP auth secret) — everything else is
  ready.

## Phase B — needs a second host, not yet started

In rough order:

1. Provision node 2, same OS/Docker setup as node 1.
2. Deploy this same `docker-compose.yml` stack to it.
3. Point `litestream.yml`'s 5 `replica.path` fields at node 2 over SFTP
   (litestream supports it natively — `type: sftp`, no new tooling) instead
   of the local `file` target.
4. Install keepalived on both hosts, fill in `keepalived.conf.example`'s 4
   placeholders (different per node), copy to `/etc/keepalived/keepalived.conf`.
5. **Not yet designed:** the actual promotion sequence when failover fires —
   `notify_master`/`notify_backup` scripts that (a) restore/attach the
   litestream replica as node 2's live SQLite state, (b) promote Redis from
   replica to primary (`REPLICAOF NO ONE`), (c) confirm nginx config on
   node 2 matches what was last generated on the (now-dead) node 1. This is
   real remaining work — the template has a comment marking exactly where
   it plugs in, but writing it before there's a second node to test against
   would mean shipping untested failover automation for a WAF, which is
   the wrong tradeoff.
6. Test actual failover (kill node 1, confirm the VIP moves, confirm node 2
   serves traffic with current config and recent-enough data) before
   trusting this in production.

## Known, unsolved risk: split-brain

Two nodes that lose contact with each other but are both still alive can
each conclude they're the sole MASTER — for a WAF, that means both
independently accepting/blocking traffic and diverging SQLite state, which
is worse than a clean failover. Proper fencing (a third witness/arbiter, or
STONITH) needs more infrastructure than makes sense to build before node 2
exists. Not solved here — don't treat this pair as split-brain-safe until
it explicitly is.

## Two things found while scoping this, unrelated to HA

Neither blocks Phase A or B; flagging rather than silently fixing since
both touch live production files.

- **3 dead SQLite files**: `backend/app/config/users.db`,
  `backend/app/data/false_positives.db`, `backend/app/data/waf_gui.db` are
  all 0 bytes and untouched for days — confirmed not the path any service
  module actually opens (`user_service.py`'s `DB_DIR` resolves to `data/`,
  `db_service.py`'s `DB_FILE` resolves to `config/`, leaving one stale empty
  duplicate in each directory, plus `waf_gui.db` which no module references
  at all). Deliberately excluded from `litestream.yml` for that reason.
  Worth deleting at some point; not done here since it's outside this
  task's job.
- **`ml_events.db` is world-writable** (`rw-rw-rw-`, mode 666) — every other
  SQLite file here is `644`. Could be intentional (a UID mismatch
  workaround between the `backend` and `ml-engine` containers, which run as
  separate processes and both write to this file), or could be an
  unintentional gap. Not changed here — tightening it blind, without
  knowing why it's set that way, risks breaking ML event writes across the
  container boundary, which would be a worse outcome than leaving a
  permissions question open. Worth a deliberate look.
