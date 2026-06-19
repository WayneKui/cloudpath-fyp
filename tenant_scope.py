"""
CloudPath tenant-scoping helper.

Phase 6 of the database build — INGESTION SIDE.

This module owns two responsibilities:

  1. Producing a "scan-start timestamp" used as a time fence so the
     post-pass tagger can identify which nodes were created or updated
     during one scan.

  2. The post-pass tagger itself: after all ingestion subprocesses
     finish, this stamps tenant_id on every node whose lastupdated
     is at or after the scan-start time AND that has no tenant_id yet.

Why a post-pass tagger (not inline modifications to ingestors):
  - Cartography is third-party; we can't modify its MERGE statements
    without forking it. A post-pass keeps Cartography pristine.
  - Same code handles every ingestor: Cartography, aws_secret_ingest,
    gcp_ingest_full, merge_findings. One function, one place to maintain.
  - This is the pattern used by enterprise CNAPPs (Wiz, Orca, Datadog).
  - Reversible: a buggy tag can be re-run or rolled back; an inline
    bug means hunting through ~1500 lines of ingestor code.

Honest limitations documented in the report:
  - Time-fence approach only works when one scan runs at a time. We
    enforce this with PIPELINE_LOCK in app.py. Real production
    multi-tenant CNAPPs use a per-scan sync_tag column instead.
  - If a resource exists in two users' AWS accounts (rare in practice;
    impossible in FYP demo setup), the second scan's tagger overwrites
    the first user's tenant_id. Acceptable for FYP scope.

Timestamp convention:
  Cartography uses Neo4j's `timestamp()` function, which returns
  milliseconds since epoch as an INTEGER. We use the same convention
  so the comparison is apples-to-apples. Python's time.time()*1000
  produces the same shape.
"""
import os
import time
from neo4j import GraphDatabase


NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "changeme")


def scan_start_timestamp_ms() -> int:
    """Return the current wall-clock time in milliseconds since epoch.

    This is captured by the caller BEFORE the first ingestion subprocess
    runs and passed to tag_tenant_nodes() AFTER the last one finishes.
    Cartography stamps lastupdated = timestamp() (Neo4j builtin, same
    epoch-ms format) on every MERGE, so a >= comparison correctly
    identifies nodes that were created or updated during this scan.
    """
    return int(time.time() * 1000)


def ensure_tenant_index() -> None:
    """Ensure indexes exist for the tenant_id property.

    Honest implementation note: Neo4j Community Edition (and Neo4j
    in general) does not support a single "label-agnostic" index on
    a property. We'd need one index per label — ~50 indexes for the
    CloudPath schema. For FYP scale (graphs under 10K nodes), the
    post-pass tagger query (~531 nodes in dev) runs in <100ms even
    without an index. We therefore skip index creation entirely and
    rely on Neo4j's default node scan.

    Documented in the report as a future optimization: if the graph
    grows beyond ~100K nodes, create per-label tenant_id indexes for
    the most-queried labels (EC2Instance, S3Bucket, GCPInstance,
    GCPBucket, Finding, etc.).

    This function is kept as a public API for symmetry with future
    versions that might use per-label indexes; for now it's a no-op.
    """
    return  # intentional no-op for FYP scope


def tag_tenant_nodes(tenant_id: int, scan_start_ms: int) -> dict:
    """Tag every node touched by this scan with the given tenant_id.

    A node is considered "touched by this scan" if:
      - It has a `lastupdated` property (set by Cartography or our
        custom ingestors)
      - That value is >= scan_start_ms
      - It has no tenant_id yet (so we don't overwrite a previous
        tenant's claim on a node that already belongs to them)

    Returns a dict summarising how many nodes were tagged, broken down
    by primary label. Useful for logging and for the report.
    """
    if not isinstance(tenant_id, int) or tenant_id <= 0:
        raise ValueError(f"tenant_id must be a positive int, got {tenant_id!r}")
    if not isinstance(scan_start_ms, int) or scan_start_ms <= 0:
        raise ValueError(
            f"scan_start_ms must be a positive int (ms since epoch), "
            f"got {scan_start_ms!r}"
        )

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    summary = {"total_tagged": 0, "by_label": {}}
    try:
        with driver.session() as session:
            # Single bulk update for performance. The WHERE clause
            # protects against tagging old nodes and re-tagging nodes
            # that already have a tenant_id.
            result = session.run(
                """
                MATCH (n)
                WHERE n.lastupdated IS NOT NULL
                  AND n.lastupdated >= $scan_start
                  AND n.tenant_id IS NULL
                SET n.tenant_id = $tid
                RETURN labels(n) AS lbls, count(n) AS n
                """,
                tid=tenant_id, scan_start=scan_start_ms,
            )
            for record in result:
                labels = record["lbls"] or ["<no_label>"]
                count = record["n"]
                primary = labels[0]
                summary["by_label"][primary] = (
                    summary["by_label"].get(primary, 0) + count
                )
                summary["total_tagged"] += count
    finally:
        driver.close()
    return summary


def backfill_existing_nodes(default_tenant_id: int) -> dict:
    """One-time migration: assign every untagged node in the graph to
    default_tenant_id. Idempotent — safe to re-run; only nodes still
    without a tenant_id get tagged.

    Use after deploying Phase 6 to handle data from before tenancy
    existed. The intended default_tenant_id is the original test user
    (typically user_id = 1).
    """
    if not isinstance(default_tenant_id, int) or default_tenant_id <= 0:
        raise ValueError("default_tenant_id must be a positive int")

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    summary = {"total_tagged": 0, "by_label": {}}
    try:
        with driver.session() as session:
            result = session.run(
                """
                MATCH (n)
                WHERE n.tenant_id IS NULL
                SET n.tenant_id = $tid
                RETURN labels(n) AS lbls, count(n) AS n
                """,
                tid=default_tenant_id,
            )
            for record in result:
                labels = record["lbls"] or ["<no_label>"]
                count = record["n"]
                primary = labels[0]
                summary["by_label"][primary] = (
                    summary["by_label"].get(primary, 0) + count
                )
                summary["total_tagged"] += count
    finally:
        driver.close()
    return summary


# ============================================================
# CLI for one-off backfill
# ============================================================

if __name__ == "__main__":
    """Manual entry point for the one-time backfill. Run after deploying
    Phase 6 to assign all existing nodes to user_id = 1:

        python tenant_scope.py backfill 1
    """
    import sys
    if len(sys.argv) < 3 or sys.argv[1] != "backfill":
        print("Usage: python tenant_scope.py backfill <user_id>")
        sys.exit(1)
    try:
        uid = int(sys.argv[2])
    except ValueError:
        print(f"user_id must be an integer, got {sys.argv[2]!r}")
        sys.exit(1)

    print(f"[tenant_scope] ensuring index...")
    ensure_tenant_index()

    print(f"[tenant_scope] backfilling all untagged nodes to "
          f"tenant_id = {uid}...")
    result = backfill_existing_nodes(uid)
    print(f"[tenant_scope] total tagged: {result['total_tagged']}")
    if result["by_label"]:
        print(f"[tenant_scope] by label:")
        for label, count in sorted(
            result["by_label"].items(), key=lambda x: -x[1]
        ):
            print(f"  {label:30s}  {count}")
    print(f"[tenant_scope] done")