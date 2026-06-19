"""
Merge Prowler findings into Neo4j.

Reads every Prowler JSON-OCSF output file in prowler-output/ and links each
FAILed finding to a corresponding node in the Neo4j graph.

Phase 7: tenant-scoped. Pass --tenant-id N to attach findings ONLY to
resources belonging to tenant N. Finding nodes are stamped with
tenant_id and lastupdated so the post-pass tagger sees them too.

Design (informed by inspecting real Prowler OCSF output):

  Cloud detection: the Prowler OCSF schema includes `cloud.provider`
    ('aws' | 'gcp' | 'azure' | ...) on every finding. We use this rather
    than guessing from UID format, which previously caused all GCP
    findings to be misclassified as "unknown".

  GCP UIDs are plain identifiers, NOT URIs:
    - Project-level findings:   uid = '<project-id>'   (e.g. 'cloudpath-fyp')
    - Bucket findings:          uid = '<bucket-name>'  (e.g. 'cloudpath-public-bucket-1')
    - Compute findings:         uid = '<numeric-id>'   (e.g. '1967545635385603246')
    - Service account findings: uid = '<sa-email>'     (e.g. 'foo@proj.iam.gserviceaccount.com')
    - Service-usage findings:   uid = '<api-host>'     (e.g. 'containeranalysis.googleapis.com')

  AWS UIDs are ARNs (always start with 'arn:aws:').

  Matching is cloud-scoped AND tenant-scoped: a GCP finding only
  matches that tenant's GCP* nodes; AWS findings only match that
  tenant's AWS-flavoured nodes.

Run after every Prowler scan:
    prowler aws ...                                  # produces one .ocsf.json
    prowler gcp --project-id ...                     # produces another .ocsf.json
    python merge_findings.py --tenant-id 1           # ingests BOTH for tenant 1
"""
import json
import glob
import os
import sys
from neo4j import GraphDatabase

# ---- Connection settings ----
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "YourPassword123")

# Labels considered when matching findings to graph nodes, by cloud.
# Restricting matches to same-cloud labels prevents cross-cloud false
# positives (e.g. a GCP finding matching an AWSAccount node by coincidence).
CLOUD_LABELS = {
    "aws": [
        "AWSAccount", "AWSRole", "AWSPolicy", "AWSPrincipal",
        "EC2Instance", "EC2SecurityGroup", "EC2KeyPair", "EC2Network",
        "S3Bucket",
        "SecretsManagerSecret",
        "RDSInstance", "RDSCluster",
        "LambdaFunction",
        "ELBV2LoadBalancer", "ELBV2Listener",
        "DynamoDBTable",
    ],
    "gcp": [
        "GCPProject", "GCPInstance", "GCPBucket",
        "GCPServiceAccount", "GCPRole",
        "GCPNetwork", "GCPSubnet", "GCPFirewall", "GCPRoute",
        "GCPDisk", "GCPSAKey",
    ],
}


def collect_findings(file_path):
    """Read one OCSF JSON file and return a list of FAIL findings.

    Each returned finding includes a `cloud` field taken from the OCSF
    `cloud.provider` attribute. This is the authoritative source of
    cloud identity for the finding.
    """
    with open(file_path, encoding="utf-8") as f:
        data = json.load(f)

    findings = []
    for d in data:
        if d.get("status_code") != "FAIL":
            continue
        resources = d.get("resources", [])
        if not resources:
            continue
        uid = resources[0].get("uid")
        if not uid:
            continue
        # Authoritative cloud from OCSF schema
        cloud = (d.get("cloud") or {}).get("provider", "unknown").lower()
        findings.append({
            "uid": uid,
            "check": d.get("metadata", {}).get("event_code", "unknown"),
            "severity": d.get("severity", "Unknown"),
            "detail": d.get("status_detail", ""),
            "resource_type": resources[0].get("type", ""),
            "resource_name": resources[0].get("name", ""),
            "region": resources[0].get("region", ""),
            "cloud": cloud,
        })
    return findings


def write_unattached(session, fnd, tenant_id):
    """Persist a Finding that did not match any graph node. Tenant-scoped."""
    session.run(
        """
        MERGE (f:Finding {tenant_id: $tid, check: $check, resource_uid: $uid})
        SET f.severity = $severity,
            f.detail = $detail,
            f.resource_type = $resource_type,
            f.region = $region,
            f.cloud = $cloud,
            f.unattached = true,
            f.lastupdated = timestamp()
        """,
        tid=tenant_id,
        uid=fnd["uid"], check=fnd["check"], severity=fnd["severity"],
        detail=fnd["detail"], resource_type=fnd["resource_type"],
        region=fnd["region"], cloud=fnd["cloud"],
    )


def main():
    # Parse --tenant-id argument. Required so we never silently attach
    # findings to a default tenant; explicit > implicit.
    tenant_id = None
    if "--tenant-id" in sys.argv:
        idx = sys.argv.index("--tenant-id")
        if idx + 1 < len(sys.argv):
            try:
                tenant_id = int(sys.argv[idx + 1])
            except ValueError:
                print(f"--tenant-id must be an integer, got {sys.argv[idx+1]!r}")
                sys.exit(1)
    if tenant_id is None:
        # For backward compatibility with manual runs, default to 1.
        # The pipeline always passes --tenant-id explicitly.
        tenant_id = 1
        print(f"[merge_findings] no --tenant-id given, defaulting to {tenant_id}")
    else:
        print(f"[merge_findings] tenant_id = {tenant_id}")

    files = sorted(glob.glob("prowler-output/*.ocsf.json"))
    if not files:
        raise SystemExit("No Prowler JSON found in prowler-output/")

    print(f"Found {len(files)} Prowler output file(s):")
    for f in files:
        print(f"  - {os.path.basename(f)}")

    # Aggregate failures across all files
    all_findings = []
    for fp in files:
        f_list = collect_findings(fp)
        cloud_counts = {}
        for f in f_list:
            cloud_counts[f["cloud"]] = cloud_counts.get(f["cloud"], 0) + 1
        cloud_summary = ", ".join(
            f"{c}: {n}" for c, n in sorted(cloud_counts.items())
        )
        print(f"  {os.path.basename(fp)}: {len(f_list)} failures ({cloud_summary})")
        all_findings.extend(f_list)

    if not all_findings:
        print("\nNo failed findings to merge.")
        return
    print(f"\nTotal failed findings across all files: {len(all_findings)}")

    # Wipe existing Findings FOR THIS TENANT to prevent stale accumulation
    # Other tenants' Findings are untouched.
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    with driver.session() as session:
        prior = session.run(
            "MATCH (f:Finding {tenant_id: $tid}) RETURN count(f) AS n",
            tid=tenant_id,
        ).single()["n"]
        if prior > 0:
            session.run(
                "MATCH (f:Finding {tenant_id: $tid}) DETACH DELETE f",
                tid=tenant_id,
            )
            print(f"Cleared {prior} existing Finding node(s) for tenant {tenant_id} "
                  f"before re-ingest.")

    # Merge findings with cloud-scoped AND tenant-scoped node matching
    matched = 0
    unmatched = 0
    by_cloud = {}

    with driver.session() as session:
        for fnd in all_findings:
            cloud = fnd["cloud"]
            uid = fnd["uid"]
            labels = CLOUD_LABELS.get(cloud, [])
            by_cloud.setdefault(cloud, {"matched": 0, "unmatched": 0})

            if not labels:
                write_unattached(session, fnd, tenant_id)
                unmatched += 1
                by_cloud[cloud]["unmatched"] += 1
                continue

            # Cloud + tenant scoped matching: the resource r must
            # belong to this tenant, and the Finding is also stamped
            # with this tenant_id. Cross-tenant attachment is impossible.
            label_filter = " OR ".join(f"'{lbl}' IN labels(r)" for lbl in labels)
            query = f"""
                OPTIONAL MATCH (r)
                WHERE ({label_filter})
                  AND r.tenant_id = $tid
                  AND (r.arn = $uid
                       OR r.id = $uid
                       OR r.name = $uid
                       OR r.email = $uid
                       OR r.projectid = $uid)
                WITH r WHERE r IS NOT NULL
                LIMIT 1
                MERGE (f:Finding {{tenant_id: $tid, check: $check, resource_uid: $uid}})
                SET f.severity = $severity,
                    f.detail = $detail,
                    f.resource_type = $resource_type,
                    f.region = $region,
                    f.cloud = $cloud,
                    f.lastupdated = timestamp()
                MERGE (r)-[:HAS_FINDING]->(f)
                RETURN count(r) AS matched
            """
            result = session.run(
                query,
                tid=tenant_id,
                uid=uid, check=fnd["check"], severity=fnd["severity"],
                detail=fnd["detail"], resource_type=fnd["resource_type"],
                region=fnd["region"], cloud=cloud,
            )
            record = result.single()
            if record and record["matched"] > 0:
                matched += 1
                by_cloud[cloud]["matched"] += 1
            else:
                write_unattached(session, fnd, tenant_id)
                unmatched += 1
                by_cloud[cloud]["unmatched"] += 1

    driver.close()

    print("\nMerge complete.")
    print(f"  Findings linked to a graph node: {matched}")
    print(f"  Findings with no matching node:  {unmatched}")
    print("\n  By cloud:")
    for c in sorted(by_cloud.keys()):
        stats = by_cloud[c]
        total = stats["matched"] + stats["unmatched"]
        print(f"    {c.upper():8s}  matched: {stats['matched']:4d}  "
              f"unmatched: {stats['unmatched']:4d}  (total: {total})")
    print("\nUnmatched findings are project-level checks or services not ingested.")
    print("They are kept in the graph with f.unattached = true for visibility.")


if __name__ == "__main__":
    main()