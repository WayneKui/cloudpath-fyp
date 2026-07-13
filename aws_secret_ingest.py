"""
aws_secret_ingest.py — Manually ingest the GCP-key AWS Secrets Manager
secret into Neo4j, plus link it to the IAM role that can read it.

Use this if Cartography's full sync is too slow or its Secrets Manager
module is missing/broken in your version. Same schema as Cartography
would produce for SecretsManagerSecret.

Run with AWS env vars set (after assume-role into Account B):
    python aws_secret_ingest.py
"""
import os
import sys
import boto3
from neo4j import GraphDatabase

NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "changeme")

BOOTSTRAP_REGION = os.environ.get("AWS_REGION", "us-east-1")


def _list_enabled_regions() -> list:
    """Ask AWS which regions are enabled for this account instead of
    assuming one. Falls back to the bootstrap region alone if the
    account can't call ec2:DescribeRegions for some reason."""
    try:
        ec2 = boto3.client("ec2", region_name=BOOTSTRAP_REGION)
        resp = ec2.describe_regions(AllRegions=False)
        return sorted(r["RegionName"] for r in resp["Regions"])
    except Exception as e:
        print(f"WARNING: could not list regions ({e}); falling back to {BOOTSTRAP_REGION} only")
        return [BOOTSTRAP_REGION]


# 1. Fetch secret metadata from AWS (NOT the secret value), across every
#    enabled region. Secrets Manager is region-scoped — there's no
#    single "all regions" API call — so each region needs its own
#    list_secrets() call.
regions = _list_enabled_regions()
print(f"[AWS Secret Ingest] Scanning {len(regions)} region(s): {', '.join(regions)}")

secrets = []  # list of (region, secret_dict)
regions_failed = []
for region in regions:
    try:
        client = boto3.client("secretsmanager", region_name=region)
        response = client.list_secrets()
        found = response.get("SecretList", [])
        if found:
            print(f"[AWS Secret Ingest] {region}: found {len(found)} secret(s)")
        secrets.extend((region, s) for s in found)
    except Exception as e:
        print(f"  ({region}: could not list secrets — {str(e)[:80]})")
        regions_failed.append(region)

print(f"[AWS Secret Ingest] Found {len(secrets)} secret(s) total across all regions")


if regions and len(regions_failed) == len(regions):
    print(f"ERROR: all {len(regions)} region(s) failed — could not verify "
          f"whether any secrets exist. Not treating this as 'zero secrets found'.")
    sys.exit(1)

# 2. Ingest into Neo4j using Cartography-compatible schema
driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

with driver.session() as session:
    # Get the AWS account ID
    sts = boto3.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    for region, s in secrets:
        arn = s["ARN"]
        name = s["Name"]
        description = s.get("Description", "")
        kms_key_id = s.get("KmsKeyId", "")
        rotation_enabled = s.get("RotationEnabled", False)

        session.run(
            """
            MERGE (sec:SecretsManagerSecret {arn: $arn})
            SET sec.name = $name,
                sec.description = $desc,
                sec.kms_key_id = $kms,
                sec.rotation_enabled = $rot,
                sec.region = $region,
                sec.lastupdated = timestamp()
            WITH sec
            MATCH (a:AWSAccount {id: $aid})
            MERGE (a)-[:RESOURCE]->(sec)
            """,
            arn=arn, name=name, desc=description,
            kms=kms_key_id, rot=rotation_enabled,
            region=region, aid=account_id,
        )
        print(f"  Ingested: {name} ({arn}) [{region}]")

    # 3. Optional sanity check: confirm node count
    result = session.run(
        "MATCH (s:SecretsManagerSecret) RETURN count(s) AS n"
    )
    record = result.single()
    print(f"\n[AWS Secret Ingest] Total SecretsManagerSecret nodes in Neo4j: {record['n']}")

driver.close()
print("[AWS Secret Ingest] Done.")
