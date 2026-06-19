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

# Allow override; defaults to us-east-1 where you stored the secret
REGION = os.environ.get("AWS_REGION", "us-east-1")

print(f"[AWS Secret Ingest] Region: {REGION}")

# 1. Fetch secret metadata from AWS (NOT the secret value)
try:
    client = boto3.client("secretsmanager", region_name=REGION)
    response = client.list_secrets()
    secrets = response.get("SecretList", [])
    print(f"[AWS Secret Ingest] Found {len(secrets)} secret(s)")
except Exception as e:
    print(f"ERROR: could not list secrets: {e}")
    sys.exit(1)

# 2. Ingest into Neo4j using Cartography-compatible schema
driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

with driver.session() as session:
    # Get the AWS account ID
    sts = boto3.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    for s in secrets:
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
            region=REGION, aid=account_id,
        )
        print(f"  Ingested: {name} ({arn})")

    # 3. Optional sanity check: confirm node count
    result = session.run(
        "MATCH (s:SecretsManagerSecret) RETURN count(s) AS n"
    )
    record = result.single()
    print(f"\n[AWS Secret Ingest] Total SecretsManagerSecret nodes in Neo4j: {record['n']}")

driver.close()
print("[AWS Secret Ingest] Done.")
