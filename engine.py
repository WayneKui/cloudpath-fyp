import os
import re
import glob
import yaml
from neo4j import GraphDatabase

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import db

NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "changeme")


# ---------------------------------------------------------------------------
# Multi-tenancy: tenant filter injection for YAML detection rules
# ---------------------------------------------------------------------------
# Every Cypher query in CloudPath must scope its MATCH patterns by tenant_id
# so that a tenant can only see their own data. For Python code we add the
# `{tenant_id: $tid}` filter explicitly (visible at the call site). For YAML
# rules — written by rule authors who shouldn't have to remember about
# tenancy — we inject the filter automatically at load time.
#
# How it works:
#   - The regex below finds node patterns with a label, e.g. `(:Label)`
#     or `(var:Label)`, and inserts `{tenant_id: $tid}` after the label.
#   - If the node already has property braces — e.g. `(i:EC2Instance {id: $x})`
#     — we insert `tenant_id: $tid, ` at the start of the existing brace block.
#   - Anonymous patterns without a label (e.g. plain `(n)`) are NOT modified
#     because we can't know what label they should match. In practice every
#     CloudPath rule uses labeled nodes — this is enforced by code review.
#
# The injector runs once when load_rules() reads each YAML. The transformed
# Cypher is what gets executed; the original YAML stays clean and readable.
# ---------------------------------------------------------------------------

# Pattern A: `(var:Label)` or `(:Label)` with NO trailing brace block.
# We rewrite to add `{tenant_id: $tid}`.
_LABELED_NO_PROPS = re.compile(
    r"""\(            # opening paren
        (\w*)         # optional variable name (capture 1)
        :             # the colon
        (\w+(?:\|\w+)*) # label name(s) -- capture 2 -- handles 'A|B' too
        \s*           # optional whitespace
        \)            # closing paren -- NOT followed by a brace
    """,
    re.VERBOSE,
)

# Pattern B: `(var:Label {existing: $props})` with property braces.
# We insert `tenant_id: $tid, ` at the start of the brace block.
_LABELED_WITH_PROPS = re.compile(
    r"""\(            # opening paren
        (\w*)         # optional variable name
        :             # colon
        (\w+(?:\|\w+)*) # label name(s)
        \s*           # whitespace
        \{            # opening brace
        \s*           # whitespace
    """,
    re.VERBOSE,
)


def inject_tenant_filter(cypher: str) -> str:
    """Add `tenant_id: $tid` to every labeled node pattern in a Cypher query.
    """
    if not cypher:
        return cypher

    # Pass 1: nodes with existing property braces — insert tenant_id at start
    def _with_props(m):
        var, label = m.group(1), m.group(2)
        return f"({var}:{label} {{tenant_id: $tid, "
    cypher = _LABELED_WITH_PROPS.sub(_with_props, cypher)

    # Pass 2: bare labeled nodes — wrap with new property braces.
    # We must not re-match nodes already fixed by pass 1, so check that
    # the closing paren isn't immediately followed by braces. The regex
    # already ends at `)`, so we just need to peek the next char.
    def _no_props(m):
        var, label = m.group(1), m.group(2)
        end = m.end()
        if end < len(cypher) and cypher[end] == "{":
            return m.group(0)  # unchanged
        return f"({var}:{label} {{tenant_id: $tid}})"
    cypher = _LABELED_NO_PROPS.sub(_no_props, cypher)

    return cypher

# ---------------------------------------------------------------------------
# Rule loading: supports BOTH old (single-cloud) and new (unified) YAML formats
# ---------------------------------------------------------------------------

# MITRE tactic order (kill chain). Lower number = earlier in an attack.
TACTIC_ORDER = {
    "Initial Access": 1,
    "Execution": 2,
    "Persistence": 3,
    "Privilege Escalation": 4,
    "Defense Evasion": 5,
    "Credential Access": 6,
    "Discovery": 7,
    "Lateral Movement": 8,
    "Collection": 9,
    "Exfiltration": 10,
    "Impact": 11,
}

# ---------------------------------------------------------------------------
# CVSS-aligned attack path scoring
# Grounded in CVSS v3.1/v4.0 (FIRST.org): Base score = f(Exploitability, Impact)
# Adapted for attack paths, with a cloud-context multiplier (cf. Wiz, Orca).
# ---------------------------------------------------------------------------

# Impact weighting by tactic (CIA-triad analogue: later tactics = more harm)
TACTIC_IMPACT = {
    "Impact": 0.9,
    "Exfiltration": 0.9,
    "Collection": 0.7,
    "Privilege Escalation": 0.6,
    "Lateral Movement": 0.6,
    "Credential Access": 0.6,
    "Persistence": 0.4,
    "Execution": 0.4,
    "Discovery": 0.3,
    "Initial Access": 0.3,
    "Defense Evasion": 0.3,
}

# Severity -> impact magnitude (CVSS-style)
SEVERITY_TO_IMPACT = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}


def load_rules(rules_dir="rules"):
    """Loads YAML detection rules.

    Supports two formats for backward compatibility:

      OLD FORMAT (single-cloud):
          id: T1190
          cloud: aws
          cypher: |
            MATCH (...) RETURN ...

      NEW FORMAT (unified, multi-cloud):
          id: T1190
          detections:
            - cloud: aws
              cypher: |
                MATCH (...) RETURN ...
            - cloud: gcp
              cypher: |
                MATCH (...) RETURN ...

    Internally, both formats are expanded into a flat list where each
    entry represents one (technique, cloud) detection. This means a
    unified rule with 2 detections becomes 2 internal rule entries.
    """
    rules = []
    for path in glob.glob(os.path.join(rules_dir, "*.yaml")):
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f)
            if not raw:
                continue

            # New unified format: has a 'detections' list
            if "detections" in raw and isinstance(raw["detections"], list):
                for det in raw["detections"]:
                    rule = {
                        "id": raw["id"],
                        "mitre_name": raw["mitre_name"],
                        "tactic": raw["tactic"],
                        "severity": raw.get("severity", "medium"),
                        "description": raw.get("description", ""),
                        "cloud": det.get("cloud", "unknown"),
                        # PHASE 7: auto-inject tenant_id filter so rule
                        # authors don't have to remember it.
                        "cypher": inject_tenant_filter(det["cypher"]),
                        "_file": os.path.basename(path),
                        "_format": "unified",
                    }
                    rules.append(rule)
            # Old single-cloud format: top-level cypher
            elif "cypher" in raw:
                rule = {
                    "id": raw["id"],
                    "mitre_name": raw["mitre_name"],
                    "tactic": raw["tactic"],
                    "severity": raw.get("severity", "medium"),
                    "description": raw.get("description", ""),
                    "cloud": raw.get("cloud", "unknown"),
                    # PHASE 7: auto-inject tenant_id filter
                    "cypher": inject_tenant_filter(raw["cypher"]),
                    "_file": os.path.basename(path),
                    "_format": "legacy",
                }
                rules.append(rule)
            else:
                print(f"  WARN: rule {path} has neither 'detections' nor 'cypher', skipped")

    # Friendly summary by cloud
    by_cloud = {}
    for r in rules:
        by_cloud[r["cloud"]] = by_cloud.get(r["cloud"], 0) + 1
    cloud_summary = ", ".join(f"{c}: {n}" for c, n in by_cloud.items())
    print(f"Loaded {len(rules)} detection(s) across clouds ({cloud_summary}).")
    return rules


# ---------------------------------------------------------------------------
# Custom (per-tenant) rules
# ---------------------------------------------------------------------------
# Users can author their own Cypher detection rules from /rules. Unlike the
# 4 built-in YAML rules — written by us, code-reviewed — custom rule Cypher
# is arbitrary text typed by a customer, run against a Neo4j database that
# holds EVERY tenant's data. That needs two independent locks, not one:
#
#   1. validate_custom_rule_cypher() below — a keyword blocklist run at
#      SAVE time, so a user gets an immediate, friendly error instead of
#      a silent failure or a successful save of something dangerous.
#   2. run_rule() executes ALL rules (built-in and custom) inside a Neo4j
#      READ transaction (session.execute_read) — the database itself
#      refuses to execute a write, even if something slipped past (1).
#
# Tenant isolation for custom rules reuses inject_tenant_filter(), the
# exact same regex-based rewrite the 4 built-in rules already depend on
# — so a custom rule's MATCH clauses are scoped to the author's own data
# without the author having to remember to type a tenant filter.

_CYPHER_BLOCKED_KEYWORDS = (
    "CREATE", "MERGE", "SET", "DELETE", "DETACH", "REMOVE", "DROP",
    "CALL", "FOREACH", "LOAD CSV",
)

_APOC_CALL = re.compile(r"\bapoc\.[\w.]+", re.IGNORECASE)
_CYPHER_MAX_LEN = 4000


def validate_custom_rule_cypher(cypher: str) -> str | None:
    """Return None if the Cypher is acceptable for a custom rule,
    otherwise a human-readable reason it was rejected.

    This is a first line of defense (clear error message at save time),
    not the only one — run_rule() also forces every rule through a
    read-only Neo4j transaction regardless of what passes here.
    """
    if not cypher or not cypher.strip():
        return "Cypher query is required."
    if len(cypher) > _CYPHER_MAX_LEN:
        return f"Cypher query is too long (max {_CYPHER_MAX_LEN} characters)."
    if not re.search(r"\bMATCH\b", cypher, re.IGNORECASE):
        return "Cypher query must contain a MATCH clause."
    if not re.search(r"\bRETURN\b", cypher, re.IGNORECASE):
        return "Cypher query must contain a RETURN clause (return at least node_id, node_type)."
    apoc_match = _APOC_CALL.search(cypher)
    if apoc_match:
        return (
            f"The procedure '{apoc_match.group()}' is not allowed in a "
            f"custom rule. APOC procedures can read local files, make "
            f"network calls, or modify the graph outside normal Cypher — "
            f"custom rules may only use MATCH ... RETURN."
        )
    for kw in _CYPHER_BLOCKED_KEYWORDS:
        if re.search(r"\b" + re.escape(kw) + r"\b", cypher, re.IGNORECASE):
            return (
                f"'{kw}' is not allowed in a custom rule. Custom rules can "
                f"only read and return data (MATCH ... RETURN), not modify "
                f"the graph or call external procedures."
            )
    # SECURITY: inject_tenant_filter() only scopes node patterns that
    # carry an explicit label, e.g. (b:S3Bucket) — it can't safely scope
    # an unlabeled pattern like (n) since it doesn't know what property
    # to filter on. The 4 built-in rules are all written with labels (a
    # code-review guarantee); a custom rule has no such guarantee, so a
    # query like "MATCH (n) RETURN n.id AS node_id, labels(n)[0] AS
    # node_type" would run completely unscoped — reading every tenant's
    # data. Refuse to save anything that doesn't actually end up scoped.
    if "tenant_id: $tid" not in inject_tenant_filter(cypher):
        return (
            "Every MATCH pattern must use a specific node label, e.g. "
            "MATCH (b:S3Bucket) ... — not an unlabeled MATCH (n). This is "
            "required so the rule can be automatically scoped to your own "
            "account's data."
        )
    return None


def load_custom_rules_for_tenant(tenant_id: int) -> list[dict]:
    """Load one tenant's saved custom rules from Postgres, in the same
    shape load_rules() produces, so detect_all() can't tell the
    difference between a built-in and a custom rule.

    Cypher is passed through inject_tenant_filter() exactly like the
    YAML rules — the author never has to type a tenant filter, and it
    can never be omitted by mistake.

    Defense in depth: validate_custom_rule_cypher() already refuses to
    SAVE a rule that inject_tenant_filter() can't scope, but this loads
    straight from the DB, not through that gate — a row saved before
    this check existed, or one edited directly in Postgres, could still
    be unscoped. Skip (don't run) any rule where injection didn't
    actually add a tenant filter, rather than trusting the save-time
    check alone for something this security-sensitive.
    """
    rows = db.list_custom_rules_sync(tenant_id)
    rules = []
    for row in rows:
        injected = inject_tenant_filter(row["cypher"])
        if "tenant_id: $tid" not in injected:
            print(f"[engine] WARNING: custom rule {row['rule_key']!r} "
                  f"(id={row['id']}, user={tenant_id}) has no scopable "
                  f"labeled node pattern — skipping to avoid an unscoped "
                  f"cross-tenant query.", flush=True)
            continue
        rules.append({
            "id": row["rule_key"],
            "mitre_name": row["mitre_name"],
            "tactic": row["tactic"],
            "severity": row["severity"],
            "description": row.get("description") or "",
            "cloud": row["cloud"],
            "cypher": injected,
            "_file": f"custom:{row['id']}",
            "_format": "custom",
            "_source": "custom",
            "_db_id": row["id"],
        })
    return rules


def load_builtin_rules_summary(rules_dir="rules"):
    """One display row per built-in rule FILE (not per detection).

    load_rules() flattens a unified multi-cloud rule (e.g. T1078, which
    has both an aws and a gcp detection) into 2 separate entries — that's
    the right shape for detect_all(), but wrong for a human-facing rule
    list, where "T1078" should appear once, not twice. This walks the
    YAML files directly instead of going through load_rules(), so it
    can't drift out of sync with what's actually in rules_dir the way a
    hand-maintained list in a template would.
    """
    summary = []
    for path in glob.glob(os.path.join(rules_dir, "*.yaml")):
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f)
            if not raw:
                continue
        if "detections" in raw and isinstance(raw["detections"], list):
            clouds = sorted({d.get("cloud", "unknown") for d in raw["detections"]})
        else:
            clouds = [raw.get("cloud", "unknown")]
        summary.append({
            "id": raw["id"],
            "mitre_name": raw["mitre_name"],
            "tactic": raw["tactic"],
            "severity": raw.get("severity", "medium"),
            "description": (raw.get("description") or "").strip(),
            "cloud": "+".join(clouds),
        })
    summary.sort(key=lambda r: r["id"])
    return summary


def run_rule(session, rule, tenant_id):
    """Execute a rule's (auto-injected) Cypher with the running tenant's id.

    The cypher has already been transformed by inject_tenant_filter at
    load time, so it expects $tid as a parameter on every labeled node.

    Runs inside a READ transaction (session.execute_read), not a plain
    session.run(). This matters once custom (user-authored) rules exist
    alongside the built-in ones: even if validate_custom_rule_cypher()
    or inject_tenant_filter() ever missed something, Neo4j itself
    refuses to execute a write inside a read transaction — a second,
    independent lock, not just a keyword blocklist.
    """
    def _work(tx):
        result = tx.run(rule["cypher"], tid=tenant_id)
        return [record.data() for record in result]
    try:
        return session.execute_read(_work)
    except Exception as e:
        print(f"  ERROR in rule {rule['id']} ({rule['cloud']}): {e}")
        return []


def detect_all(session, rules, tenant_id):
    """Run every detection scoped to one tenant, return findings tagged with cloud."""
    detections = []
    for rule in rules:
        for match in run_rule(session, rule, tenant_id):
            detections.append({
                "id": rule["id"],
                "mitre_name": rule["mitre_name"],
                "tactic": rule["tactic"],
                "severity": rule["severity"],
                "cloud": rule["cloud"],
                "node_id": match.get("node_id"),
                "node_type": match.get("node_type"),
                "detail": match.get("detail"),
            })
    return detections


# ---------------------------------------------------------------------------
# Reachability checks (cloud-specific)
# Each cloud has its own identity/policy graph, so reachability is per-cloud.
# ---------------------------------------------------------------------------
def can_role_reach_bucket_aws(session, ec2_node_id, bucket_name, tenant_id):
    """AWS reachability: EC2 instance role -> S3 bucket, via BFS shortestPath.
    Scoped to one tenant — only nodes owned by tenant_id participate."""
    query = """
    MATCH (i:EC2Instance {tenant_id: $tid, id: $ec2_id})
    MATCH (i)-[:ASSOCIATED_WITH|INSTANCE_PROFILE]-(prof:AWSInstanceProfile {tenant_id: $tid})
    MATCH (r:AWSRole {tenant_id: $tid})-[:ASSOCIATED_WITH]-(prof)
    MATCH (r)-[:POLICY]-(p:AWSPolicy {tenant_id: $tid})
    WHERE p.name CONTAINS 'S3' OR p.name CONTAINS 'FullAccess'
       OR p.name CONTAINS 'Administrator'
    OPTIONAL MATCH sp = shortestPath((r)-[*1..6]-(b:S3Bucket {tenant_id: $tid, name: $bucket}))
    RETURN count(p) AS priv_count, sp IS NOT NULL AS path_exists
    """
    result = session.run(query, tid=tenant_id, ec2_id=ec2_node_id, bucket=bucket_name)
    record = result.single()
    if not record:
        return False
    return bool(record["priv_count"] > 0)


def can_sa_reach_bucket_gcp(session, instance_name, bucket_name, tenant_id):
    """GCP reachability: Compute instance's SA -> Cloud Storage bucket.
    Scoped to one tenant.

    Detects whether the SA attached to the instance has a project-level role
    (Editor, Owner, Storage Admin, or anything with 'storage' permissions)
    that would let it access the named bucket.
    """
    query = """
    MATCH (i:GCPInstance {tenant_id: $tid, name: $iname})-[:USES_SERVICE_ACCOUNT]->(sa:GCPServiceAccount {tenant_id: $tid})
    OPTIONAL MATCH (sa)-[:HAS_ROLE]->(r:GCPRole {tenant_id: $tid})
    WHERE r.name IN ['roles/editor', 'roles/owner', 'roles/storage.admin']
       OR r.name CONTAINS 'storage'
       OR r.name CONTAINS 'admin'
    OPTIONAL MATCH (b:GCPBucket {tenant_id: $tid, name: $bucket})
    RETURN count(r) AS priv_count, b IS NOT NULL AS bucket_exists
    """
    result = session.run(query, tid=tenant_id, iname=instance_name, bucket=bucket_name)
    record = result.single()
    if not record:
        return False
    return bool(record["priv_count"] > 0 and record["bucket_exists"])


# ---------------------------------------------------------------------------
# CROSS-CLOUD BRIDGE
# AWS Secret holding a GCP credential -> GCP Service Account
# This is the synthetic link that makes cross-cloud attack paths possible.
# ---------------------------------------------------------------------------
def link_cross_cloud_credentials(session, tenant_id):
    """Structurally detect AWS secrets that could plausibly contain
    cross-cloud credentials, scoped to one tenant.

    The bridge edges are created BETWEEN nodes that BOTH belong to the
    same tenant. A user's secret can only be bridged to that user's GCP
    SAs — never to another tenant's. The bridge edges themselves don't
    carry tenant_id (relationships in our schema don't have tenant_id),
    but because both endpoints are tenant-scoped, querying through them
    from a tenant-filtered node naturally stays within that tenant.
    """
    # Clean up any stale bridge edges from previous runs FOR THIS TENANT
    # before re-linking. We restrict the cleanup to this tenant's secrets
    # so user A's re-scan doesn't blow away user B's bridge edges.
    session.run("""
        MATCH (:SecretsManagerSecret {tenant_id: $tid})-[r:CONTAINS_CREDENTIAL_FOR]->(:GCPServiceAccount {tenant_id: $tid})
        DELETE r
    """, tid=tenant_id)

    # Condition 2 check: are there GCP service accounts at all FOR THIS TENANT?
    gcp_check = session.run("""
        MATCH (sa:GCPServiceAccount {tenant_id: $tid})
        WHERE NOT toLower(sa.email) CONTAINS 'compute@developer'
          AND NOT sa.email STARTS WITH 'service-'
        RETURN count(sa) AS n
    """, tid=tenant_id)
    gcp_count = gcp_check.single()["n"]
    if gcp_count == 0:
        return 0

    # Find ALL secrets (FOR THIS TENANT) that have at least one principal
    # with read permission. Truly general — no name/description matching.
    secrets_result = session.run("""
        MATCH (s:SecretsManagerSecret {tenant_id: $tid})
        OPTIONAL MATCH (s)<-[*1..4]-(p:AWSPolicy {tenant_id: $tid})
        WHERE p.name CONTAINS 'Secret'
           OR p.name CONTAINS 'FullAccess'
           OR p.name CONTAINS 'Administrator'
           OR p.name CONTAINS 'AllowRead'
        WITH s, count(p) AS policy_count
        RETURN s.arn AS arn,
               s.name AS name,
               coalesce(s.description, '') AS description,
               coalesce(s.tags, []) AS tags,
               policy_count
    """, tid=tenant_id)
    all_secrets = [dict(r) for r in secrets_result]
    if not all_secrets:
        return 0

    edges_created = 0
    for secret in all_secrets:
        arn = secret["arn"]

        # Compute optional confidence signals (do not gate detection)
        name = (secret["name"] or "").lower()
        desc = (secret["description"] or "").lower()
        tags = [str(t).lower() for t in (secret["tags"] or [])]

        signals = []
        if any(kw in name for kw in ["gcp", "google", "gcloud", "gserviceaccount"]):
            signals.append("name_pattern")
        if any(kw in desc for kw in ["gcp", "google cloud", "service account", "gserviceaccount"]):
            signals.append("description_pattern")
        if any(("gcp" in t or "google" in t or "provider:gcp" in t) for t in tags):
            signals.append("tag_match")

        if signals and secret["policy_count"] > 0:
            confidence = "high"
        elif signals or secret["policy_count"] > 0:
            confidence = "medium"
        else:
            confidence = "low"

        if confidence == "low":
            continue

        signals_str = ",".join(signals) if signals else "structural_only"

        # Tier 1: name-token match (with broader matching than v7) — TENANT-SCOPED
        if signals:
            tier1 = session.run("""
                MATCH (s:SecretsManagerSecret {tenant_id: $tid, arn: $arn})
                MATCH (sa:GCPServiceAccount {tenant_id: $tid})
                WHERE NOT toLower(sa.email) CONTAINS 'compute@developer'
                  AND NOT sa.email STARTS WITH 'service-'
                  AND NOT toLower(sa.email) CONTAINS 'scanner'
                WITH s, sa,
                     [token IN split(toLower($secret_name), '-')
                      WHERE size(token) >= 4] AS secret_tokens,
                     toLower(split(sa.email, '@')[0]) AS sa_local
                WHERE any(token IN secret_tokens WHERE sa_local CONTAINS token)
                   OR any(token IN split(sa_local, '-')
                          WHERE size(token) >= 4
                            AND toLower($secret_name) CONTAINS token)
                MERGE (s)-[r:CONTAINS_CREDENTIAL_FOR]->(sa)
                SET r.confidence = 'high',
                    r.detected_by = 'name_token_match',
                    r.signals = $signals,
                    r.synthetic = true
                RETURN count(r) AS n
            """, tid=tenant_id, arn=arn, secret_name=name, signals=signals_str)
            rec = tier1.single()
            if rec and rec["n"] > 0:
                edges_created += rec["n"]
                continue

        # Tier 2: structural fallback — TENANT-SCOPED
        tier2 = session.run("""
            MATCH (s:SecretsManagerSecret {tenant_id: $tid, arn: $arn})
            MATCH (sa:GCPServiceAccount {tenant_id: $tid})
            WHERE NOT toLower(sa.email) CONTAINS 'compute@developer'
              AND NOT sa.email STARTS WITH 'service-'
              AND NOT toLower(sa.email) CONTAINS 'scanner'
            OPTIONAL MATCH (sa)-[:HAS_ROLE]->(r:GCPRole {tenant_id: $tid})
            WHERE r.name CONTAINS 'storage'
               OR r.name CONTAINS 'admin'
               OR r.name CONTAINS 'editor'
               OR r.name CONTAINS 'owner'
               OR r.name CONTAINS 'viewer'
            WITH s, sa, count(r) AS access_score
            ORDER BY access_score DESC, sa.email ASC
            LIMIT 1
            MERGE (s)-[link:CONTAINS_CREDENTIAL_FOR]->(sa)
            SET link.confidence = $conf,
                link.detected_by = 'most_exploitable_structural',
                link.signals = $signals,
                link.synthetic = true
            RETURN count(link) AS n
        """, tid=tenant_id, arn=arn, conf=confidence, signals=signals_str)
        rec = tier2.single()
        if rec:
            edges_created += rec["n"]

    return edges_created


def can_secret_reach_gcp_sa(session, secret_arn, gcp_sa_email, tenant_id):
    """Check if an AWS secret has a synthetic bridge to a given GCP SA.
    Used by the chainer to validate cross-cloud links. Tenant-scoped."""
    result = session.run("""
        MATCH (s:SecretsManagerSecret {tenant_id: $tid, arn: $arn})
              -[:CONTAINS_CREDENTIAL_FOR]->
              (sa:GCPServiceAccount {tenant_id: $tid, email: $email})
        RETURN count(sa) AS n
    """, tid=tenant_id, arn=secret_arn, email=gcp_sa_email)
    record = result.single()
    return bool(record and record["n"] > 0)


def aws_role_can_read_secret(session, ec2_node_id, secret_arn, tenant_id):
    """Check if the EC2's role has secretsmanager:GetSecretValue permission
    that would allow it to extract the named secret. Tenant-scoped."""
    result = session.run("""
        MATCH (i:EC2Instance {tenant_id: $tid, id: $ec2_id})
        MATCH (i)-[:ASSOCIATED_WITH|INSTANCE_PROFILE]-(prof:AWSInstanceProfile {tenant_id: $tid})
        MATCH (r:AWSRole {tenant_id: $tid})-[:ASSOCIATED_WITH]-(prof)
        MATCH (r)-[:POLICY]-(p:AWSPolicy {tenant_id: $tid})
        WHERE p.name CONTAINS 'Secret'
           OR p.name CONTAINS 'FullAccess'
           OR p.name CONTAINS 'Administrator'
           OR p.name CONTAINS 'AllowReadGCPSecret'
        OPTIONAL MATCH (sec:SecretsManagerSecret {tenant_id: $tid, arn: $arn})
        RETURN count(p) AS priv_count, sec IS NOT NULL AS secret_exists
    """, tid=tenant_id, ec2_id=ec2_node_id, arn=secret_arn)
    record = result.single()
    if not record:
        return False
    return bool(record["priv_count"] > 0 and record["secret_exists"])


# ---------------------------------------------------------------------------
# Attack-path chaining: cloud-aware
# ---------------------------------------------------------------------------
def build_attack_paths(session, detections, tenant_id):
    """Chain detections into attack paths using DEPTH-FIRST SEARCH (DFS).

    Cloud-aware: chains can be single-cloud OR cross-cloud. Cross-cloud
    chains require a bridge edge (synthetic CONTAINS_CREDENTIAL_FOR) which
    is created elsewhere — see link_cross_cloud_credentials().

    Links between consecutive techniques are validated by:
      (1) Shared-node adjacency (same node_id)
      (2) AWS BFS reachability: EC2 -> S3 (via can_role_reach_bucket_aws)
      (3) GCP BFS reachability: GCPInstance -> GCPBucket (via can_sa_reach_bucket_gcp)

    Tactic ordering enforces a valid MITRE ATT&CK kill-chain direction.

    All node-graph queries are tenant-scoped — chains only form between
    nodes owned by the same tenant.
    """
    ordered = sorted(detections, key=lambda d: TACTIC_ORDER.get(d["tactic"], 99))
    paths = []

    def is_linked(chain, candidate):
        cand_tactic = TACTIC_ORDER.get(candidate["tactic"], 99)
        for step in chain:
            step_tactic = TACTIC_ORDER.get(step["tactic"], 99)
            if cand_tactic <= step_tactic:
                continue  # kill chain must move forward

            # Link 1: shared-node adjacency
            if candidate["node_id"] == step["node_id"]:
                return True

            # Link 2: AWS BFS reachability (EC2 -> S3 bucket)
            if (step["node_type"] == "EC2Instance"
                    and candidate["node_type"] == "S3Bucket"):
                if can_role_reach_bucket_aws(
                    session, step["node_id"], candidate["node_id"], tenant_id
                ):
                    return True

            # Link 3: GCP BFS reachability (GCPInstance -> GCPBucket)
            if (step["node_type"] == "GCPInstance"
                    and candidate["node_type"] == "GCPBucket"):
                if can_sa_reach_bucket_gcp(
                    session, step["node_id"], candidate["node_id"], tenant_id
                ):
                    return True

            # Link 4: AWS EC2 with secret-read permission -> AWS Secret
            if (step["node_type"] == "EC2Instance"
                    and candidate["node_type"] == "SecretsManagerSecret"):
                if aws_role_can_read_secret(
                    session, step["node_id"], candidate["node_id"], tenant_id
                ):
                    return True

            # Link 5: CROSS-CLOUD BRIDGE — AWS Secret -> GCP ServiceAccount
            if (step["node_type"] == "SecretsManagerSecret"
                    and candidate["node_type"] == "GCPServiceAccount"):
                if can_secret_reach_gcp_sa(
                    session, step["node_id"], candidate["node_id"], tenant_id
                ):
                    return True

            # Link 5b: CROSS-CLOUD TRANSITIVE — AWS Secret -> GCP Bucket
            if (step["node_type"] == "SecretsManagerSecret"
                    and candidate["node_type"] == "GCPBucket"):
                check = session.run("""
                    MATCH (s:SecretsManagerSecret {tenant_id: $tid, arn: $arn})
                          -[:CONTAINS_CREDENTIAL_FOR]->
                          (sa:GCPServiceAccount {tenant_id: $tid})-[:HAS_ROLE]->(r:GCPRole {tenant_id: $tid})
                    WHERE r.name CONTAINS 'storage'
                       OR r.name CONTAINS 'admin'
                       OR r.name CONTAINS 'editor'
                       OR r.name CONTAINS 'owner'
                       OR r.name CONTAINS 'viewer'
                    MATCH (b:GCPBucket {tenant_id: $tid, name: $bucket})
                    RETURN count(r) AS n
                """, tid=tenant_id, arn=step["node_id"], bucket=candidate["node_id"])
                rec = check.single()
                if rec and rec["n"] > 0:
                    return True

            # Link 6: GCP ServiceAccount -> GCP Bucket (when SA has access)
            if (step["node_type"] == "GCPServiceAccount"
                    and candidate["node_type"] == "GCPBucket"):
                check = session.run("""
                    MATCH (sa:GCPServiceAccount {tenant_id: $tid, email: $email})-[:HAS_ROLE]->(r:GCPRole {tenant_id: $tid})
                    WHERE r.name IN ['roles/editor', 'roles/owner', 'roles/storage.admin']
                       OR r.name CONTAINS 'storage'
                       OR r.name CONTAINS 'admin'
                       OR r.name CONTAINS 'viewer'
                    MATCH (b:GCPBucket {tenant_id: $tid, name: $bucket})
                    RETURN count(r) AS n
                """, tid=tenant_id, email=step["node_id"], bucket=candidate["node_id"])
                rec = check.single()
                if rec and rec["n"] > 0:
                    return True
        return False

    def dfs_extend(chain):
        """Recursive DFS: explore every valid extension branch and save the
        chain as a path when it ends at an Impact tactic (the attacker's
        kill-chain endpoint).

        Saving only Impact-terminated chains has two benefits:
          1. Partial chains like T1190→T1078 (Initial Access→Priv Esc only)
             aren't surfaced as attack "paths" because they don't represent
             a completed breach.
          2. Two different DFS orderings that reach the same final node-set
             via different intermediate sequences are correctly deduplicated
             later via set-based deduplication.

        Both AWS-only-ending paths AND cross-cloud-continuation paths are
        preserved because each represents a distinct security outcome:
          - "data exfiltrated to AWS S3" (AWS-only)
          - "attacker pivoted from AWS into GCP" (cross-cloud)
        """
        # Save the chain if it terminates at Impact (length >= 2).
        # This filters out partial/incomplete attack chains (e.g. T1190→T1078
        # alone) and only surfaces complete attack outcomes.
        if len(chain) >= 2:
            last_tactic = TACTIC_ORDER.get(chain[-1]["tactic"], 99)
            if last_tactic >= TACTIC_ORDER.get("Impact", 9):
                paths.append(sorted(chain, key=lambda d: TACTIC_ORDER.get(d["tactic"], 99)))

        for cand in ordered:
            if cand in chain:
                continue
            if is_linked(chain, cand):
                dfs_extend(chain + [cand])

    # DFS starts from each earliest-tactic detection
    earliest = min((TACTIC_ORDER.get(d["tactic"], 99) for d in ordered), default=99)
    starters = [d for d in ordered if TACTIC_ORDER.get(d["tactic"], 99) == earliest]
    for s in starters:
        dfs_extend([s])

    # Step 1: Collapse paths with the same node-set into one representative.
    # DFS can generate two paths with identical node-sets but different
    # Impact-step orderings (e.g. T1530_AWS-then-T1530_GCP vs T1530_GCP-
    # then-T1530_AWS). These represent the same attack outcome; keep only
    # the one whose ordering best matches MITRE kill-chain progression.
    seen_sets = {}
    for p in paths:
        node_set = frozenset((s["id"], s.get("cloud"), s["node_id"]) for s in p)
        # Score by monotonicity of kill-chain progression
        order_score = sum(
            1 for i in range(len(p) - 1)
            if TACTIC_ORDER.get(p[i]["tactic"], 99)
               <= TACTIC_ORDER.get(p[i + 1]["tactic"], 99)
        )
        if node_set not in seen_sets or order_score > seen_sets[node_set][1]:
            seen_sets[node_set] = (p, order_score)
    set_deduped = [v[0] for v in seen_sets.values()]

    # Step 2: Keep only MAXIMAL paths from the set-deduped list.
    #
    # A path is dropped if it is a subsequence of a longer path AND shares
    # the same terminal Impact node. This preserves the AWS-only path
    # (ending at AWS S3) alongside the cross-cloud path (ending at GCP
    # bucket) because their terminuses differ.
    def is_subsequence_of(short, long_path):
        if len(short) >= len(long_path):
            return False
        short_keys = [(s["id"], s.get("cloud"), s["node_id"]) for s in short]
        long_keys = [(s["id"], s.get("cloud"), s["node_id"]) for s in long_path]
        i = 0
        for k in long_keys:
            if i < len(short_keys) and k == short_keys[i]:
                i += 1
        return i == len(short_keys)

    def has_distinct_outcome(short, long_path):
        s_last = short[-1]
        l_last = long_path[-1]
        return (s_last["node_id"] != l_last["node_id"]
                or s_last.get("cloud") != l_last.get("cloud"))

    maximal = []
    for p in set_deduped:
        is_redundant = any(
            is_subsequence_of(p, q) and not has_distinct_outcome(p, q)
            for q in set_deduped if q is not p
        )
        if not is_redundant:
            maximal.append(p)

    # Final ordered-sequence dedup: collapse any paths that have identical
    # step sequences (rare after the set-based dedup, but defensive).
    seen, unique = set(), []
    for p in maximal:
        key = tuple((s["id"], s.get("cloud"), s["node_id"]) for s in p)
        if key not in seen:
            seen.add(key)
            unique.append(p)

    return unique


def is_cross_cloud(path):
    """A path is cross-cloud if it has steps from more than one cloud."""
    clouds_in_path = {s.get("cloud") for s in path if s.get("cloud") not in (None, "unknown")}
    return len(clouds_in_path) > 1


def score_path(path):
    """Multi-factor attack path risk score (0.0 - 10.0).

    Approach: combines several independently-cited risk factors rather than
    relying on a single magic multiplier. This follows the multi-factor
    methodology documented by commercial CNAPPs (Orca, Wiz, Lightspin).

    Factors (each independently grounded):

      1. Base Exploitability
         Source: CVSS v3.1 Specification, Section 7.1 (FIRST.org, 2019)
         Internet-facing entry (Attack Vector: Network) = 0.85
         Non-internet entry (Attack Vector: Adjacent/Local) = 0.55

      2. Length penalty (multi-stage attack probability decay)
         Source: Modi & Patel (2018), "Cyber Attacks in Cloud Computing:
         Modelling Multi-stage Attacks using Probability Density"
         "The probability of reaching a target located further in the
         attack network reduces with an increase in atomic attack steps."
         Implemented as: length_factor = max(0.6, 1.0 - 0.05 * (length-1))

      3. Scope change multiplier
         Source: CVSS v3.1 Specification, Section 7.1 (FIRST.org, 2019)
         Cross-authority impacts use Changed scope with ISC coefficient
         7.52 vs Unchanged 6.42. Ratio = 1.17. Cross-cloud paths cross
         security authorities (AWS account boundary -> GCP project).

      4. Blast radius (resource diversity)
         Source: Orca Security (2023), "Cloud Attack Path Analysis";
         Lightspin / Roy Maor (2021), "Attack Path Analysis in Stateful
         Cloud Graphs". Risk grows with the number of distinct resource
         categories an attacker traverses (network, identity, storage,
         compute, secret). 0.05 added per distinct category, capped at 0.25.

      5. Impact component (CIA-triad analogue)
         Source: CVSS v3.1 Specification, Section 7.1
         max(TACTIC_IMPACT) x max(SEVERITY_TO_IMPACT) across path steps.

    Final score: (E x I x scope_multiplier + blast_radius_bonus) x 10
    capped at 10.0, mapped to CVSS severity bands (FIRST.org standard).
    """
    cross_cloud = is_cross_cloud(path)

    # --- FACTOR 1: Base exploitability (CVSS Attack Vector analogue) ---
    has_internet_entry = any(s["tactic"] == "Initial Access" for s in path)
    base_exploitability = 0.85 if has_internet_entry else 0.55

    # --- FACTOR 2: Length penalty (Modi & Patel 2018) ---
    length = len(path)
    length_factor = max(0.6, 1.0 - 0.05 * (length - 1))
    exploitability = base_exploitability * length_factor

    # --- FACTOR 5: Impact ---
    max_tactic_impact = max(TACTIC_IMPACT.get(s["tactic"], 0.3) for s in path)
    max_severity = max(
        SEVERITY_TO_IMPACT.get(s["severity"].lower(), 0.25) for s in path
    )
    impact = max_tactic_impact * max_severity

    # --- FACTOR 3: Scope multiplier (CVSS v3.1 Section 7.1) ---
    # 1.17 = 7.52/6.42, ratio of Changed-scope to Unchanged-scope ISC
    # coefficients from the CVSS v3.1 specification.
    scope_multiplier = 1.17 if cross_cloud else 1.0

    # --- FACTOR 4: Blast radius (Orca 2023, Lightspin 2021) ---
    # Count distinct resource categories traversed. More diverse = higher
    # impact because more controls bypassed.
    resource_categories = set()
    for step in path:
        nt = step["node_type"]
        if nt in ("EC2Instance", "GCPInstance"):
            resource_categories.add("compute")
        elif nt in ("S3Bucket", "GCPBucket"):
            resource_categories.add("storage")
        elif nt in ("SecretsManagerSecret",):
            resource_categories.add("secret")
        elif nt in ("AWSRole", "AWSPolicy", "GCPServiceAccount", "GCPRole"):
            resource_categories.add("identity")
        elif nt in ("EC2SecurityGroup", "GCPFirewall"):
            resource_categories.add("network")
    # 0.05 per category above 1, capped at +0.25 (5 categories)
    blast_radius_bonus = min(0.25, 0.05 * max(0, len(resource_categories) - 1))

    # --- Combine ---
    raw = exploitability * impact * scope_multiplier + blast_radius_bonus
    score = round(min(10.0, raw * 10), 1)

    # CVSS severity bands (FIRST.org standard)
    if score == 0:
        label = "None"
    elif score < 4.0:
        label = "Low"
    elif score < 7.0:
        label = "Medium"
    elif score < 9.0:
        label = "High"
    else:
        label = "Critical"

    clouds = sorted({s.get("cloud", "unknown") for s in path})
    breakdown = {
        "exploitability": round(exploitability, 3),
        "impact": round(impact, 3),
        "scope_multiplier": scope_multiplier,
        "blast_radius_bonus": round(blast_radius_bonus, 3),
        "resource_categories": sorted(resource_categories),
        "length": length,
        "internet_entry": has_internet_entry,
        "cross_cloud": cross_cloud,
        "clouds": clouds,
        "score_0_10": score,
        "severity": label,
    }
    return score, label, breakdown


def get_attack_paths_json(tenant_id):
    """Run the engine for ONE tenant and RETURN attack paths as a list of dicts.

    Called from Flask with current_user.id. Every query inside is scoped
    to this tenant, so the dashboard naturally shows only the calling
    user's data.
    """
    rules = load_rules() + load_custom_rules_for_tenant(tenant_id)
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

    with driver.session() as session:
        link_cross_cloud_credentials(session, tenant_id)
        detections = detect_all(session, rules, tenant_id)
        paths = build_attack_paths(session, detections, tenant_id)

    driver.close()

    output = []
    for idx, path in enumerate(paths, 1):
        score, label, breakdown = score_path(path)
        output.append({
            "id": idx,
            "score": score,
            "severity": label,
            "breakdown": breakdown,
            "steps": [
                {
                    "technique_id": s["id"],
                    "mitre_name": s["mitre_name"],
                    "tactic": s["tactic"],
                    "severity": s["severity"],
                    "cloud": s.get("cloud", "unknown"),
                    "node_id": s["node_id"],
                    "node_type": s["node_type"],
                    "detail": s.get("detail"),
                }
                for s in path
            ],
        })
    return output


def main():
    """CLI entry point. Reads tenant_id from --tenant-id arg (default 1).

    Usage:
        python engine.py                    # tenant_id = 1
        python engine.py --tenant-id 2      # tenant_id = 2
    """
    import sys
    tenant_id = 1
    if "--tenant-id" in sys.argv:
        idx = sys.argv.index("--tenant-id")
        if idx + 1 < len(sys.argv):
            try:
                tenant_id = int(sys.argv[idx + 1])
            except ValueError:
                print(f"--tenant-id must be an integer, got {sys.argv[idx+1]!r}")
                sys.exit(1)
    print(f"Running engine for tenant_id = {tenant_id}")

    rules = load_rules() + load_custom_rules_for_tenant(tenant_id)
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

    with driver.session() as session:
        bridge_count = link_cross_cloud_credentials(session, tenant_id)
        if bridge_count > 0:
            print(f"Cross-cloud bridge: linked {bridge_count} synthetic edge(s).")

        detections = detect_all(session, rules, tenant_id)

        print(f"\n=== {len(detections)} technique(s) detected ===\n")
        for d in detections:
            print(f"  [{d['id']}/{d['cloud'].upper()}] {d['mitre_name']} "
                  f"({d['tactic']}) -> {d['node_type']}: {d['node_id']}")

        paths = build_attack_paths(session, detections, tenant_id)

    driver.close()

    print(f"\n=== {len(paths)} ATTACK PATH(S) FOUND ===\n")
    for idx, path in enumerate(paths, 1):
        score, label, breakdown = score_path(path)
        cross_marker = " [CROSS-CLOUD]" if breakdown["cross_cloud"] else ""
        print(f"Attack Path #{idx}  (Risk Score: {score}/10 - {label}){cross_marker}")
        print(f"  Clouds: {breakdown['clouds']}, "
              f"Exploitability: {breakdown['exploitability']}, "
              f"Impact: {breakdown['impact']}, "
              f"Length: {breakdown['length']}")
        print("  " + " --> ".join(
            f"[{s['tactic']}/{s.get('cloud','?').upper()}] {s['id']} "
            f"on {s['node_type']} {s['node_id']}"
            for s in path
        ))
        print()


if __name__ == "__main__":
    main()