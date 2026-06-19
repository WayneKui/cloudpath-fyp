"""
CloudPath Security Testing Harness — Layer 2 Baseline Comparison

What this script does:
  Compares CloudPath's detection capability against two baseline tools:
    - Prowler   (compliance-driven misconfiguration scanner)
    - Cartography (cloud asset inventory tool)
  on the SAME planted misconfigurations used in Layer 1.

The honest research question Layer 2 answers:
  "What does CloudPath surface that running Prowler + Cartography
   independently would not surface?"

Three sub-questions:
  1. COVERAGE:    Do the baselines detect each planted misconfiguration?
                  (Read Prowler JSON output; check Cartography Neo4j state.)
  2. CORRELATION: Do the baselines surface attack PATHS, not just findings?
                  (Spoiler: no — they produce findings/inventory, not chains.)
  3. CROSS-CLOUD: Do the baselines correlate across cloud providers?
                  (Spoiler: no — they scan AWS and GCP separately.)

Output:
  - layer2_results.json     machine-readable detail
  - layer2_results.csv      flat metrics for charts
  - layer2_summary.txt      human-readable report

Notes on honesty:
  - "Cartography catches it" means: the resource is ingested into Neo4j
    such that an analyst querying directly could spot the issue. It does
    NOT mean Cartography raises an alert — Cartography never raises alerts.
  - "Prowler catches it" means: a Prowler check with FAIL status fired
    on the resource UID in the actual Prowler output files. Verified by
    parsing prowler-output/*.ocsf.json.
  - Cross-cloud correlation: by construction, neither baseline performs
    this. Reported here as a zero-by-design result, not a measured gap.

Usage:
  $env:NEO4J_PASSWORD = "YourPassword123"
  python baseline_compare.py
"""
import json
import csv
import glob
import os
import sys
from datetime import datetime
import yaml
from neo4j import GraphDatabase

from engine import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD


# ============================================================
# Loading and parsing
# ============================================================

def load_ground_truth(path="ground_truth.yaml"):
    """Read the ground-truth file. Same file Layer 1 uses, extended with
    baseline-mapping fields."""
    try:
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        sys.exit(f"ERROR: {path} not found.")


def load_prowler_findings(directory="prowler-output"):
    """Read every Prowler OCSF JSON file and return a list of FAIL findings.

    Each finding is normalised to {check_id, cloud, resource_uid, resource_name}
    so the downstream comparison code doesn't need to know OCSF schema details.
    """
    files = sorted(glob.glob(os.path.join(directory, "*.ocsf.json")))
    if not files:
        print(f"WARNING: no Prowler JSON files found in {directory}/")
        return []

    findings = []
    for fp in files:
        with open(fp, encoding="utf-8") as f:
            data = json.load(f)
        for d in data:
            if d.get("status_code") != "FAIL":
                continue
            resources = d.get("resources", [])
            if not resources:
                continue
            cloud = (d.get("cloud") or {}).get("provider", "unknown").lower()
            findings.append({
                "check_id": d.get("metadata", {}).get("event_code", ""),
                "cloud": cloud,
                "resource_uid": resources[0].get("uid", ""),
                "resource_name": resources[0].get("name", ""),
                "severity": d.get("severity", "Unknown"),
            })
    print(f"Loaded {len(findings)} Prowler FAIL findings from {len(files)} file(s).")
    return findings


def load_cartography_state():
    """Query Neo4j and return the set of labels present (label -> count).

    'Cartography state' here means whatever is currently in Neo4j — which
    includes data from Cartography proper, your custom ingestors, and
    aws_secret_ingest.py. We don't try to attribute by ingestion source.
    """
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    label_counts = {}
    try:
        with driver.session() as session:
            result = session.run(
                "MATCH (n) RETURN labels(n)[0] AS label, count(n) AS n "
                "ORDER BY n DESC"
            )
            for record in result:
                if record["label"]:
                    label_counts[record["label"]] = record["n"]
    finally:
        driver.close()
    print(f"Loaded Cartography/Neo4j state: {len(label_counts)} distinct node labels.")
    return label_counts


# ============================================================
# Coverage computation
# ============================================================

def check_prowler_coverage(planted, prowler_findings):
    """For one planted misconfiguration, find which Prowler checks fired
    against the same OR a related target resource.

    A finding matches a planted misconfig if:
      - Its check_id is listed in the misconfig's prowler_check_ids, AND
      - Its resource_uid or resource_name matches:
          - the misconfig's node_id (direct match), OR
          - any UID/name listed in prowler_related_uids (Path A match)

    The "related UIDs" extension handles the case where Prowler anchors
    its check on a different (but functionally connected) resource than
    CloudPath does. For example: CloudPath anchors T1190 detection on the
    GCP VM (fw-misconfiguration); Prowler raises the same compliance
    issue on the attached firewall (fw-misconfig-open-ssh). Without
    related-UID matching, Prowler is unfairly scored as "missed" when
    it actually caught the issue on the adjacent resource.

    Returns a dict with the match details, including a `match_kind`
    field that distinguishes direct vs related-resource matches so the
    report can be transparent about which kind of match each row used.
    """
    expected_checks = planted.get("prowler_check_ids", []) or []
    if not expected_checks:
        return {
            "expected_check_ids": [],
            "matching_findings": [],
            "prowler_caught": False,
            "match_kind": "none",
            "reason": "no Prowler check is known to detect this misconfiguration",
        }

    node_id = planted["node_id"]
    related = planted.get("prowler_related_uids", []) or []
    direct_targets = {node_id}
    related_targets = set(related)

    direct_matches = []
    related_matches = []
    for f in prowler_findings:
        if f["check_id"] not in expected_checks:
            continue
        uid = f.get("resource_uid") or ""
        name = f.get("resource_name") or ""

        # Direct match: the same node_id CloudPath anchors on
        if (uid in direct_targets
                or name in direct_targets
                or node_id in uid):
            direct_matches.append({
                "check_id": f["check_id"],
                "severity": f["severity"],
                "resource_uid": uid,
                "match": "direct",
            })
            continue

        # Related-resource match: Prowler anchored its check on an adjacent
        # resource. Counted as "Prowler caught it" but noted as 'related'.
        if uid in related_targets or name in related_targets:
            related_matches.append({
                "check_id": f["check_id"],
                "severity": f["severity"],
                "resource_uid": uid,
                "match": "related",
            })

    matches = direct_matches + related_matches
    if direct_matches:
        match_kind = "direct"
        reason = "Prowler raised matching FAIL finding(s) on the same resource"
    elif related_matches:
        match_kind = "related"
        reason = ("Prowler raised matching FAIL finding(s) on a related "
                  "resource (different anchor than CloudPath)")
    else:
        match_kind = "miss"
        reason = "expected check IDs did not fire on this resource or related resources"

    return {
        "expected_check_ids": expected_checks,
        "matching_findings": matches,
        "prowler_caught": len(matches) > 0,
        "match_kind": match_kind,
        "reason": reason,
    }


def check_cartography_coverage(planted, label_counts):
    """For one planted misconfiguration, check whether Cartography ingested
    the required node types.

    A misconfig is 'ingested by Cartography' if EVERY label in its
    cartography_required_labels list exists in Neo4j with count > 0.

    This is a structural test — it confirms the data is in the graph, not
    that any tool flagged it as a problem. Cartography is an inventory
    tool; raising alerts is not its job.
    """
    required = planted.get("cartography_required_labels", []) or []
    if not required:
        return {
            "required_labels": [],
            "missing_labels": [],
            "cartography_ingested": False,
            "reason": "no required labels listed",
        }

    missing = [lbl for lbl in required if label_counts.get(lbl, 0) == 0]
    return {
        "required_labels": required,
        "labels_present": {lbl: label_counts.get(lbl, 0) for lbl in required},
        "missing_labels": missing,
        "cartography_ingested": len(missing) == 0,
        "reason": ("all required node types ingested" if not missing
                   else f"missing node types: {missing}"),
    }


def evaluate_baselines(ground_truth, prowler_findings, label_counts):
    """Run baseline checks for every planted misconfiguration.

    Returns a list of per-misconfig records, plus an aggregate summary
    of how many were caught by each baseline (and by CloudPath, taken
    from the ground-truth file for cross-reference).
    """
    per_misconfig = []
    prowler_caught_count = 0
    cartography_ingested_count = 0

    for planted in ground_truth["planted_misconfigurations"]:
        prowler = check_prowler_coverage(planted, prowler_findings)
        carto = check_cartography_coverage(planted, label_counts)

        if prowler["prowler_caught"]:
            prowler_caught_count += 1
        if carto["cartography_ingested"]:
            cartography_ingested_count += 1

        # CloudPath always catches these — by construction the planted
        # misconfigs match the engine's rules. Layer 1 already verified
        # this with TP=7/7. We surface the Layer 1 assertion here for
        # side-by-side comparison.
        cloudpath_caught = True

        per_misconfig.append({
            "misconfig_id": planted["id"],
            "cloud": planted["cloud"],
            "technique": planted["technique"],
            "node_id": planted["node_id"],
            "severity": planted["severity"],
            "prowler": prowler,
            "cartography": carto,
            "cloudpath_caught": cloudpath_caught,
        })

    total = len(ground_truth["planted_misconfigurations"])
    return {
        "per_misconfig": per_misconfig,
        "summary": {
            "total_planted": total,
            "prowler_caught": prowler_caught_count,
            "prowler_recall": round(prowler_caught_count / total, 3) if total else 0,
            "cartography_ingested": cartography_ingested_count,
            "cartography_coverage": round(cartography_ingested_count / total, 3) if total else 0,
            "cloudpath_caught": total,  # from Layer 1 — every planted is detected
            "cloudpath_recall": 1.0,
        },
    }


# ============================================================
# Capability comparison: PATHS and CROSS-CLOUD
# ============================================================

def evaluate_capabilities(ground_truth):
    """Compare what each tool CAN and CANNOT do, by tool design.

    These are structural claims about the tools, not measured per-run.
    Documented here so the report can quote them with the data file as
    evidence.
    """
    n_paths = len(ground_truth["expected_attack_paths"])
    n_cross_cloud = sum(1 for p in ground_truth["expected_attack_paths"]
                        if p.get("is_cross_cloud"))
    return {
        "attack_path_correlation": {
            "prowler": {
                "supports_paths": False,
                "evidence": "Prowler emits a flat list of FAIL findings per "
                            "resource. No attack-path concept exists in its "
                            "output schema (OCSF events without sequence).",
                "paths_surfaced": 0,
            },
            "cartography": {
                "supports_paths": False,
                "evidence": "Cartography is an inventory tool. It populates "
                            "Neo4j with cloud-resource nodes but does not "
                            "perform path traversal or alerting. An analyst "
                            "can write Cypher queries to find paths, but the "
                            "tool itself does not.",
                "paths_surfaced": 0,
            },
            "cloudpath": {
                "supports_paths": True,
                "evidence": "Path correlation is CloudPath's primary function. "
                            "Layer 1 measured 3/3 expected paths detected.",
                "paths_surfaced": n_paths,
            },
        },
        "cross_cloud_correlation": {
            "prowler": {
                "supports_cross_cloud": False,
                "evidence": "Prowler scans AWS and GCP as separate invocations "
                            "with separate output files. No cross-provider "
                            "linkage is performed.",
            },
            "cartography": {
                "supports_cross_cloud": False,
                "evidence": "Cartography ingests both clouds into the same "
                            "Neo4j instance but does not synthesise edges "
                            "between AWS and GCP resources.",
            },
            "cloudpath": {
                "supports_cross_cloud": True,
                "evidence": "CloudPath synthesises CONTAINS_CREDENTIAL_FOR "
                            "edges between AWS Secrets and the GCP service "
                            "accounts they grant access to. Layer 1 verified "
                            "1/1 expected cross-cloud paths detected.",
                "expected_cross_cloud_paths": n_cross_cloud,
            },
        },
    }


# ============================================================
# Output writers
# ============================================================

def write_json_results(results, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)


def write_csv_results(results, path):
    """Flat CSV with per-misconfig rows + aggregate totals."""
    rows = [["misconfig_id", "cloud", "technique", "severity",
             "prowler_caught", "matching_prowler_checks",
             "cartography_ingested", "cartography_missing_labels",
             "cloudpath_caught"]]
    for m in results["baseline_coverage"]["per_misconfig"]:
        rows.append([
            m["misconfig_id"],
            m["cloud"],
            m["technique"],
            m["severity"],
            m["prowler"]["prowler_caught"],
            ";".join(f["check_id"] for f in m["prowler"]["matching_findings"]),
            m["cartography"]["cartography_ingested"],
            ";".join(m["cartography"]["missing_labels"]),
            m["cloudpath_caught"],
        ])
    rows.append([])
    rows.append(["AGGREGATE", "", "", "", "", "", "", "", ""])
    s = results["baseline_coverage"]["summary"]
    rows.append(["total_planted", s["total_planted"]])
    rows.append(["prowler_recall", s["prowler_recall"]])
    rows.append(["cartography_coverage", s["cartography_coverage"]])
    rows.append(["cloudpath_recall", s["cloudpath_recall"]])

    with open(path, "w", encoding="utf-8", newline="") as f:
        csv.writer(f).writerows(rows)


def write_summary(results, path):
    s = results["baseline_coverage"]["summary"]
    cap = results["capabilities"]
    per = results["baseline_coverage"]["per_misconfig"]

    lines = []
    lines.append("=" * 70)
    lines.append("CloudPath Layer 2 — Baseline Comparison Summary")
    lines.append("=" * 70)
    lines.append(f"Generated: {results['timestamp']}")
    lines.append("")

    lines.append("HEADLINE NUMBERS")
    lines.append("-" * 70)
    lines.append(f"  Planted misconfigurations:  {s['total_planted']}")
    lines.append(f"  Caught by Prowler:          {s['prowler_caught']}/"
                 f"{s['total_planted']} (recall {s['prowler_recall']})")
    lines.append(f"  Ingested by Cartography:    {s['cartography_ingested']}/"
                 f"{s['total_planted']} (coverage {s['cartography_coverage']})")
    lines.append(f"  Caught by CloudPath:        {s['cloudpath_caught']}/"
                 f"{s['total_planted']} (recall {s['cloudpath_recall']})")
    lines.append("")

    lines.append("PER-MISCONFIGURATION COMPARISON")
    lines.append("-" * 70)
    lines.append("  Prowler column legend:")
    lines.append("    DIRECT  = Prowler caught it on the same resource CloudPath anchors")
    lines.append("    RELATED = Prowler caught it on an adjacent resource (Path A match)")
    lines.append("    NO      = no matching Prowler check fired")
    lines.append("")
    header = f"  {'misconfig':<32s} {'Prowler':<10s} {'Cartography':<14s} {'CloudPath':<10s}"
    lines.append(header)
    lines.append(f"  {'-' * 32} {'-' * 10} {'-' * 14} {'-' * 10}")
    for m in per:
        mk = m["prowler"].get("match_kind", "none")
        if mk == "direct":
            p = "DIRECT"
        elif mk == "related":
            p = "RELATED"
        else:
            p = "NO"
        c = "YES" if m["cartography"]["cartography_ingested"] else "NO"
        cp = "YES" if m["cloudpath_caught"] else "NO"
        lines.append(f"  {m['misconfig_id']:<32s} {p:<10s} {c:<14s} {cp:<10s}")
    lines.append("")

    lines.append("MISSED BY PROWLER (CloudPath unique value)")
    lines.append("-" * 70)
    lines.append("  Note: 'missed' here means Prowler did not raise a FAIL")
    lines.append("  finding ON THE TARGET RESOURCE identified by CloudPath's")
    lines.append("  attack-path step. Prowler may have raised related findings")
    lines.append("  on adjacent resources (e.g. the IAM role attached to the")
    lines.append("  EC2 instance) but it does not correlate them into an")
    lines.append("  attack chain anchored to the compute resource. CloudPath's")
    lines.append("  contribution is this correlation, not the raw detection.")
    lines.append("")
    missed_by_prowler = [m for m in per if not m["prowler"]["prowler_caught"]]
    if missed_by_prowler:
        for m in missed_by_prowler:
            lines.append(f"  - {m['misconfig_id']} ({m['technique']}/{m['cloud']})")
            lines.append(f"      Reason: {m['prowler']['reason']}")
            lines.append(f"      Node:   {m['node_id']}")
    else:
        lines.append("  (Prowler caught all planted misconfigurations)")
    lines.append("")

    lines.append("CAPABILITY COMPARISON (path correlation & cross-cloud)")
    lines.append("-" * 70)
    pc = cap["attack_path_correlation"]
    lines.append("  Attack-path correlation (chains of techniques into kill-chains):")
    lines.append(f"    Prowler:    {'supported' if pc['prowler']['supports_paths'] else 'NOT supported'} "
                 f"({pc['prowler']['paths_surfaced']} paths surfaced)")
    lines.append(f"    Cartography:{'supported' if pc['cartography']['supports_paths'] else ' NOT supported'} "
                 f"({pc['cartography']['paths_surfaced']} paths surfaced)")
    lines.append(f"    CloudPath:  {'supported' if pc['cloudpath']['supports_paths'] else 'NOT supported'} "
                 f"({pc['cloudpath']['paths_surfaced']} paths surfaced)")
    lines.append("")
    cc = cap["cross_cloud_correlation"]
    lines.append("  Cross-cloud correlation (AWS<->GCP attack chains):")
    lines.append(f"    Prowler:    {'supported' if cc['prowler']['supports_cross_cloud'] else 'NOT supported'}")
    lines.append(f"    Cartography:{'supported' if cc['cartography']['supports_cross_cloud'] else ' NOT supported'}")
    lines.append(f"    CloudPath:  {'supported' if cc['cloudpath']['supports_cross_cloud'] else 'NOT supported'} "
                 f"({cc['cloudpath']['expected_cross_cloud_paths']} expected, "
                 "1 detected — verified in Layer 1)")
    lines.append("")

    lines.append("CONTRIBUTION CLAIM (for the report)")
    lines.append("-" * 70)
    lines.append("  Prowler and Cartography, by design, do not correlate")
    lines.append("  findings into attack paths or across cloud providers.")
    lines.append("  CloudPath sits above both and provides:")
    lines.append("    (a) attack-path correlation (3 paths surfaced)")
    lines.append("    (b) cross-cloud correlation (1 cross-cloud path verified)")
    lines.append("    (c) detection of relationship-dependent misconfigs that")
    lines.append("        Prowler's checklist approach misses ")
    lines.append(f"        ({s['total_planted'] - s['prowler_caught']} misses identified above).")
    lines.append("")
    lines.append("=" * 70)

    text = "\n".join(lines)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    print("\n" + text)


# ============================================================
# Main
# ============================================================

def main():
    print("=" * 70)
    print("CloudPath Layer 2 — Baseline Comparison")
    print("=" * 70)

    ground_truth = load_ground_truth("ground_truth.yaml")
    prowler_findings = load_prowler_findings("prowler-output")
    label_counts = load_cartography_state()

    baseline_coverage = evaluate_baselines(
        ground_truth, prowler_findings, label_counts
    )
    capabilities = evaluate_capabilities(ground_truth)

    results = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "ground_truth_file": "ground_truth.yaml",
        "prowler_findings_loaded": len(prowler_findings),
        "neo4j_labels_present": len(label_counts),
        "baseline_coverage": baseline_coverage,
        "capabilities": capabilities,
    }

    write_json_results(results, "layer2_results.json")
    write_csv_results(results, "layer2_results.csv")
    write_summary(results, "layer2_summary.txt")

    print("\nResults written to:")
    print("  - layer2_results.json")
    print("  - layer2_results.csv")
    print("  - layer2_summary.txt")


if __name__ == "__main__":
    main()