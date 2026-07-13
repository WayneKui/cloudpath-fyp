"""
CloudPath Security Testing Harness — Layer 1 Synthetic Evaluation

What this script does:
  1. Loads ground_truth.yaml — the authoritative list of planted
     misconfigurations and expected attack paths.
  2. Runs the CloudPath detection engine (via engine.py's functions,
     NOT subprocess — so we capture accurate timing and detection objects).
  3. Compares engine output to ground truth and computes:
       - Detection-level metrics (True Positives, False Positives,
         False Negatives, Precision, Recall, F1)
       - Path-level metrics (path completeness, score accuracy,
         cross-cloud detection correctness)
       - Performance metrics (engine runtime, per-rule timing,
         averaged over multiple runs)
  4. Writes results to three files:
       - security_test_results.json   (machine-readable, full detail)
       - security_test_results.csv    (for charts / spreadsheet import)
       - security_test_summary.txt    (human-readable report)

This is Layer 1 of the security testing chapter. It evaluates CloudPath
against a controlled synthetic environment with known planted attacks.
Layer 2 (baseline comparison vs Prowler/Cartography) and Layer 3
(literature mapping) are separate exercises.

Usage:
  $env:NEO4J_PASSWORD = "changeme"
  python security_test.py
"""
import json
import csv
import time
import statistics
import sys
import yaml
from datetime import datetime

# Import directly from the engine instead of running it as a subprocess.
# This gives us access to internal objects (detections, paths) and
# accurate per-component timing.
from engine import (
    load_rules,
    detect_all,
    link_cross_cloud_credentials,
    build_attack_paths,
    score_path,
    is_cross_cloud,
    NEO4J_URI,
    NEO4J_USER,
    NEO4J_PASSWORD,
)
from neo4j import GraphDatabase


# ============================================================
# Ground truth loading and key-extraction utilities
# ============================================================

def load_ground_truth(path="ground_truth.yaml"):
    """Read the YAML ground-truth file. Raises SystemExit on failure."""
    try:
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        sys.exit(f"ERROR: {path} not found. Run from the project root.")
    except yaml.YAMLError as e:
        sys.exit(f"ERROR: {path} is malformed: {e}")


def detection_key(d):
    """Stable identifier for a detection: (technique, cloud, node_id).

    Used to compare engine detections to ground-truth misconfigurations
    regardless of how either side orders or formats other fields.
    """
    return (
        d.get("id") or d.get("technique"),
        d.get("cloud"),
        d.get("node_id"),
    )


def planted_key(m):
    """Stable identifier for a planted misconfiguration."""
    return (m["technique"], m["cloud"], m["node_id"])


def path_step_keys(steps):
    """Extract step (technique, cloud, node_id) tuples from a path.

    Works on BOTH engine paths (list of detection dicts) and
    ground-truth paths (list of step dicts with 'technique' field).
    """
    out = []
    for s in steps:
        tech = s.get("id") or s.get("technique")
        out.append((tech, s.get("cloud"), s.get("node_id")))
    return out


# ============================================================
# Engine execution with timing
# ============================================================

def run_engine_once(session, rules, tenant_id, capture_per_rule_timing=True):
    """Execute the full detection pipeline once and return a result bundle.

    Captures:
      - Wall-clock timing for each pipeline phase
      - Optional per-rule timing (capture_per_rule_timing=True)
      - The raw detection list and attack path list

    tenant_id: this harness evaluates against the primary test account
    (tenant_id=1, where ground_truth.yaml's planted misconfigurations
    actually live). engine.py's detect_all/build_attack_paths/etc. all
    require tenant_id since Phase 7 (multi-tenant scoping) — this script
    pre-dates that and needs it threaded through explicitly.
    """
    timings = {}

    # Phase 1: cross-cloud bridge edges
    t0 = time.perf_counter()
    link_cross_cloud_credentials(session, tenant_id)
    timings["bridge_ms"] = round((time.perf_counter() - t0) * 1000, 2)

    # Phase 2: run detection rules. Optionally measure each rule
    # individually so we can spot slow ones.
    per_rule = {}
    if capture_per_rule_timing:
        # Replicate detect_all locally with per-rule timing.
        # IMPORTANT: detect_all wraps each raw rule match with metadata
        # from the rule (tactic, mitre_name, severity, cloud). We MUST do
        # the same wrapping here or downstream chaining will crash with
        # KeyError: 'tactic'.
        from engine import run_rule
        t0 = time.perf_counter()
        detections = []
        for rule in rules:
            rt0 = time.perf_counter()
            raw_matches = run_rule(session, rule, tenant_id)
            rt_ms = round((time.perf_counter() - rt0) * 1000, 2)
            per_rule[rule["id"]] = rt_ms
            for match in raw_matches:
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
        timings["detection_ms"] = round((time.perf_counter() - t0) * 1000, 2)
    else:
        t0 = time.perf_counter()
        detections = detect_all(session, rules, tenant_id)
        timings["detection_ms"] = round((time.perf_counter() - t0) * 1000, 2)

    # Phase 3: chain detections into paths
    t0 = time.perf_counter()
    paths = build_attack_paths(session, detections, tenant_id)
    timings["chaining_ms"] = round((time.perf_counter() - t0) * 1000, 2)

    timings["total_ms"] = (
        timings["bridge_ms"] + timings["detection_ms"] + timings["chaining_ms"]
    )

    return {
        "detections": detections,
        "paths": paths,
        "timings": timings,
        "per_rule_ms": per_rule,
    }


def run_engine_repeatedly(n_runs, tenant_id=1):
    """Execute the engine n_runs times and return aggregate timings.

    The detections/paths from the FIRST run are used for correctness
    evaluation (they should be identical across runs since Neo4j data
    doesn't change). Timings from ALL runs are averaged.
    """
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    rules = load_rules()

    all_runs = []
    print(f"\nRunning engine {n_runs} times for performance averaging…")
    with driver.session() as session:
        for i in range(n_runs):
            result = run_engine_once(session, rules, tenant_id, capture_per_rule_timing=True)
            all_runs.append(result)
            print(f"  Run {i + 1}/{n_runs}: total={result['timings']['total_ms']}ms "
                  f"(bridge={result['timings']['bridge_ms']}, "
                  f"detection={result['timings']['detection_ms']}, "
                  f"chaining={result['timings']['chaining_ms']})")
    driver.close()

    # Aggregate timings across all runs
    def agg(field):
        values = [r["timings"][field] for r in all_runs]
        return {
            "mean": round(statistics.mean(values), 2),
            "median": round(statistics.median(values), 2),
            "min": round(min(values), 2),
            "max": round(max(values), 2),
            "stdev": round(statistics.stdev(values), 2) if len(values) > 1 else 0,
        }

    perf = {
        "n_runs": n_runs,
        "bridge_ms": agg("bridge_ms"),
        "detection_ms": agg("detection_ms"),
        "chaining_ms": agg("chaining_ms"),
        "total_ms": agg("total_ms"),
    }

    # Aggregate per-rule timing
    per_rule_agg = {}
    if all_runs and all_runs[0]["per_rule_ms"]:
        for rule_id in all_runs[0]["per_rule_ms"]:
            values = [r["per_rule_ms"].get(rule_id, 0) for r in all_runs]
            per_rule_agg[rule_id] = {
                "mean": round(statistics.mean(values), 2),
                "median": round(statistics.median(values), 2),
                "max": round(max(values), 2),
            }
    perf["per_rule_ms"] = per_rule_agg

    # Use the FIRST run's correctness data (identical across runs anyway)
    return all_runs[0]["detections"], all_runs[0]["paths"], perf


# ============================================================
# Layer 1 metrics: detection-level (P / R / F1)
# ============================================================

def evaluate_detections(engine_detections, planted_list, extra_paths_policy):
    """Compare engine detections to planted misconfigurations.

    Returns a dict with TP / FP / FN counts, the matched/unmatched lists,
    and computed Precision / Recall / F1.

    Matching rule: a detection matches a planted misconfiguration iff
    they have the same (technique_id, cloud, node_id) tuple.
    """
    planted_keys = {planted_key(m): m for m in planted_list}
    detection_keys = {detection_key(d): d for d in engine_detections}

    tp_keys = set(planted_keys.keys()) & set(detection_keys.keys())
    fn_keys = set(planted_keys.keys()) - set(detection_keys.keys())
    fp_keys = set(detection_keys.keys()) - set(planted_keys.keys())

    tp = len(tp_keys)
    fn = len(fn_keys)
    fp = len(fp_keys) if extra_paths_policy == "fp_strict" else 0

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) > 0 else 0)

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "matched_detections": [
            {"technique": k[0], "cloud": k[1], "node_id": k[2]} for k in tp_keys
        ],
        "missed_misconfigurations": [
            planted_keys[k] for k in fn_keys
        ],
        "extra_detections": [
            {"technique": k[0], "cloud": k[1], "node_id": k[2]} for k in fp_keys
        ],
    }


# ============================================================
# Layer 1 metrics: path-level
# ============================================================

def evaluate_paths(engine_paths, expected_paths, extra_paths_policy):
    """Compare engine attack paths to expected paths.

    Two paths match if they have the same sequence of (technique, cloud,
    node_id) tuples. Score is reported separately (matches the path? AND
    is the score within the expected range?).
    """
    expected_signatures = {}
    for ep in expected_paths:
        sig = tuple(path_step_keys(ep["steps"]))
        expected_signatures[sig] = ep

    engine_signatures = {}
    engine_scored = {}
    for ep in engine_paths:
        sig = tuple(path_step_keys(ep))
        engine_signatures[sig] = ep
        score, label, breakdown = score_path(ep)
        engine_scored[sig] = {"score": score, "label": label, "breakdown": breakdown}

    matched_sigs = set(expected_signatures.keys()) & set(engine_signatures.keys())
    missed_sigs = set(expected_signatures.keys()) - set(engine_signatures.keys())
    extra_sigs = set(engine_signatures.keys()) - set(expected_signatures.keys())

    # Score validation for matched paths
    score_in_range = []
    score_out_of_range = []
    for sig in matched_sigs:
        expected = expected_signatures[sig]
        actual_score = engine_scored[sig]["score"]
        lo, hi = expected["expected_score_range"]
        record = {
            "path_id": expected["id"],
            "expected_range": [lo, hi],
            "actual_score": actual_score,
        }
        if lo <= actual_score <= hi:
            score_in_range.append(record)
        else:
            score_out_of_range.append(record)

    tp = len(matched_sigs)
    fn = len(missed_sigs)
    fp = len(extra_sigs) if extra_paths_policy == "fp_strict" else 0

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) > 0 else 0)

    # Cross-cloud detection accuracy
    cross_cloud_expected = sum(1 for ep in expected_paths if ep["is_cross_cloud"])
    cross_cloud_detected = sum(1 for ep in engine_paths if is_cross_cloud(ep))

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "score_validation": {
            "in_range": score_in_range,
            "out_of_range": score_out_of_range,
        },
        "cross_cloud": {
            "expected": cross_cloud_expected,
            "detected": cross_cloud_detected,
            "correct": cross_cloud_expected == cross_cloud_detected,
        },
        "missed_paths": [
            {"id": expected_signatures[sig]["id"],
             "label": expected_signatures[sig]["label"]}
            for sig in missed_sigs
        ],
        "extra_paths": [
            {"steps": [{"technique": k[0], "cloud": k[1], "node_id": k[2]}
                       for k in sig],
             "score": engine_scored[sig]["score"]}
            for sig in extra_sigs
        ],
    }


# ============================================================
# Output writers
# ============================================================

def write_json_results(results, path):
    """Write the full structured results to JSON."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)


def write_csv_results(results, path):
    """Write a flat CSV row-per-metric for spreadsheet/chart import."""
    rows = [
        ["metric", "value"],
        ["timestamp", results["timestamp"]],
        ["detection_tp", results["detection_metrics"]["tp"]],
        ["detection_fp", results["detection_metrics"]["fp"]],
        ["detection_fn", results["detection_metrics"]["fn"]],
        ["detection_precision", results["detection_metrics"]["precision"]],
        ["detection_recall", results["detection_metrics"]["recall"]],
        ["detection_f1", results["detection_metrics"]["f1"]],
        ["path_tp", results["path_metrics"]["tp"]],
        ["path_fp", results["path_metrics"]["fp"]],
        ["path_fn", results["path_metrics"]["fn"]],
        ["path_precision", results["path_metrics"]["precision"]],
        ["path_recall", results["path_metrics"]["recall"]],
        ["path_f1", results["path_metrics"]["f1"]],
        ["cross_cloud_expected", results["path_metrics"]["cross_cloud"]["expected"]],
        ["cross_cloud_detected", results["path_metrics"]["cross_cloud"]["detected"]],
        ["total_runtime_mean_ms", results["performance"]["total_ms"]["mean"]],
        ["bridge_mean_ms", results["performance"]["bridge_ms"]["mean"]],
        ["detection_mean_ms", results["performance"]["detection_ms"]["mean"]],
        ["chaining_mean_ms", results["performance"]["chaining_ms"]["mean"]],
    ]
    # Append per-rule timings
    for rule_id, t in results["performance"].get("per_rule_ms", {}).items():
        rows.append([f"rule_{rule_id}_mean_ms", t["mean"]])

    with open(path, "w", encoding="utf-8", newline="") as f:
        csv.writer(f).writerows(rows)


def write_summary(results, path):
    """Write a human-readable summary suitable for inclusion in the report."""
    d = results["detection_metrics"]
    p = results["path_metrics"]
    perf = results["performance"]

    lines = []
    lines.append("=" * 70)
    lines.append("CloudPath Layer 1 — Synthetic Evaluation Summary")
    lines.append("=" * 70)
    lines.append(f"Generated: {results['timestamp']}")
    lines.append(f"Ground truth: {results['ground_truth_file']}")
    lines.append("")

    lines.append("DETECTION-LEVEL METRICS (per planted misconfiguration)")
    lines.append("-" * 70)
    lines.append(f"  True Positives:   {d['tp']}")
    lines.append(f"  False Positives:  {d['fp']}")
    lines.append(f"  False Negatives:  {d['fn']}")
    lines.append(f"  Precision:        {d['precision']}")
    lines.append(f"  Recall:           {d['recall']}")
    lines.append(f"  F1 Score:         {d['f1']}")
    if d["missed_misconfigurations"]:
        lines.append("")
        lines.append("  Missed planted misconfigurations:")
        for m in d["missed_misconfigurations"]:
            lines.append(f"    - {m['id']}: {m['technique']}/{m['cloud']} on {m['node_id']}")
    if d["extra_detections"]:
        lines.append("")
        lines.append("  Extra (un-planted) detections — possible false positives:")
        for e in d["extra_detections"]:
            lines.append(f"    - {e['technique']}/{e['cloud']} on {e['node_id']}")
    lines.append("")

    lines.append("PATH-LEVEL METRICS (per expected attack scenario)")
    lines.append("-" * 70)
    lines.append(f"  True Positives:   {p['tp']}")
    lines.append(f"  False Positives:  {p['fp']}")
    lines.append(f"  False Negatives:  {p['fn']}")
    lines.append(f"  Precision:        {p['precision']}")
    lines.append(f"  Recall:           {p['recall']}")
    lines.append(f"  F1 Score:         {p['f1']}")
    lines.append("")
    lines.append("  Cross-cloud detection:")
    cc = p["cross_cloud"]
    lines.append(f"    Expected cross-cloud paths: {cc['expected']}")
    lines.append(f"    Detected cross-cloud paths: {cc['detected']}")
    lines.append(f"    Correct: {'YES' if cc['correct'] else 'NO'}")
    lines.append("")

    sv = p["score_validation"]
    lines.append("  Risk score validation (matched paths):")
    for r in sv["in_range"]:
        lines.append(f"    [OK]   {r['path_id']}: actual={r['actual_score']} "
                     f"in {r['expected_range']}")
    for r in sv["out_of_range"]:
        lines.append(f"    [WARN] {r['path_id']}: actual={r['actual_score']} "
                     f"OUTSIDE {r['expected_range']}")
    if p["missed_paths"]:
        lines.append("")
        lines.append("  Missed expected paths:")
        for mp in p["missed_paths"]:
            lines.append(f"    - {mp['id']}: {mp['label']}")
    if p["extra_paths"]:
        lines.append("")
        lines.append("  Extra (unexpected) paths:")
        for ep in p["extra_paths"]:
            lines.append(f"    - score={ep['score']}, steps={len(ep['steps'])}")
    lines.append("")

    lines.append(f"PERFORMANCE METRICS ({perf['n_runs']} runs averaged)")
    lines.append("-" * 70)
    for phase in ["bridge_ms", "detection_ms", "chaining_ms", "total_ms"]:
        t = perf[phase]
        lines.append(f"  {phase:20s}  mean={t['mean']:>8.2f}  median={t['median']:>8.2f}  "
                     f"min={t['min']:>8.2f}  max={t['max']:>8.2f}  stdev={t['stdev']:>6.2f}")
    lines.append("")
    if perf.get("per_rule_ms"):
        lines.append("  Per-rule execution time (mean ms):")
        for rule_id, t in sorted(perf["per_rule_ms"].items(),
                                 key=lambda kv: -kv[1]["mean"]):
            lines.append(f"    {rule_id:<10s} mean={t['mean']:>7.2f}  max={t['max']:>7.2f}")
    lines.append("")
    lines.append("=" * 70)

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    # Also echo to stdout for immediate feedback
    print("\n" + "\n".join(lines))


# ============================================================
# Main
# ============================================================

def main():
    print("=" * 70)
    print("CloudPath Layer 1 — Synthetic Evaluation")
    print("=" * 70)

    # Load ground truth
    ground_truth = load_ground_truth("ground_truth.yaml")
    planted = ground_truth["planted_misconfigurations"]
    expected_paths = ground_truth["expected_attack_paths"]
    cfg = ground_truth["evaluation"]
    print(f"Loaded ground truth: {len(planted)} planted misconfigurations, "
          f"{len(expected_paths)} expected attack paths")

    # Run the engine n times (averages timings; uses first run for correctness)
    detections, paths, perf = run_engine_repeatedly(cfg["performance_runs"])
    print(f"\nEngine produced {len(detections)} detections, {len(paths)} attack paths")

    # Compute detection-level metrics
    det_metrics = evaluate_detections(
        detections, planted, cfg["extra_paths_policy"]
    )

    # Compute path-level metrics
    path_metrics = evaluate_paths(
        paths, expected_paths, cfg["extra_paths_policy"]
    )

    results = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "ground_truth_file": "ground_truth.yaml",
        "engine_output": {
            "detection_count": len(detections),
            "path_count": len(paths),
        },
        "detection_metrics": det_metrics,
        "path_metrics": path_metrics,
        "performance": perf,
    }

    # Write outputs
    write_json_results(results, cfg["output_json"])
    write_csv_results(results, cfg["output_csv"])
    write_summary(results, cfg["output_summary"])

    print(f"\nResults written to:")
    print(f"  - {cfg['output_json']}  (machine-readable JSON)")
    print(f"  - {cfg['output_csv']}   (flat CSV for charts)")
    print(f"  - {cfg['output_summary']}  (human-readable summary)")


if __name__ == "__main__":
    main()