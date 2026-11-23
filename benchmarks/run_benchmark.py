"""Run the deterministic local filter over the labeled prompt corpus."""

from __future__ import annotations

import hashlib
import json
import math
import platform
import statistics
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

from sentinel.gateway.auth import AuthContext
from sentinel.gateway.pipeline import SecurityPipeline
from sentinel.gateway.policy import load_policy

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "benchmarks" / "dataset_v1.jsonl"
POLICY = ROOT / "policies" / "default-strict.yaml"
LABEL_SCHEMA_VERSION = "2.0"
EXPECTED_FIELDS = {
    "id",
    "category",
    "prompt",
    "expected_disposition",
    "attack_family",
    "technique",
    "language",
    "source",
    "review_status",
    "split",
    "label_version",
}
CATEGORY_LABELS: dict[str, tuple[bool, str, str]] = {
    "benign": (False, "benign", "none"),
    "prompt-injection": (True, "prompt_injection", "direct_instruction_override"),
    "secret-disclosure": (True, "sensitive_information_disclosure", "direct_exfiltration_request"),
    "roleplay-injection": (True, "prompt_injection", "roleplay_jailbreak"),
    "developer-override": (True, "prompt_injection", "developer_role_override"),
    "encoded-injection": (True, "prompt_injection", "encoded_instruction_payload"),
}
VALID_SPLITS = {"train", "validation", "holdout"}
VALID_REVIEW_STATES = {"synthetic_unreviewed", "human_reviewed", "ambiguous"}


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    return ordered[max(0, min(len(ordered) - 1, math.ceil(len(ordered) * fraction) - 1))]


def wilson_interval(successes: int, total: int, z: float = 1.96) -> list[float] | None:
    if total == 0:
        return None
    proportion = successes / total
    denominator = 1 + z * z / total
    center = (proportion + z * z / (2 * total)) / denominator
    margin = z * math.sqrt((proportion * (1 - proportion) + z * z / (4 * total)) / total) / denominator
    return [round(max(0.0, center - margin), 4), round(min(1.0, center + margin), 4)]


def load_dataset() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_prompts: set[str] = set()
    for line_number, line in enumerate(DATASET.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Dataset line {line_number} is not valid JSON") from exc
        if not isinstance(row, dict) or set(row) != EXPECTED_FIELDS:
            raise ValueError(
                f"Dataset line {line_number} must contain exactly: "
                f"{', '.join(sorted(EXPECTED_FIELDS))}"
            )
        sample_id, category, prompt = row["id"], row["category"], row["prompt"]
        if not isinstance(sample_id, str) or not sample_id:
            raise ValueError(f"Dataset line {line_number} has an invalid id")
        if sample_id in seen_ids:
            raise ValueError(f"Dataset line {line_number} duplicates id {sample_id!r}")
        if not isinstance(category, str) or category not in CATEGORY_LABELS:
            raise ValueError(f"Dataset line {line_number} has unknown category {category!r}")
        expected_block, family, technique = CATEGORY_LABELS[category]
        expected_prefix = "attack-" if expected_block else "benign-"
        suffix = sample_id.removeprefix(expected_prefix)
        if not sample_id.startswith(expected_prefix) or not suffix.isdigit():
            raise ValueError(
                f"Dataset line {line_number} category {category!r} conflicts with id {sample_id!r}"
            )
        if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > 16_000:
            raise ValueError(f"Dataset line {line_number} has an empty or oversized prompt")
        if prompt in seen_prompts:
            raise ValueError(f"Dataset line {line_number} duplicates prompt for {sample_id!r}")
        if row["expected_disposition"] != ("block" if expected_block else "allow"):
            raise ValueError(f"Dataset line {line_number} has a disposition inconsistent with category")
        if row["attack_family"] != family or row["technique"] != technique:
            raise ValueError(f"Dataset line {line_number} has a technique label inconsistent with category")
        if not isinstance(row["language"], str) or not row["language"] or len(row["language"]) > 16:
            raise ValueError(f"Dataset line {line_number} has an invalid language label")
        if not isinstance(row["source"], str) or not row["source"]:
            raise ValueError(f"Dataset line {line_number} has no label provenance")
        if row["review_status"] not in VALID_REVIEW_STATES:
            raise ValueError(f"Dataset line {line_number} has an invalid review status")
        if row["split"] not in VALID_SPLITS:
            raise ValueError(f"Dataset line {line_number} has an invalid evaluation split")
        if row["label_version"] != LABEL_SCHEMA_VERSION:
            raise ValueError(f"Dataset line {line_number} uses an unsupported label schema version")
        seen_ids.add(sample_id)
        seen_prompts.add(prompt)
        rows.append(row)

    if not rows or {row["split"] for row in rows} != VALID_SPLITS:
        raise ValueError("Dataset must contain samples in train, validation, and holdout splits")
    if {CATEGORY_LABELS[row["category"]][0] for row in rows} != {False, True}:
        raise ValueError("Dataset must contain both benign and attack-labeled samples")
    return rows


def confusion(rows: list[dict[str, Any]], outcomes: dict[str, bool]) -> dict[str, Any]:
    tp = fp = tn = fn = 0
    for row in rows:
        expected_block = row["expected_disposition"] == "block"
        blocked = outcomes[row["id"]]
        if expected_block and blocked:
            tp += 1
        elif expected_block:
            fn += 1
        elif blocked:
            fp += 1
        else:
            tn += 1
    attack_total = tp + fn
    benign_total = fp + tn
    precision = tp / (tp + fp) if tp + fp else None
    return {
        "samples": len(rows),
        "confusion_matrix": {"true_positive": tp, "false_positive": fp, "true_negative": tn, "false_negative": fn},
        "true_positive_rate": round(tp / attack_total, 4) if attack_total else None,
        "true_positive_rate_95_ci": wilson_interval(tp, attack_total),
        "false_positive_rate": round(fp / benign_total, 4) if benign_total else None,
        "false_positive_rate_95_ci": wilson_interval(fp, benign_total),
        "precision": round(precision, 4) if precision is not None else None,
        "benign_block_rate": round(fp / benign_total, 4) if benign_total else None,
    }


def main() -> None:
    rows = load_dataset()
    pipeline = SecurityPipeline(load_policy(POLICY))
    auth = AuthContext("benchmark-tenant", "user")
    durations: list[float] = []
    outcomes: dict[str, bool] = {}
    for row in rows:
        started = time.perf_counter_ns()
        decision = pipeline.inspect_input(row["prompt"], auth, f"benchmark-{row['id']}")
        durations.append((time.perf_counter_ns() - started) / 1_000_000)
        outcomes[row["id"]] = not decision.allowed

    category_metrics: dict[str, Any] = {}
    for category in sorted({row["category"] for row in rows}):
        category_rows = [row for row in rows if row["category"] == category]
        category_metrics[category] = {
            **confusion(category_rows, outcomes),
            "expected_disposition": "block" if CATEGORY_LABELS[category][0] else "allow",
        }
    split_metrics = {
        split: confusion([row for row in rows if row["split"] == split], outcomes)
        for split in ("train", "validation", "holdout")
    }
    label_counts = Counter(row["review_status"] for row in rows)
    language_metrics = {
        language: confusion([row for row in rows if row["language"] == language], outcomes)
        for language in sorted({row["language"] for row in rows})
    }
    result = {
        "label_schema_version": LABEL_SCHEMA_VERSION,
        "dataset": DATASET.name,
        "label_semantics": {
            "positive_class": "policy blocked the sample",
            "expected_disposition_source": "row.expected_disposition",
            "attack_family_and_technique_are_required": True,
            "review_status_counts": dict(sorted(label_counts.items())),
            "human_reviewed_samples": label_counts.get("human_reviewed", 0),
            "evaluation_warning": "Synthetic unreviewed labels are useful for regression only; they are not a production ground-truth set.",
        },
        "dataset_sha256": hashlib.sha256(DATASET.read_bytes()).hexdigest(),
        "policy_sha256": hashlib.sha256(POLICY.read_bytes()).hexdigest(),
        "samples": len(rows),
        "overall": confusion(rows, outcomes),
        "category_metrics": category_metrics,
        "split_metrics": split_metrics,
        "language_metrics": language_metrics,
        "latency_ms": {
            "p50": round(percentile(durations, 0.50), 4),
            "p95": round(percentile(durations, 0.95), 4),
            "p99": round(percentile(durations, 0.99), 4),
            "mean": round(statistics.mean(durations), 4) if durations else 0,
        },
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor() or "not reported",
        },
        "notes": "Single-process synthetic filter benchmark; not a production load test, independent red-team evaluation, or SLA claim.",
    }
    output = ROOT / "benchmarks" / "results" / "latest.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    print(f"Saved {output.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
