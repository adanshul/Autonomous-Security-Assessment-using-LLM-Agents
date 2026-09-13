"""Ground-truth scoring, paired case bootstrap and externally adjudicated run import."""

from __future__ import annotations

import random
import statistics
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from .models import Contract, Snapshot, digest
from .orchestrator import assess
from .planners import ReferencePlanner


class LabelCase(Contract):
    snapshot_file: str
    expected_keys: list[str]

    @model_validator(mode="after")
    def unique_labels(self):
        if len(set(self.expected_keys)) != len(self.expected_keys):
            raise ValueError("Ground-truth keys must be unique")
        return self


class Suite(Contract):
    schema_version: Literal[1] = 1
    name: str
    dataset_kind: Literal["synthetic", "empirical"]
    cases: dict[str, LabelCase]


class Run(Contract):
    case_id: str
    participant: str
    method: str
    snapshot_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    finding_keys: list[str]
    elapsed_seconds: float = Field(ge=0, allow_inf_nan=False)
    report_seconds: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    status: Literal["completed", "budget_exhausted", "planner_error"] = "completed"


def load_suite(path: Path) -> tuple[Suite, dict[str, Snapshot]]:
    suite = Suite.model_validate_json(path.read_text(encoding="utf-8"))
    if not suite.cases:
        raise ValueError("A benchmark suite must contain cases")
    snapshots = {}
    root = path.parent.resolve()
    for case_id, case in suite.cases.items():
        source = (root / case.snapshot_file).resolve()
        if not source.is_relative_to(root):
            raise ValueError("Suite snapshot paths must stay within the suite directory")
        snapshot = Snapshot.model_validate_json(source.read_text(encoding="utf-8"))
        if snapshot.snapshot_id != case_id:
            raise ValueError("Case ID does not match its snapshot ID")
        if suite.dataset_kind == "synthetic" and snapshot.source != "synthetic":
            raise ValueError("Synthetic suites may only contain synthetic snapshots")
        snapshots[case_id] = snapshot
    return suite, snapshots


def score(expected: set[str], observed: set[str]) -> dict:
    tp = len(expected & observed)
    fp = len(observed - expected)
    fn = len(expected - observed)
    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
    }


def paired_bootstrap(deltas: list[float], seed: int, samples: int = 2000) -> dict | None:
    if not deltas:
        return None
    rng = random.Random(seed)
    means = sorted(statistics.mean(rng.choices(deltas, k=len(deltas))) for _ in range(samples))
    return {
        "mean": statistics.mean(deltas),
        "ci95": [means[49], means[1949]],
        "n_cases": len(deltas),
        "resamples": samples,
        "seed": seed,
    }


def evaluate(
    suite: Suite,
    snapshots: dict[str, Snapshot],
    runs: list[Run],
    *,
    seed: int = 42,
    baseline: str = "static",
    candidate: str = "reference",
) -> dict:
    grouped = {}
    rows = []
    seen = set()
    for run in runs:
        if run.case_id not in suite.cases:
            raise ValueError(f"Unknown case ID: {run.case_id}")
        if run.snapshot_sha256 != digest(snapshots[run.case_id].model_dump()):
            raise ValueError(f"Snapshot hash mismatch for {run.case_id}")
        identity = (run.method, run.participant, run.case_id)
        if identity in seen:
            raise ValueError("Duplicate method/participant/case run")
        seen.add(identity)
        metrics = score(set(suite.cases[run.case_id].expected_keys), set(run.finding_keys))
        row = {**run.model_dump(), **metrics}
        rows.append(row)
        grouped.setdefault(run.method, []).append(row)
    methods = {}
    for method, entries in grouped.items():
        # Weight each case equally, then each participant within a case equally.
        by_case = {}
        for row in entries:
            by_case.setdefault(row["case_id"], []).append(row)
        case_recalls = {
            case: statistics.mean(r["recall"] for r in group if r["recall"] is not None)
            for case, group in by_case.items()
            if any(r["recall"] is not None for r in group)
        }
        tp = sum(e["true_positives"] for e in entries)
        fp = sum(e["false_positives"] for e in entries)
        fn = sum(e["false_negatives"] for e in entries)
        times = [e["report_seconds"] for e in entries if e["report_seconds"] is not None]
        methods[method] = {
            "runs": len(entries),
            "cases": len(by_case),
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "micro_precision": tp / (tp + fp) if tp + fp else None,
            "micro_recall": tp / (tp + fn) if tp + fn else None,
            "macro_recall": statistics.mean(case_recalls.values()) if case_recalls else None,
            "case_recalls": case_recalls,
            "median_elapsed_seconds": statistics.median(e["elapsed_seconds"] for e in entries),
            "median_report_seconds": statistics.median(times) if times else None,
            "incomplete_runs": sum(e["status"] != "completed" for e in entries),
        }
    comparison = None
    if baseline in methods and candidate in methods:
        left, right = methods[baseline], methods[candidate]
        paired = sorted(set(left["case_recalls"]) & set(right["case_recalls"]))
        deltas = [right["case_recalls"][c] - left["case_recalls"][c] for c in paired]
        base = statistics.mean(left["case_recalls"][c] for c in paired) if paired else None
        delta = statistics.mean(deltas) if deltas else None
        comparison = {
            "baseline": baseline,
            "candidate": candidate,
            "paired_cases": paired,
            "recall_difference": paired_bootstrap(deltas, seed),
            "relative_recall_lift": delta / base if base else None,
            "all_cases_paired": set(paired)
            == {c for c, labels in suite.cases.items() if labels.expected_keys},
        }
    return {
        "schema_version": 1,
        "suite": suite.name,
        "suite_sha256": digest(suite.model_dump()),
        "dataset_kind": suite.dataset_kind,
        "methods": methods,
        "comparison": comparison,
        "runs": rows,
        "interpretation": (
            "Synthetic regression data. This does not measure LLM efficacy or human performance."
            if suite.dataset_kind == "synthetic"
            else "Imported empirical observations require independent adjudication "
            "and study review."
        ),
    }


def benchmark(
    suite_path: Path,
    *,
    extra_runs: list[Run] | None = None,
    seed: int = 42,
    baseline: str = "static",
    candidate: str = "reference",
) -> dict:
    suite, snapshots = load_suite(suite_path)
    runs = []
    for case_id, snapshot in snapshots.items():
        for static in (True, False):
            report = assess(snapshot, ReferencePlanner(snapshot, static=static), max_steps=10_000)
            runs.append(
                Run(
                    case_id=case_id,
                    participant="builtin",
                    method=report.engine,
                    snapshot_sha256=report.snapshot_sha256,
                    finding_keys=[f.key for f in report.findings],
                    elapsed_seconds=report.elapsed_seconds,
                    status=report.status,
                )
            )
    return evaluate(
        suite,
        snapshots,
        runs + (extra_runs or []),
        seed=seed,
        baseline=baseline,
        candidate=candidate,
    )
