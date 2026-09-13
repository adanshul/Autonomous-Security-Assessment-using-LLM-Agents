import json

import pytest

from aegis_cloud.benchmark import (
    Run,
    Suite,
    benchmark,
    evaluate,
    load_suite,
    paired_bootstrap,
    score,
)
from aegis_cloud.cli import lab_path
from aegis_cloud.models import digest


def test_score_deduplicated_sets_and_zero_denominators():
    result = score({"a", "b"}, {"a", "c"})
    assert result == {
        "true_positives": 1,
        "false_positives": 1,
        "false_negatives": 1,
        "precision": 0.5,
        "recall": 0.5,
        "f1": 0.5,
    }
    assert score(set(), set())["recall"] is None
    assert score({"a"}, set())["precision"] is None
    assert score(set(), {"a"})["false_positives"] == 1


def test_reference_recovers_all_regression_labels():
    result = benchmark(lab_path("labels.json"))
    assert result["dataset_kind"] == "synthetic"
    assert result["methods"]["reference"]["micro_recall"] == 1
    assert result["methods"]["reference"]["false_positives"] == 0
    assert result["methods"]["static"]["micro_recall"] < 1
    assert result["comparison"]["all_cases_paired"]
    assert len(result["runs"]) == 24


def make_run(exposed, **kwargs):
    return Run(
        case_id="exposed",
        participant="human-01",
        method="human",
        snapshot_sha256=digest(exposed.model_dump()),
        finding_keys=["IAM_ADMIN:admin"],
        elapsed_seconds=10.0,
        **kwargs,
    )


def test_human_import_is_observation_not_generated_baseline(exposed):
    run = make_run(exposed, report_seconds=5.0)
    result = benchmark(lab_path("labels.json"), extra_runs=[run], candidate="human")
    assert result["methods"]["human"]["median_report_seconds"] == 5
    assert not result["comparison"]["all_cases_paired"]
    assert result["comparison"]["paired_cases"] == ["exposed"]


def test_import_validation(exposed):
    suite, snapshots = load_suite(lab_path("labels.json"))
    run = make_run(exposed)
    with pytest.raises(ValueError, match="Duplicate"):
        evaluate(suite, snapshots, [run, run])
    bad = run.model_copy(update={"case_id": "missing"})
    with pytest.raises(ValueError, match="Unknown case"):
        evaluate(suite, snapshots, [bad])
    bad = run.model_copy(update={"snapshot_sha256": "0" * 64})
    with pytest.raises(ValueError, match="hash mismatch"):
        evaluate(suite, snapshots, [bad])


def test_zero_baseline_lift_is_null(exposed):
    suite, snapshots = load_suite(lab_path("labels.json"))
    run = make_run(exposed)
    left = run.model_copy(update={"method": "static", "finding_keys": []})
    right = run.model_copy(update={"method": "reference"})
    result = evaluate(suite, snapshots, [left, right])
    assert result["comparison"]["relative_recall_lift"] is None


def test_bootstrap_is_seeded_and_empty_is_null():
    assert paired_bootstrap([], 42) is None
    assert paired_bootstrap([0.1, 0.3, -0.1], 42) == paired_bootstrap([0.1, 0.3, -0.1], 42)


def test_suite_cannot_escape_directory(tmp_path):
    path = tmp_path / "labels.json"
    data = {
        "schema_version": 1,
        "name": "bad",
        "dataset_kind": "synthetic",
        "cases": {
            "escape": {"snapshot_file": "../outside.json", "expected_keys": []},
        },
    }
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="within"):
        load_suite(path)
    data["cases"] = {}
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="contain cases"):
        load_suite(path)


def test_case_id_and_source_binding(tmp_path, exposed):
    source = tmp_path / "snapshot.json"
    source.write_text(exposed.model_dump_json())
    path = tmp_path / "labels.json"
    data = {
        "name": "bad",
        "dataset_kind": "synthetic",
        "cases": {
            "other": {"snapshot_file": "snapshot.json", "expected_keys": []},
        },
    }
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="Case ID"):
        load_suite(path)
    data["cases"]["exposed"] = data["cases"].pop("other")
    path.write_text(json.dumps(data))
    exposed.source = "aws"
    source.write_text(exposed.model_dump_json())
    with pytest.raises(ValueError, match="Synthetic"):
        load_suite(path)


def test_label_uniqueness_and_finite_timings(exposed):
    with pytest.raises(ValueError):
        Suite.model_validate(
            {
                "name": "x",
                "dataset_kind": "synthetic",
                "cases": {
                    "x": {"snapshot_file": "x.json", "expected_keys": ["a", "a"]},
                },
            }
        )
    with pytest.raises(ValueError):
        make_run(exposed, report_seconds=float("nan"))
