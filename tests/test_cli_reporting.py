import json
import runpy
from unittest.mock import MagicMock

import pytest

from aegis_cloud.cli import lab_path, main
from aegis_cloud.orchestrator import assess
from aegis_cloud.planners import ReferencePlanner
from aegis_cloud.reporting import render_html, sarif


def test_demo_bundle_verify_replay_and_tampering(tmp_path, capsys):
    out = tmp_path / "demo"
    assert main(["demo", "--out", str(out)]) == 0
    assert {p.name for p in out.iterdir()} == {
        "report.html",
        "report.md",
        "report.json",
        "report.sarif",
        "snapshot.json",
        "trace.jsonl",
    }
    assert main(["verify", str(out)]) == 0
    assert main(["replay", str(out), "--out", str(tmp_path / "replay")]) == 0
    assert "Replayed 6 findings offline" in capsys.readouterr().out
    report = json.loads((out / "report.json").read_text())
    report["findings"] = []
    (out / "report.json").write_text(json.dumps(report))
    assert main(["verify", str(out)]) == 2
    assert main(["replay", str(out), "--out", str(tmp_path / "bad-replay")]) == 2
    assert not (tmp_path / "bad-replay").exists()


def test_cli_assess_diff_and_export(tmp_path):
    before, after = tmp_path / "before", tmp_path / "after"
    assert main(["demo", "--out", str(before)]) == 0
    assert main(["assess", str(lab_path("hardened.json")), "--out", str(after)]) == 0
    diff = tmp_path / "diff.json"
    assert (
        main(["diff", str(before / "report.json"), str(after / "report.json"), "--out", str(diff)])
        == 0
    )
    assert len(json.loads(diff.read_text())["no_longer_observed"]) == 6
    exported = tmp_path / "run.json"
    assert (
        main(
            [
                "export-run",
                str(before / "report.json"),
                "--participant",
                "tester",
                "--method",
                "custom",
                "--out",
                str(exported),
            ]
        )
        == 0
    )
    assert json.loads(exported.read_text())[0]["report_seconds"] is None
    benchmark = tmp_path / "benchmark"
    assert (
        main(
            ["benchmark", "--runs", str(exported), "--candidate", "custom", "--out", str(benchmark)]
        )
        == 0
    )
    assert "custom" in json.loads((benchmark / "benchmark.json").read_text())["methods"]


def test_cli_rejects_overwrite_and_bad_inputs(tmp_path):
    assert main(["demo", "--out", str(tmp_path)]) == 2
    assert main(["assess", str(tmp_path / "missing"), "--out", str(tmp_path / "out")]) == 2
    assert main(["benchmark", "--out", str(tmp_path)]) == 2
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    assert main(["benchmark", "--runs", str(bad), "--out", str(tmp_path / "b")]) == 2


def test_incomplete_and_mismatched_diff_rejected(tmp_path):
    partial, full, static = tmp_path / "partial", tmp_path / "full", tmp_path / "static"
    assert (
        main(["assess", str(lab_path("exposed.json")), "--max-steps", "1", "--out", str(partial)])
        == 2
    )
    assert main(["demo", "--out", str(full)]) == 0
    assert (
        main(["assess", str(lab_path("exposed.json")), "--engine", "static", "--out", str(static)])
        == 0
    )
    for left in (partial, static):
        assert (
            main(
                [
                    "diff",
                    str(left / "report.json"),
                    str(full / "report.json"),
                    "--out",
                    str(tmp_path / "diff.json"),
                ]
            )
            == 2
        )


def test_bedrock_requires_explicit_optin_and_model(tmp_path):
    args = [
        "assess",
        str(lab_path("exposed.json")),
        "--engine",
        "bedrock",
        "--out",
        str(tmp_path / "out"),
    ]
    assert main(args) == 2
    assert main([*args, "--allow-model-data-transfer"]) == 2


def test_cli_bedrock_uses_injected_client_only(tmp_path, monkeypatch):
    fake = MagicMock()
    fake.client.return_value.converse.return_value = {
        "output": {"message": {"content": [{"text": '{"tool":"finish"}'}]}},
        "stopReason": "end_turn",
        "usage": {"inputTokens": 10, "outputTokens": 5},
    }
    monkeypatch.setattr("aegis_cloud.aws.session", lambda *args: fake)
    out = tmp_path / "llm"
    assert (
        main(
            [
                "assess",
                str(lab_path("exposed.json")),
                "--engine",
                "bedrock",
                "--model-id",
                "test-model",
                "--allow-model-data-transfer",
                "--out",
                str(out),
            ]
        )
        == 0
    )
    assert json.loads((out / "report.json").read_text())["engine"] == "bedrock"


def test_cli_collection_with_injected_gateway(tmp_path, monkeypatch, exposed):
    monkeypatch.setattr("aegis_cloud.aws.session", lambda *args: MagicMock())
    monkeypatch.setattr("aegis_cloud.aws.collect", lambda *args, **kwargs: exposed)
    out = tmp_path / "snapshot.json"
    args = ["collect", "--account-id", "111111111111", "--region", "us-east-1", "--out", str(out)]
    assert main(args) == 0
    assert main(args) == 2
    exposed.collection_errors = ["AccessDenied"]
    assert main([*args[:-1], str(tmp_path / "partial.json")]) == 2


def test_html_escapes_resource_content_and_sarif_has_stable_ids(exposed):
    report = assess(exposed, ReferencePlanner(exposed))
    report.findings[0].resource_id = '<img src=x onerror="alert(1)">'
    text = render_html(report)
    assert "<img src=x" not in text
    assert "&lt;img" in text
    assert "Content-Security-Policy" in text
    data = sarif(report)
    assert data["version"] == "2.1.0"
    results = data["runs"][0]["results"]
    assert len(results) == 6
    assert len({r["partialFingerprints"]["aegisFindingKey/v1"] for r in results}) == 6


def test_module_entrypoint(monkeypatch):
    monkeypatch.setattr("sys.argv", ["aegis", "--version"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("aegis_cloud", run_name="__main__")
    assert exc.value.code == 0
