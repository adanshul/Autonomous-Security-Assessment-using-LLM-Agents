import copy
import json

import pytest
from pydantic import ValidationError

from aegis_cloud.benchmark import load_suite
from aegis_cloud.checks import Verifier, pointer
from aegis_cloud.cli import lab_path
from aegis_cloud.models import Action, Snapshot, digest
from aegis_cloud.orchestrator import assess, verify_trace
from aegis_cloud.planners import BedrockPlanner, ReferencePlanner


def test_all_labs_match_independent_ground_truth():
    suite, snapshots = load_suite(lab_path("labels.json"))
    assert len(suite.cases) == 12
    for name, snapshot in snapshots.items():
        report = assess(snapshot, ReferencePlanner(snapshot))
        assert report.status == "completed"
        assert {f.key for f in report.findings} == set(suite.cases[name].expected_keys), name
        assert verify_trace(report.trace, report.trace_sha256)
        # Every evidence pointer must resolve in the archived snapshot.
        data = snapshot.model_dump()
        for finding in report.findings:
            for evidence in finding.evidence:
                value = data
                for part in evidence.lstrip("/").split("/"):
                    token = part.replace("~1", "/").replace("~0", "~")
                    value = value[int(token)] if isinstance(value, list) else value[token]


def test_static_ablation_does_not_include_graph(exposed):
    report = assess(exposed, ReferencePlanner(exposed, static=True))
    assert len(report.findings) == 4
    assert all(f.rule_id != "IAM_ASSUME_ADMIN_PATH" for f in report.findings)


def test_live_paths_need_review(exposed):
    exposed.source = "aws"
    exposed.controls_complete = False
    findings = Verifier(exposed).check("IAM_ASSUME_ADMIN_PATH", "ci")
    assert findings[0].path == ["ci", "broker", "admin"]
    assert findings[0].status == "needs_review"


def test_trust_and_identity_required(exposed):
    exposed.roles["admin"].trust = {"Statement": []}
    assert not Verifier(exposed).check("IAM_ASSUME_ADMIN_PATH", "ci")


def test_multiple_ingress_rules_deduplicate(exposed):
    rule = exposed.security_groups["admin-sg"].ingress[0].model_copy(deep=True)
    rule.from_port = rule.to_port = 3389
    exposed.security_groups["admin-sg"].ingress.append(rule)
    findings = Verifier(exposed).check("EC2_OPEN_ADMIN", "admin-sg")
    assert len(findings) == 1
    assert len(findings[0].evidence) == 2


def test_verifier_scope_and_rule_types(exposed):
    verifier = Verifier(exposed)
    for rule, resource in [("shell", "ci"), ("IAM_ADMIN", "outside"), ("IAM_ADMIN", "admin-sg")]:
        with pytest.raises(ValueError):
            verifier.check(rule, resource)
    with pytest.raises(ValueError):
        exposed.resource("outside")
    assert pointer("roles", "a/b~c", "trust") == "/roles/a~1b~0c/trust"


def test_graph_limit(exposed):
    exposed.roles = {str(n): exposed.roles["ci"] for n in range(251)}
    with pytest.raises(ValueError, match="250"):
        Verifier(exposed).graph()


@pytest.mark.parametrize(
    "data",
    [
        {"tool": "shell", "command": "echo forbidden"},
        {"tool": "finish", "resource_id": "x"},
        {"tool": "inspect"},
        {"tool": "check", "resource_id": "x"},
        {"tool": "inspect", "resource_id": "x", "rule_id": "IAM_ADMIN"},
        {"tool": "check", "resource_id": "x", "rule_id": "IAM_ADMIN", "code": "bad"},
    ],
)
def test_action_contract_rejects_unsafe_shapes(data):
    with pytest.raises(ValidationError):
        Action.model_validate(data)


def test_snapshot_validation(raw_exposed):
    raw_exposed["expected_keys"] = ["secret-label"]
    with pytest.raises(ValidationError):
        Snapshot.model_validate(raw_exposed)
    del raw_exposed["expected_keys"]
    raw_exposed["buckets"]["ci"] = raw_exposed["buckets"]["research-data"]
    with pytest.raises(ValidationError):
        Snapshot.model_validate(raw_exposed)


def test_step_budget_and_trace_integrity(exposed):
    report = assess(exposed, ReferencePlanner(exposed), max_steps=1)
    assert report.status == "budget_exhausted"
    assert report.steps == 1
    changed = copy.deepcopy(report.trace)
    changed[0]["result"] = {"tampered": True}
    assert not verify_trace(changed, report.trace_sha256)
    assert not verify_trace(report.trace, "bad")
    with pytest.raises(ValueError):
        assess(exposed, ReferencePlanner(exposed), max_steps=0)


class FakeClient:
    def __init__(self, text='{"tool":"finish"}', stop="end_turn"):
        self.text, self.stop, self.requests = text, stop, []

    def converse(self, **kwargs):
        self.requests.append(kwargs)
        return {
            "output": {"message": {"content": [{"text": self.text}]}},
            "stopReason": self.stop,
            "usage": {"inputTokens": 30, "outputTokens": 10},
        }


def test_real_provider_contract_and_no_label_leakage(exposed):
    client = FakeClient()
    planner = BedrockPlanner(client, "test-model")
    report = assess(exposed, planner)
    assert report.status == "completed"
    assert report.input_tokens == 30 and report.output_tokens == 10
    assert report.checks_completed == 0 and report.checks_available == 14
    observation = json.loads(client.requests[0]["messages"][0]["content"][0]["text"])
    assert "expected_keys" not in json.dumps(observation)
    assert "policies" not in json.dumps(observation)
    assert client.requests[0]["modelId"] == "test-model"


@pytest.mark.parametrize(
    "text,stop",
    [
        ("not JSON", "end_turn"),
        ('{"tool":"shell"}', "end_turn"),
        ('{"tool":"check","resource_id":"outside","rule_id":"IAM_ADMIN"}', "end_turn"),
        ('{"tool":"finish"}', "max_tokens"),
        ("x" * 10_001, "end_turn"),
    ],
)
def test_malformed_or_out_of_scope_model_actions_stop(exposed, text, stop):
    report = assess(exposed, BedrockPlanner(FakeClient(text, stop), "test-model"))
    assert report.status == "planner_error"
    assert not report.findings


def test_repeated_actions_stop(exposed):
    client = FakeClient('{"tool":"inspect","resource_id":"ci"}')
    report = assess(exposed, BedrockPlanner(client, "test-model"))
    assert report.status == "planner_error" and report.steps == 2
    assert any("Repeated action" in w for w in report.warnings)


def test_model_budgets_checked_before_network(exposed):
    for kwargs in ({"max_total_tokens": 1}, {"max_context_chars": 1}):
        client = FakeClient()
        report = assess(exposed, BedrockPlanner(client, "test-model", **kwargs))
        assert report.status == "planner_error"
        assert not client.requests
    with pytest.raises(ValueError):
        BedrockPlanner(FakeClient(), "")
    with pytest.raises(ValueError):
        BedrockPlanner(FakeClient(), "x", max_total_tokens=0)


def test_sdk_errors_do_not_leak_exception_payload(exposed):
    class Broken(FakeClient):
        def converse(self, **kwargs):
            raise RuntimeError("sensitive-request-payload")

    report = assess(exposed, BedrockPlanner(Broken(), "test-model"))
    assert report.status == "planner_error"
    assert "sensitive-request-payload" not in report.model_dump_json()


def test_deterministic_findings_and_trace(exposed):
    first = assess(exposed, ReferencePlanner(exposed))
    second = assess(exposed, ReferencePlanner(exposed))
    assert first.findings == second.findings
    assert first.trace_sha256 == second.trace_sha256
    assert first.snapshot_sha256 == digest(exposed.model_dump())
