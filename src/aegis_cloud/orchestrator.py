"""A bounded planner -> tool -> verifier loop with a tamper-evident event chain."""

from __future__ import annotations

import time

from .checks import RULES, Verifier
from .models import Assessment, Snapshot, canonical, digest
from .planners import Planner


def verify_trace(trace: list[dict], expected_hash: str) -> bool:
    previous = "0" * 64
    for event in trace:
        payload = {k: v for k, v in event.items() if k != "sha256"}
        if payload.get("previous_sha256") != previous or digest(payload) != event.get("sha256"):
            return False
        previous = event["sha256"]
    return previous == expected_hash


def assess(snapshot: Snapshot, planner: Planner, *, max_steps: int = 128) -> Assessment:
    if not 1 <= max_steps <= 10_000:
        raise ValueError("max_steps must be between 1 and 10000")
    start = time.perf_counter()
    verifier = Verifier(snapshot)
    findings = {}
    trace = []
    previous = "0" * 64
    completed = set()
    inspected = {}
    checks = []
    warnings = list(snapshot.collection_errors)
    if not snapshot.controls_complete:
        warnings.append("SCPs, RCPs, session policies and other context are not fully modeled.")
    warnings.append(
        "Conditions, NotAction/NotResource and policy variables may suppress IAM checks; "
        "no findings does not establish that an account is secure."
    )
    status = "budget_exhausted"
    steps = 0
    for step in range(1, max_steps + 1):
        steps = step
        action_data = None
        try:
            action = planner.next_action(
                {
                    "catalog": snapshot.catalog(),
                    "rules": {k: {"kind": v[0], "title": v[1]} for k, v in RULES.items()},
                    "inspected_resources": inspected,
                    "completed_checks": checks,
                    "remaining_steps": max_steps - step + 1,
                }
            )
            action_data = action.model_dump(exclude_none=True)
            signature = canonical(action_data)
            if signature in completed:
                raise ValueError("Repeated action rejected; planner made no progress")
            completed.add(signature)
            if action.tool == "finish":
                status = "completed"
                result = {"status": "finished"}
            elif action.tool == "inspect":
                resource = snapshot.resource(action.resource_id).model_dump()
                inspected[action.resource_id] = resource
                result = {"resource": resource}
            else:
                accepted = verifier.check(action.rule_id, action.resource_id)
                for finding in accepted:
                    findings[finding.key] = finding
                result = {"accepted_findings": [f.model_dump() for f in accepted]}
                checks.append({"action": action_data, "finding_keys": [f.key for f in accepted]})
        except Exception as exc:
            # Do not persist SDK exception text, which may contain account/model request data.
            status = "planner_error"
            message = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
            warnings.append(f"Assessment stopped: {message[:500]}")
            result = {"error": type(exc).__name__}
        event = {"step": step, "action": action_data, "result": result, "previous_sha256": previous}
        previous = digest(event)
        event["sha256"] = previous
        trace.append(event)
        if status in ("completed", "planner_error"):
            break
    if status == "budget_exhausted":
        warnings.append("Step budget exhausted; findings are partial.")
    available = sum(
        kind == rule_kind for kind in snapshot.catalog().values() for rule_kind, _ in RULES.values()
    )
    if len(checks) < available:
        warnings.append(
            f"Executed {len(checks)} of {available} registered resource checks. "
            "Unchecked rules remain outside this run's coverage."
        )
    return Assessment(
        snapshot_id=snapshot.snapshot_id,
        snapshot_sha256=digest(snapshot.model_dump()),
        source=snapshot.source,
        engine=planner.name,
        model_id=planner.model_id,
        status=status,
        elapsed_seconds=time.perf_counter() - start,
        steps=steps,
        checks_completed=len(checks),
        checks_available=available,
        input_tokens=planner.input_tokens,
        output_tokens=planner.output_tokens,
        findings=sorted(findings.values(), key=lambda f: f.key),
        warnings=warnings,
        trace=trace,
        trace_sha256=previous,
    )
