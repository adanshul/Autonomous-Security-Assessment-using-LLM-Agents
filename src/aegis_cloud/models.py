"""Versioned contracts shared by collectors, planners, verifiers and scorers."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Role(Contract):
    arn: str
    policies: list[dict[str, Any]] = Field(default_factory=list)
    trust: dict[str, Any] = Field(default_factory=lambda: {"Statement": []})
    boundary: list[dict[str, Any]] | None = None
    policies_complete: bool = True


class Bucket(Contract):
    arn: str
    public_policy: bool | None = None
    restrict_public_buckets: bool | None = None


class Ingress(Contract):
    protocol: str
    from_port: int | None = None
    to_port: int | None = None
    cidrs: list[str] = Field(default_factory=list)


class SecurityGroup(Contract):
    arn: str
    ingress: list[Ingress] = Field(default_factory=list)


class Snapshot(Contract):
    schema_version: Literal[1] = 1
    snapshot_id: str = Field(pattern=r"^[a-zA-Z0-9_.-]{1,100}$")
    account_id: str = Field(pattern=r"^\d{12}$")
    source: Literal["synthetic", "aws"]
    regions: list[str] = Field(default_factory=list)
    captured_at: str | None = None
    controls_complete: bool = False
    roles: dict[str, Role] = Field(default_factory=dict)
    buckets: dict[str, Bucket] = Field(default_factory=dict)
    security_groups: dict[str, SecurityGroup] = Field(default_factory=dict)
    collection_errors: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique_resources(self) -> Snapshot:
        keys = [*self.roles, *self.buckets, *self.security_groups]
        if len(keys) != len(set(keys)):
            raise ValueError("Resource IDs must be unique across resource kinds")
        if len(keys) > 5000:
            raise ValueError("Snapshot exceeds the 5000-resource limit; split the assessment")
        for key in keys:
            if not key or len(key) > 512:
                raise ValueError("Resource IDs must contain 1-512 characters")
        return self

    def catalog(self) -> dict[str, str]:
        return {
            **dict.fromkeys(self.roles, "role"),
            **dict.fromkeys(self.buckets, "bucket"),
            **dict.fromkeys(self.security_groups, "security_group"),
        }

    def resource(self, resource_id: str) -> Role | Bucket | SecurityGroup:
        for collection in (self.roles, self.buckets, self.security_groups):
            if resource_id in collection:
                return collection[resource_id]
        raise ValueError("Resource is outside the snapshot scope")


class Finding(Contract):
    rule_id: str
    resource_id: str
    title: str
    severity: Literal["critical", "high", "medium", "low"]
    status: Literal["simulated", "configuration_observed", "needs_review"]
    description: str
    evidence: list[str]
    remediation: str
    references: list[str]
    path: list[str] = Field(default_factory=list)

    @property
    def key(self) -> str:
        # One issue per rule/source/terminal role; alternative paths are not inflated.
        suffix = f"->{self.path[-1]}" if self.path else ""
        return f"{self.rule_id}:{self.resource_id}{suffix}"


class Action(Contract):
    tool: Literal["inspect", "check", "finish"]
    resource_id: str | None = None
    rule_id: str | None = None

    @model_validator(mode="after")
    def valid_arguments(self) -> Action:
        if self.tool == "finish" and (self.resource_id is not None or self.rule_id is not None):
            raise ValueError("finish takes no arguments")
        if self.tool != "finish" and not self.resource_id:
            raise ValueError("resource_id is required")
        if self.tool == "check" and not self.rule_id:
            raise ValueError("check requires rule_id")
        if self.tool == "inspect" and self.rule_id is not None:
            raise ValueError("inspect does not accept rule_id")
        return self


class Assessment(Contract):
    schema_version: Literal[1] = 1
    tool_version: str = "0.1.0"
    snapshot_id: str
    snapshot_sha256: str
    source: Literal["synthetic", "aws"]
    engine: str
    model_id: str | None = None
    status: Literal["completed", "budget_exhausted", "planner_error"]
    elapsed_seconds: float
    steps: int
    checks_completed: int
    checks_available: int
    input_tokens: int = 0
    output_tokens: int = 0
    findings: list[Finding]
    warnings: list[str]
    trace: list[dict[str, Any]]
    trace_sha256: str
