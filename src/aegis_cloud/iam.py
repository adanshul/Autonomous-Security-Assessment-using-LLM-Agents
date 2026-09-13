"""Deliberately small three-valued IAM model, never an AWS authorization oracle.

Unresolved conditions, NotAction/NotResource and policy variables propagate UNKNOWN.
Only unconditional explicit denies are conclusive; missing context never becomes ALLOW.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any

from .models import Role


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    UNKNOWN = "unknown"


def items(value: Any) -> list:
    return value if isinstance(value, list) else [value]


def statements(policy: dict) -> list[dict]:
    value = policy.get("Statement", [])
    return [s for s in items(value) if isinstance(s, dict)]


def match(pattern: str, value: str, *, ignore_case: bool = False) -> bool:
    # IAM glob syntax has only * and ?; Python fnmatch also interprets [character classes].
    expr = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
    return re.fullmatch(expr, value, re.IGNORECASE if ignore_case else 0) is not None


def policy_decision(
    policies: list[dict], action: str, resource: str, *, principal: str | None = None
) -> Decision:
    allowed = uncertain = False
    for policy in policies:
        if "Statement" not in policy or not isinstance(policy["Statement"], (dict, list)):
            uncertain = True
        if any(not isinstance(s, dict) for s in items(policy.get("Statement", []))):
            uncertain = True
        for stmt in statements(policy):
            if "NotAction" in stmt or "NotResource" in stmt or "NotPrincipal" in stmt:
                uncertain = True
                continue
            actions = items(stmt.get("Action", []))
            resources = items(stmt.get("Resource", "*" if principal else []))
            if any(not isinstance(x, str) or "${" in x for x in actions + resources):
                uncertain = True
                continue
            if not any(match(a, action, ignore_case=True) for a in actions):
                continue
            if not any(match(r, resource) for r in resources):
                continue
            if principal is not None:
                target = stmt.get("Principal", {})
                principals = items(target.get("AWS", []) if isinstance(target, dict) else target)
                if principal not in principals and "*" not in principals:
                    # Account-root and federated/session principals need extra context.
                    if any(isinstance(p, str) and p.endswith(":root") for p in principals):
                        uncertain = True
                    continue
            if stmt.get("Condition"):
                uncertain = True
                continue
            if stmt.get("Effect") == "Deny":
                return Decision.DENY
            if stmt.get("Effect") == "Allow":
                allowed = True
            else:
                uncertain = True
    if uncertain:
        return Decision.UNKNOWN
    return Decision.ALLOW if allowed else Decision.DENY


def role_decision(role: Role, action: str, resource: str) -> Decision:
    identity = policy_decision(role.policies, action, resource)
    if not role.policies_complete:
        return Decision.UNKNOWN
    if role.boundary is None:
        return identity
    boundary = policy_decision(role.boundary, action, resource)
    if Decision.DENY in (identity, boundary):
        return Decision.DENY
    if Decision.UNKNOWN in (identity, boundary):
        return Decision.UNKNOWN
    return Decision.ALLOW


def unrestricted_admin(role: Role) -> bool:
    """Prove universal allow in this model, rather than sampling a few powerful actions."""
    if not role.policies_complete:
        return False
    sets = [role.policies] + ([role.boundary] if role.boundary is not None else [])
    for policies in sets:
        if any("Statement" not in p for p in policies):
            return False
        if any(not isinstance(s, dict) for p in policies for s in items(p.get("Statement", []))):
            return False
        stmts = [s for p in policies for s in statements(p)]
        if any(s.get("Effect") != "Allow" or s.get("Condition") for s in stmts):
            return False
        if not any(
            "*" in items(s.get("Action", []))
            and "*" in items(s.get("Resource", []))
            and not any(k in s for k in ("NotAction", "NotResource", "NotPrincipal"))
            for s in stmts
        ):
            return False
    return True
