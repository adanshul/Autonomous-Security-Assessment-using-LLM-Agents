"""Deterministic evidence validators. Planners cannot author accepted findings."""

from __future__ import annotations

from collections import deque

from .iam import Decision, items, policy_decision, role_decision, statements, unrestricted_admin
from .models import Finding, Snapshot

IAM_DOC = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html"
)
S3_DOC = (
    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
)
EC2_DOC = "https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html"
RULES = {
    "IAM_ADMIN": ("role", "Unrestricted administrator policy"),
    "IAM_PUBLIC_TRUST": ("role", "Unconditional wildcard AWS trust"),
    "IAM_ASSUME_ADMIN_PATH": ("role", "Role-assumption path to administrator"),
    "S3_PUBLIC_POLICY": ("bucket", "Public bucket policy without an observed restriction"),
    "EC2_OPEN_ADMIN": ("security_group", "Administrative ports open to the internet"),
}
STATIC_RULES = tuple(k for k in RULES if k != "IAM_ASSUME_ADMIN_PATH")


def pointer(collection: str, key: str, field: str = "") -> str:
    escaped = key.replace("~", "~0").replace("/", "~1")
    return f"/{collection}/{escaped}" + (f"/{field}" if field else "")


class Verifier:
    def __init__(self, snapshot: Snapshot):
        self.snapshot = snapshot
        self._graph: dict[str, list[str]] | None = None

    def graph(self) -> dict[str, list[str]]:
        if self._graph is not None:
            return self._graph
        roles = self.snapshot.roles
        if len(roles) > 250:
            raise ValueError("Path analysis supports at most 250 roles; split the snapshot")
        graph = {k: [] for k in roles}
        for source, role in sorted(roles.items()):
            for target, target_role in sorted(roles.items()):
                if source == target:
                    continue
                identity = role_decision(role, "sts:AssumeRole", target_role.arn)
                trust = policy_decision(
                    [target_role.trust], "sts:AssumeRole", target_role.arn, principal=role.arn
                )
                if identity == trust == Decision.ALLOW:
                    graph[source].append(target)
        self._graph = graph
        return graph

    def paths(self, source: str) -> list[list[str]]:
        graph = self.graph()
        queue = deque([[source]])
        seen = {source}
        paths = []
        while queue:
            path = queue.popleft()
            if len(path) > 1 and unrestricted_admin(self.snapshot.roles[path[-1]]):
                paths.append(path)
                continue
            for target in graph[path[-1]]:
                if target not in seen:
                    seen.add(target)
                    queue.append([*path, target])
        return paths

    def check(self, rule_id: str, resource_id: str) -> list[Finding]:
        if rule_id not in RULES:
            raise ValueError("Unknown rule; only documented checks are permitted")
        if self.snapshot.catalog().get(resource_id) != RULES[rule_id][0]:
            raise ValueError("Rule and resource kind do not match, or resource is out of scope")
        snap = self.snapshot
        result = []

        def add(description, evidence, remediation, reference, *, severity="high", path=None):
            status = "configuration_observed"
            if rule_id == "IAM_ASSUME_ADMIN_PATH":
                status = (
                    "simulated"
                    if snap.source == "synthetic" and snap.controls_complete
                    else "needs_review"
                )
            result.append(
                Finding(
                    rule_id=rule_id,
                    resource_id=resource_id,
                    title=RULES[rule_id][1],
                    severity=severity,
                    status=status,
                    description=description,
                    evidence=evidence,
                    remediation=remediation,
                    references=[reference],
                    path=path or [],
                )
            )

        if rule_id == "IAM_ADMIN" and unrestricted_admin(snap.roles[resource_id]):
            add(
                "An unconditional Action=* and Resource=* grant survives the modeled boundary. "
                "Organizational and session controls may further restrict live access.",
                [
                    pointer("roles", resource_id, "policies"),
                    pointer("roles", resource_id, "boundary"),
                ],
                "Replace wildcard grants with required actions and resources. Review a permissions "
                "boundary, then re-collect and compare assessments before changing production.",
                IAM_DOC,
                severity="critical",
            )
        elif rule_id == "IAM_PUBLIC_TRUST":
            role = snap.roles[resource_id]
            wildcard = any(
                "*"
                in items(
                    s.get("Principal", {}).get("AWS", [])
                    if isinstance(s.get("Principal"), dict)
                    else s.get("Principal", [])
                )
                for s in statements(role.trust)
            )
            if (
                wildcard
                and policy_decision([role.trust], "sts:AssumeRole", role.arn, principal="*")
                == Decision.ALLOW
            ):
                add(
                    "The trust document allows sts:AssumeRole for any AWS principal without "
                    "conditions. Caller-side permission is still required; "
                    "this is a trust finding.",
                    [pointer("roles", resource_id, "trust")],
                    "Replace wildcard AWS principals with approved role ARNs and add appropriate "
                    "organization, external-ID, or source constraints. Validate intended callers.",
                    IAM_DOC,
                )
        elif rule_id == "IAM_ASSUME_ADMIN_PATH":
            if unrestricted_admin(snap.roles[resource_id]):
                return []
            for path in self.paths(resource_id):
                evidence = []
                for source, target in zip(path, path[1:], strict=False):
                    evidence.extend(
                        [
                            pointer("roles", source, "policies"),
                            pointer("roles", source, "boundary"),
                            pointer("roles", target, "trust"),
                        ]
                    )
                evidence.append(pointer("roles", path[-1], "policies"))
                add(
                    "The snapshot model permits each role-assumption edge to an unrestricted "
                    "administrator. This is an offline reachability proof, "
                    "not an executed AWS exploit.",
                    list(dict.fromkeys(evidence)),
                    "Break the first unnecessary sts:AssumeRole grant or restrict its trust. "
                    "Reduce terminal-role privileges. Re-run functional and security checks.",
                    IAM_DOC,
                    severity="critical",
                    path=path,
                )
        elif rule_id == "S3_PUBLIC_POLICY":
            bucket = snap.buckets[resource_id]
            if bucket.public_policy is True and bucket.restrict_public_buckets is not True:
                add(
                    "S3 classifies the bucket policy as public. RestrictPublicBuckets is false "
                    "or unknown at the observed account/bucket levels. Object access, ACLs and "
                    "organization controls were not tested.",
                    [pointer("buckets", resource_id)],
                    "Review whether public access is intended. Restrict the policy to approved "
                    "principals and enable all four Block Public Access settings at both levels.",
                    S3_DOC,
                )
                if bucket.restrict_public_buckets is None:
                    result[-1].status = "needs_review"
        elif rule_id == "EC2_OPEN_ADMIN":
            for index, ingress in enumerate(snap.security_groups[resource_id].ingress):
                public = set(ingress.cidrs) & {"0.0.0.0/0", "::/0"}
                ports = [
                    p
                    for p in (22, 3389)
                    if (
                        ingress.protocol == "-1"
                        or (
                            ingress.protocol in ("tcp", "6")
                            and ingress.from_port is not None
                            and ingress.to_port is not None
                            and ingress.from_port <= p <= ingress.to_port
                        )
                    )
                ]
                if public and ports:
                    add(
                        f"Ingress allows administrative TCP ports {ports} from {sorted(public)}. "
                        "Routes, NACLs and listening services were not assessed.",
                        [pointer("security_groups", resource_id, f"ingress/{index}")],
                        "Remove internet-wide SSH/RDP ingress. Use a managed session service or "
                        "approved private CIDRs and verify that operator access still works.",
                        EC2_DOC,
                    )
            if result:
                result[0].evidence = [e for f in result for e in f.evidence]
                result = result[:1]
        return result
