"""Read-only collection with account binding, pagination and an API-call ceiling."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from urllib.parse import unquote

from .models import Bucket, Ingress, Role, SecurityGroup, Snapshot

READ_OPERATIONS = {
    "sts": {"get_caller_identity"},
    "iam": {"get_account_authorization_details"},
    "ec2": {"describe_security_groups"},
    "s3": {"get_bucket_policy_status", "get_public_access_block"},
    "s3control": {"get_public_access_block"},
}


def session(profile: str | None, region: str):
    try:
        import boto3
    except ImportError as exc:
        raise ValueError("Install AWS support with: pip install '.[aws]'") from exc
    return boto3.Session(profile_name=profile, region_name=region)


def client_config():
    from botocore.config import Config

    return Config(connect_timeout=10, read_timeout=45, retries={"total_max_attempts": 1})


class ReadOnlyGateway:
    def __init__(self, aws_session, max_calls: int = 500):
        if max_calls < 1:
            raise ValueError("max_calls must be positive")
        self.session = aws_session
        self.max_calls = max_calls
        self.calls = 0
        self.clients = {}

    def call(self, service: str, operation: str, region: str, **kwargs):
        if operation not in READ_OPERATIONS.get(service, set()):
            raise ValueError("AWS operation is not on the read-only allowlist")
        if self.calls >= self.max_calls:
            raise ValueError("AWS API-call budget exhausted")
        self.calls += 1
        key = (service, region)
        if key not in self.clients:
            self.clients[key] = self.session.client(
                service, region_name=region, config=client_config()
            )
        return getattr(self.clients[key], operation)(**kwargs)


def document(value):
    return value if isinstance(value, dict) else json.loads(unquote(value))


def collect(
    gateway: ReadOnlyGateway,
    *,
    account_id: str,
    regions: list[str],
    buckets: list[str] | None = None,
) -> Snapshot:
    if not re.fullmatch(r"\d{12}", account_id) or not regions:
        raise ValueError("An explicit 12-digit account ID and at least one region are required")
    if any(not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d", r) for r in regions):
        raise ValueError("Invalid AWS region")
    regions = list(dict.fromkeys(regions))
    home = regions[0]
    identity = gateway.call("sts", "get_caller_identity", home)
    if identity["Account"] != account_id:
        raise ValueError("Caller account does not match the explicitly authorized account")
    partition = identity["Arn"].split(":")[1]
    errors = []

    def read(service, operation, region=home, **kwargs):
        try:
            return gateway.call(service, operation, region, **kwargs)
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__)
            errors.append(f"{service}.{operation} ({region}): {code}")
            return None

    role_details = []
    policy_details = []
    marker = None
    iam_complete = True
    seen_markers = set()
    while True:
        args = {"Filter": ["Role", "LocalManagedPolicy", "AWSManagedPolicy"], "MaxItems": 100}
        if marker:
            args["Marker"] = marker
        page = read("iam", "get_account_authorization_details", **args)
        if page is None:
            iam_complete = False
            break
        role_details.extend(page.get("RoleDetailList", []))
        policy_details.extend(page.get("Policies", []))
        if not page.get("IsTruncated"):
            break
        marker = page.get("Marker")
        if not marker or marker in seen_markers:
            errors.append("iam: incomplete or repeating pagination marker")
            iam_complete = False
            break
        seen_markers.add(marker)
    policies = {}
    for policy in policy_details:
        for version in policy.get("PolicyVersionList", []):
            if version.get("IsDefaultVersion"):
                policies[policy["Arn"]] = document(version["Document"])
    roles = {}
    for detail in role_details:
        attached = [p["PolicyArn"] for p in detail.get("AttachedManagedPolicies", [])]
        boundary_arn = detail.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn")
        complete = iam_complete and all(arn in policies for arn in attached)
        boundary = None
        if boundary_arn:
            complete = complete and boundary_arn in policies
            boundary = [policies[boundary_arn]] if boundary_arn in policies else []
        if not complete:
            errors.append(f"iam: incomplete policy documents for {detail['Arn']}")
        roles[detail["Arn"]] = Role(
            arn=detail["Arn"],
            trust=document(detail["AssumeRolePolicyDocument"]),
            policies=[document(p["PolicyDocument"]) for p in detail.get("RolePolicyList", [])]
            + [policies[a] for a in attached if a in policies],
            boundary=boundary,
            policies_complete=complete,
        )
    groups = {}
    for region in regions:
        token = None
        seen_tokens = set()
        while True:
            args = {"MaxResults": 100}
            if token:
                args["NextToken"] = token
            page = read("ec2", "describe_security_groups", region, **args)
            if page is None:
                break
            for group in page.get("SecurityGroups", []):
                arn = f"arn:{partition}:ec2:{region}:{account_id}:security-group/{group['GroupId']}"
                groups[arn] = SecurityGroup(
                    arn=arn,
                    ingress=[
                        Ingress(
                            protocol=p["IpProtocol"],
                            from_port=p.get("FromPort"),
                            to_port=p.get("ToPort"),
                            cidrs=[r["CidrIp"] for r in p.get("IpRanges", [])]
                            + [r["CidrIpv6"] for r in p.get("Ipv6Ranges", [])],
                        )
                        for p in group.get("IpPermissions", [])
                    ],
                )
            token = page.get("NextToken")
            if not token:
                break
            if token in seen_tokens:
                errors.append(f"ec2: repeating pagination token in {region}")
                break
            seen_tokens.add(token)
    bucket_models = {}
    if buckets:
        account_block = read("s3control", "get_public_access_block", AccountId=account_id)
        for name in sorted(set(buckets)):
            kwargs = {"Bucket": name, "ExpectedBucketOwner": account_id}
            policy = read("s3", "get_bucket_policy_status", **kwargs)
            block = read("s3", "get_public_access_block", **kwargs)
            values = [
                b.get("PublicAccessBlockConfiguration", {}).get("RestrictPublicBuckets")
                if b
                else None
                for b in (account_block, block)
            ]
            effective = True if True in values else (False if values == [False, False] else None)
            arn = f"arn:{partition}:s3:::{name}"
            bucket_models[arn] = Bucket(
                arn=arn,
                public_policy=policy.get("PolicyStatus", {}).get("IsPublic") if policy else None,
                restrict_public_buckets=effective,
            )
    captured = datetime.now(UTC).isoformat()
    return Snapshot(
        snapshot_id=f"aws-{account_id}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S')}",
        account_id=account_id,
        source="aws",
        regions=regions,
        captured_at=captured,
        controls_complete=False,
        roles=roles,
        buckets=bucket_models,
        security_groups=groups,
        collection_errors=errors,
    )
