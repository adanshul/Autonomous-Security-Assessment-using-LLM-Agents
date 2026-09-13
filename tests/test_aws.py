import json
from unittest.mock import MagicMock
from urllib.parse import quote

import boto3
import pytest
from botocore.stub import Stubber

from aegis_cloud.aws import ReadOnlyGateway, collect, document

ACCOUNT = "111111111111"
REGION = "us-east-1"


@pytest.fixture
def gateway():
    # Deliberately fake credentials: tests must never use the operator's credential chain.
    session = boto3.Session(
        aws_access_key_id="testing", aws_secret_access_key="testing", region_name=REGION
    )
    result = ReadOnlyGateway(session)
    for service in ("sts", "iam", "ec2", "s3", "s3control"):
        result.clients[(service, REGION)] = session.client(service)
    return result


def caller(stub, account=ACCOUNT):
    stub.add_response(
        "get_caller_identity",
        {"Account": account, "UserId": "testing", "Arn": f"arn:aws:iam::{account}:user/test"},
    )


def test_account_mismatch_prevents_inventory(gateway):
    with Stubber(gateway.clients[("sts", REGION)]) as stub:
        caller(stub, "222222222222")
        with pytest.raises(ValueError, match="account"):
            collect(gateway, account_id=ACCOUNT, regions=[REGION])
        assert gateway.calls == 1


def test_allowlist_and_budget_precede_client_creation():
    fake = MagicMock()
    gateway = ReadOnlyGateway(fake, max_calls=1)
    for service, operation in [("iam", "create_role"), ("secretsmanager", "get_secret_value")]:
        with pytest.raises(ValueError, match="allowlist"):
            gateway.call(service, operation, REGION)
    fake.client.assert_not_called()
    gateway.call("sts", "get_caller_identity", REGION)
    with pytest.raises(ValueError, match="budget"):
        gateway.call("sts", "get_caller_identity", REGION)
    assert fake.client.call_count == 1
    with pytest.raises(ValueError):
        ReadOnlyGateway(fake, 0)


def test_collect_pages_s3_effective_block_and_regions(gateway):
    with (
        Stubber(gateway.clients[("sts", REGION)]) as sts,
        Stubber(gateway.clients[("iam", REGION)]) as iam,
        Stubber(gateway.clients[("ec2", REGION)]) as ec2,
        Stubber(gateway.clients[("s3", REGION)]) as s3,
        Stubber(gateway.clients[("s3control", REGION)]) as control,
    ):
        caller(sts)
        iam.add_response(
            "get_account_authorization_details", {"IsTruncated": True, "Marker": "page2"}
        )
        iam.add_response(
            "get_account_authorization_details",
            {"IsTruncated": False},
            {
                "Filter": ["Role", "LocalManagedPolicy", "AWSManagedPolicy"],
                "MaxItems": 100,
                "Marker": "page2",
            },
        )
        ec2.add_response(
            "describe_security_groups",
            {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-synthetic",
                        "IpPermissions": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 22,
                                "ToPort": 22,
                                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                            }
                        ],
                    }
                ],
                "NextToken": "next",
            },
        )
        ec2.add_response(
            "describe_security_groups",
            {"SecurityGroups": []},
            {"MaxResults": 100, "NextToken": "next"},
        )
        control.add_response(
            "get_public_access_block",
            {
                "PublicAccessBlockConfiguration": {
                    "RestrictPublicBuckets": True,
                }
            },
            {"AccountId": ACCOUNT},
        )
        s3.add_response(
            "get_bucket_policy_status",
            {"PolicyStatus": {"IsPublic": True}},
            {"Bucket": "approved", "ExpectedBucketOwner": ACCOUNT},
        )
        s3.add_response(
            "get_public_access_block",
            {
                "PublicAccessBlockConfiguration": {
                    "RestrictPublicBuckets": False,
                }
            },
            {"Bucket": "approved", "ExpectedBucketOwner": ACCOUNT},
        )
        result = collect(
            gateway, account_id=ACCOUNT, regions=[REGION, REGION], buckets=["approved"]
        )
        assert len(result.security_groups) == 1
        assert result.buckets["arn:aws:s3:::approved"].restrict_public_buckets is True
        assert result.source == "aws" and not result.controls_complete
        assert not result.collection_errors
        assert gateway.calls == 8
        for stub in (sts, iam, ec2, s3, control):
            stub.assert_no_pending_responses()


def test_access_denied_is_unknown_not_clean(gateway):
    with (
        Stubber(gateway.clients[("sts", REGION)]) as sts,
        Stubber(gateway.clients[("iam", REGION)]) as iam,
        Stubber(gateway.clients[("ec2", REGION)]) as ec2,
        Stubber(gateway.clients[("s3", REGION)]) as s3,
        Stubber(gateway.clients[("s3control", REGION)]) as control,
    ):
        caller(sts)
        iam.add_client_error("get_account_authorization_details", "AccessDenied")
        ec2.add_client_error("describe_security_groups", "UnauthorizedOperation")
        control.add_client_error("get_public_access_block", "AccessDenied")
        s3.add_response("get_bucket_policy_status", {"PolicyStatus": {"IsPublic": True}})
        s3.add_client_error("get_public_access_block", "AccessDenied")
        result = collect(gateway, account_id=ACCOUNT, regions=[REGION], buckets=["approved"])
        assert len(result.collection_errors) == 4
        assert result.buckets["arn:aws:s3:::approved"].restrict_public_buckets is None


def test_invalid_scope_rejected_before_network(gateway):
    for account, regions in [("*", [REGION]), (ACCOUNT, []), (ACCOUNT, ["bad.region"])]:
        with pytest.raises(ValueError):
            collect(gateway, account_id=account, regions=regions)
    assert gateway.calls == 0


def test_url_encoded_policy_document():
    raw = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    assert document(raw) == raw
    assert document(quote(json.dumps(raw))) == raw


def test_policy_inventory_and_boundary_resolution():
    class FakeGateway:
        def call(self, service, operation, region, **kwargs):
            if service == "sts":
                return {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/test"}
            if service == "ec2":
                return {}
            return {
                "RoleDetailList": [
                    {
                        "Arn": "role-a",
                        "AssumeRolePolicyDocument": {"Statement": []},
                        "RolePolicyList": [{"PolicyDocument": {"Statement": []}}],
                        "AttachedManagedPolicies": [{"PolicyArn": "policy-a"}],
                        "PermissionsBoundary": {"PermissionsBoundaryArn": "boundary-a"},
                    },
                    {
                        "Arn": "role-missing",
                        "AssumeRolePolicyDocument": {"Statement": []},
                        "AttachedManagedPolicies": [{"PolicyArn": "missing"}],
                        "PermissionsBoundary": {"PermissionsBoundaryArn": "missing"},
                    },
                ],
                "Policies": [
                    {
                        "Arn": name,
                        "PolicyVersionList": [
                            {"IsDefaultVersion": True, "Document": {"Statement": []}}
                        ],
                    }
                    for name in ("policy-a", "boundary-a")
                ],
            }

    result = collect(FakeGateway(), account_id=ACCOUNT, regions=[REGION])
    assert result.roles["role-a"].policies_complete
    assert len(result.roles["role-a"].policies) == 2
    assert result.roles["role-a"].boundary == [{"Statement": []}]
    assert not result.roles["role-missing"].policies_complete
    assert result.roles["role-missing"].boundary == []


def test_repeating_pagination_stops():
    class Repeating:
        def call(self, service, operation, region, **kwargs):
            if service == "sts":
                return {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/test"}
            if service == "iam":
                return {"IsTruncated": True, "Marker": "repeat"}
            return {"NextToken": "repeat"}

    result = collect(Repeating(), account_id=ACCOUNT, regions=[REGION])
    assert len(result.collection_errors) == 2
