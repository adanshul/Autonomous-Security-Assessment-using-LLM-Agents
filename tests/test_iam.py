import pytest

from aegis_cloud.iam import Decision, match, policy_decision, role_decision, unrestricted_admin
from aegis_cloud.models import Role


def policy(effect="Allow", action="*", resource="*", **extra):
    return {"Statement": [{"Effect": effect, "Action": action, "Resource": resource, **extra}]}


@pytest.mark.parametrize(
    "policies,expected",
    [
        ([policy()], Decision.ALLOW),
        ([], Decision.DENY),
        ([policy(), policy("Deny")], Decision.DENY),
        ([policy("Deny"), policy()], Decision.DENY),
        ([policy(action="s3:*")], Decision.DENY),
        ([policy(resource="arn:aws:iam::111111111111:role/other")], Decision.DENY),
        ([policy(Condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}})], Decision.UNKNOWN),
        ([policy(), policy("Deny", Condition={"Bool": {"x": "true"}})], Decision.UNKNOWN),
        ([policy(), {"Statement": [{"Effect": "Deny", "NotAction": "s3:*"}]}], Decision.UNKNOWN),
        ([policy(resource="${aws:PrincipalArn}")], Decision.UNKNOWN),
        ([policy(action=["sTs:assumeRole"])], Decision.ALLOW),
        ([policy(action=123)], Decision.UNKNOWN),
        ([{"Statement": "invalid"}], Decision.UNKNOWN),
        ([policy(effect="invalid")], Decision.UNKNOWN),
    ],
)
def test_three_valued_decisions(policies, expected):
    assert (
        policy_decision(policies, "sts:AssumeRole", "arn:aws:iam::111111111111:role/demo")
        == expected
    )


@pytest.mark.parametrize(
    "boundary,expected",
    [
        (None, Decision.ALLOW),
        ([], Decision.DENY),
        ([policy(action="s3:*")], Decision.DENY),
        ([policy()], Decision.ALLOW),
        ([policy(Condition={"Bool": {"x": "true"}})], Decision.UNKNOWN),
    ],
)
def test_boundary_intersection(boundary, expected):
    role = Role(arn="role", policies=[policy()], boundary=boundary)
    assert role_decision(role, "sts:AssumeRole", "target") == expected


def test_incomplete_documents_never_allow():
    role = Role(arn="role", policies=[policy()], policies_complete=False)
    assert role_decision(role, "sts:AssumeRole", "target") == Decision.UNKNOWN
    assert not unrestricted_admin(role)


def test_admin_requires_universal_effective_grant():
    assert unrestricted_admin(Role(arn="a", policies=[policy()]))
    assert not unrestricted_admin(Role(arn="a", policies=[policy(resource="bucket/*")]))
    assert not unrestricted_admin(Role(arn="a", policies=[policy(), policy("Deny", "iam:*")]))
    assert not unrestricted_admin(Role(arn="a", policies=[policy()], boundary=[]))
    assert unrestricted_admin(Role(arn="a", policies=[policy()], boundary=[policy()]))
    assert not unrestricted_admin(Role(arn="a", policies=[policy(), {}]))
    assert not unrestricted_admin(Role(arn="a", policies=[policy(), {"Statement": [1]}]))
    assert policy_decision([policy(), {}], "sts:AssumeRole", "role") == Decision.UNKNOWN
    assert (
        policy_decision([policy(), {"Statement": [1]}], "sts:AssumeRole", "role")
        == Decision.UNKNOWN
    )


def test_iam_wildcards_do_not_use_shell_character_classes():
    assert not match("role/[ab]", "role/a")
    assert match("role/[ab]", "role/[ab]")
    assert match("role/?", "role/a")
    assert not match("role/A", "role/a")


def test_trust_requires_aws_principal_match():
    doc = policy(action="sts:AssumeRole", Principal={"AWS": "arn:aws:iam::111111111111:root"})
    assert policy_decision([doc], "sts:AssumeRole", "role", principal="another") == Decision.UNKNOWN
    doc["Statement"][0]["Principal"] = {"Service": "ec2.amazonaws.com"}
    assert policy_decision([doc], "sts:AssumeRole", "role", principal="another") == Decision.DENY
