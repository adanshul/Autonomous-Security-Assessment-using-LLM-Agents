"""Author the bundled synthetic regression cases and independent, explicit labels.

This file does not import the assessment engine. Lab labels are illustrative, not empirical data.
"""

import copy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "src" / "aegis_cloud" / "labs"
ACCOUNT = "111111111111"


def arn(name):
    return f"arn:aws:iam::{ACCOUNT}:role/{name}"


def policy(action, resource="*", **extra):
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": action, "Resource": resource, **extra}],
    }


def trust(principal):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": principal}}
        ],
    }


def role(name, policies, trust_doc=None):
    return {"arn": arn(name), "policies": policies, "trust": trust_doc or {"Statement": []}}


def snapshot(name):
    return {
        "schema_version": 1,
        "snapshot_id": name,
        "account_id": ACCOUNT,
        "source": "synthetic",
        "regions": ["us-east-1"],
        "controls_complete": True,
        "roles": {},
        "buckets": {},
        "security_groups": {},
        "collection_errors": [],
    }


def chain(name):
    result = snapshot(name)
    result["roles"] = {
        "ci": role("ci", [policy("sts:AssumeRole", arn("broker"))]),
        "broker": role("broker", [policy("sts:AssumeRole", arn("admin"))], trust(arn("ci"))),
        "admin": role("admin", [policy("*")], trust(arn("broker"))),
    }
    return result


def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    labels = {
        "schema_version": 1,
        "name": "aegis-synthetic-v1",
        "dataset_kind": "synthetic",
        "cases": {},
    }

    def save(data, expected):
        name = data["snapshot_id"]
        (ROOT / f"{name}.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        labels["cases"][name] = {"snapshot_file": f"{name}.json", "expected_keys": expected}

    exposed = chain("exposed")
    exposed["roles"]["public-role"] = role("public-role", [], trust("*"))
    exposed["buckets"]["research-data"] = {
        "arn": "arn:aws:s3:::aegis-synthetic-research-data",
        "public_policy": True,
        "restrict_public_buckets": False,
    }
    exposed["security_groups"]["admin-sg"] = {
        "arn": f"arn:aws:ec2:us-east-1:{ACCOUNT}:security-group/sg-synthetic",
        "ingress": [{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidrs": ["0.0.0.0/0"]}],
    }
    save(
        exposed,
        [
            "IAM_ADMIN:admin",
            "IAM_PUBLIC_TRUST:public-role",
            "IAM_ASSUME_ADMIN_PATH:ci->admin",
            "IAM_ASSUME_ADMIN_PATH:broker->admin",
            "S3_PUBLIC_POLICY:research-data",
            "EC2_OPEN_ADMIN:admin-sg",
        ],
    )
    hardened = copy.deepcopy(exposed)
    hardened["snapshot_id"] = "hardened"
    hardened["roles"]["admin"]["policies"] = [policy("s3:GetObject", "arn:aws:s3:::approved/*")]
    hardened["roles"]["public-role"]["trust"] = trust(arn("ci"))
    hardened["buckets"]["research-data"]["restrict_public_buckets"] = True
    hardened["security_groups"]["admin-sg"]["ingress"][0]["cidrs"] = ["10.0.0.0/24"]
    save(hardened, [])
    denied = chain("explicit-deny")
    denied["roles"]["ci"]["policies"].append(
        {"Statement": [{"Effect": "Deny", "Action": "sts:AssumeRole", "Resource": "*"}]}
    )
    save(denied, ["IAM_ADMIN:admin", "IAM_ASSUME_ADMIN_PATH:broker->admin"])
    boundary = chain("boundary")
    boundary["roles"]["ci"]["boundary"] = [policy("s3:GetObject")]
    save(boundary, ["IAM_ADMIN:admin", "IAM_ASSUME_ADMIN_PATH:broker->admin"])
    conditional = chain("conditional-trust")
    conditional["roles"]["broker"]["trust"]["Statement"][0]["Condition"] = {
        "StringEquals": {"sts:ExternalId": "synthetic-context-not-provided"}
    }
    save(conditional, ["IAM_ADMIN:admin", "IAM_ASSUME_ADMIN_PATH:broker->admin"])
    cycle = chain("cycle")
    cycle["roles"]["broker"]["policies"].append(policy("sts:AssumeRole", arn("ci")))
    cycle["roles"]["ci"]["trust"] = trust(arn("broker"))
    save(
        cycle,
        [
            "IAM_ADMIN:admin",
            "IAM_ASSUME_ADMIN_PATH:ci->admin",
            "IAM_ASSUME_ADMIN_PATH:broker->admin",
        ],
    )
    blocked = snapshot("blocked-public-policy")
    blocked["buckets"] = copy.deepcopy(hardened["buckets"])
    save(blocked, [])
    unknown = snapshot("unknown-public-block")
    unknown["buckets"] = copy.deepcopy(exposed["buckets"])
    unknown["buckets"]["research-data"]["restrict_public_buckets"] = None
    save(unknown, ["S3_PUBLIC_POLICY:research-data"])
    service = snapshot("service-trust")
    service["roles"]["service"] = role(
        "service",
        [],
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                }
            ]
        },
    )
    save(service, [])
    ipv6 = snapshot("ipv6-admin")
    ipv6["security_groups"] = copy.deepcopy(exposed["security_groups"])
    ipv6["security_groups"]["admin-sg"]["ingress"] = [{"protocol": "-1", "cidrs": ["::/0"]}]
    save(ipv6, ["EC2_OPEN_ADMIN:admin-sg"])
    denied_trust = snapshot("denied-trust")
    trust_doc = trust("*")
    trust_doc["Statement"].append({"Effect": "Deny", "Action": "sts:AssumeRole", "Principal": "*"})
    denied_trust["roles"]["locked"] = role("locked", [], trust_doc)
    save(denied_trust, [])
    scoped = snapshot("scoped-wildcard")
    scoped["roles"]["scoped"] = role("scoped", [policy("*", "arn:aws:s3:::one-bucket/*")])
    save(scoped, [])
    (ROOT / "labels.json").write_text(json.dumps(labels, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
