import json

import pytest

from aegis_cloud.cli import lab_path
from aegis_cloud.models import Snapshot


@pytest.fixture(autouse=True)
def isolate_aws(monkeypatch, tmp_path):
    # Never read local AWS profiles, write an operator TLS log, or make real SDK requests.
    import botocore.httpsession

    monkeypatch.delenv("SSLKEYLOGFILE", raising=False)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_PROFILE", raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "no-aws-config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "no-aws-credentials"))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")

    def reject_network(*args, **kwargs):
        pytest.fail("A test attempted a real AWS HTTP request")

    monkeypatch.setattr(botocore.httpsession.URLLib3Session, "send", reject_network)


@pytest.fixture
def exposed():
    return Snapshot.model_validate_json(lab_path("exposed.json").read_text())


@pytest.fixture
def raw_exposed():
    return json.loads(lab_path("exposed.json").read_text())
