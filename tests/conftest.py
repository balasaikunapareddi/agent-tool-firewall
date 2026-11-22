import pytest

from agent_tool_firewall.audit import AuditLog
from agent_tool_firewall.demo import DEFAULT_POLICY_PATH
from agent_tool_firewall.firewall import DirectRunner, ToolFirewall
from agent_tool_firewall.policy import Policy
from agent_tool_firewall.sandbox import Sandbox
from agent_tool_firewall.tools import (
    FAKE_DB_PASSWORD,
    FAKE_PAYMENTS_KEY,
    MockWorld,
    build_mock_registry,
    seed_workspace,
)
from agent_tool_firewall.vault import Vault


@pytest.fixture()
def policy() -> Policy:
    return Policy.from_yaml(DEFAULT_POLICY_PATH)


@pytest.fixture()
def world() -> MockWorld:
    return MockWorld()


@pytest.fixture()
def vault() -> Vault:
    return Vault({"payments_api_key": FAKE_PAYMENTS_KEY, "db_password": FAKE_DB_PASSWORD})


@pytest.fixture()
def sandbox(tmp_path) -> Sandbox:
    seed_workspace(tmp_path)
    return Sandbox(root=tmp_path, timeout_seconds=2.0, max_output_chars=4000)


@pytest.fixture()
def audit(tmp_path, vault) -> AuditLog:
    return AuditLog(path=tmp_path / "audit.jsonl", redactor=vault.redact)


@pytest.fixture()
def firewall(policy, world, vault, sandbox, audit) -> ToolFirewall:
    return ToolFirewall(policy, build_mock_registry(world), vault, audit, sandbox)


@pytest.fixture()
def direct(world, vault, sandbox) -> DirectRunner:
    return DirectRunner(build_mock_registry(world), sandbox, vault)
