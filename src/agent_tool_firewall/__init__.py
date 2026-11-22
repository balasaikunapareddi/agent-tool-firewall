"""agent-tool-firewall: a defensive permission boundary between AI agents
and their tools — scoped capabilities, sandboxed execution, credential
isolation, human approval gates, and a complete audit trail."""

from .audit import AuditLog
from .firewall import CallResult, DirectRunner, ToolFirewall
from .policy import Policy, PolicyEvaluator, Verdict
from .sandbox import Sandbox
from .tools import MockWorld, ToolRegistry, build_mock_registry
from .vault import Vault

__version__ = "0.1.0"

__all__ = [
    "AuditLog",
    "CallResult",
    "DirectRunner",
    "MockWorld",
    "Policy",
    "PolicyEvaluator",
    "Sandbox",
    "ToolFirewall",
    "ToolRegistry",
    "Vault",
    "Verdict",
    "build_mock_registry",
]
