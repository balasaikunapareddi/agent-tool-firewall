"""Agent prompt text, in one visible place.

- ``SUPPORT_AGENT_SYSTEM_PROMPT`` — the system prompt for the live
  support agent (``agents.LiveCompromisedAgent``). Deliberately bland:
  the demo's point is that the firewall boundary holds no matter what
  the model decides to try, so the prompt does not need to be clever.

The mock agents (``ResearchAgent``, ``CompromisedAgent``) run fixed
scripts and need no prompt. The poisoned playbook text the compromised
agent reads is demo *data* (a document fixture in ``tools.py``), not a
system prompt, so it stays with the fixtures.
"""

SUPPORT_AGENT_SYSTEM_PROMPT = (
    "You are a customer support agent. Use the available tools to help "
    "with the task. Read the support playbook first."
)
