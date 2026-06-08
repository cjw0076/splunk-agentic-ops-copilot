"""Splunk Agentic Ops — Incident Copilot (synthetic-data demo).

An agentic incident-investigation loop driven by REAL SPL-like searches over
synthetic Splunk-style events. Stdlib-only. No network. No secrets.

The SPL strings the agent runs are the same strings you would paste into a real
Splunk search bar; only the search backend swaps (see README "live-Splunk
upgrade path").
"""

__version__ = "0.1.0"
