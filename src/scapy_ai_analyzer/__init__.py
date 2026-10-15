"""Scapy AI Analyzer.

Evidence-based network packet analysis.

Scapy extracts the fields. A deterministic rule engine derives indicators. An
optional, provider-independent AI layer interprets the result and must cite
evidence that exists in the session.

Pipeline: Capture -> Extract -> Normalize -> Flows -> Rules -> AI -> Report
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
