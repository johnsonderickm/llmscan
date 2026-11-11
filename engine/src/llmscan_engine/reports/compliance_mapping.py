"""Backward-compatible shim over `core.taxonomy`.

The OWASP category → compliance framework cross-reference now lives in
`core/taxonomy.py` (the single source of truth for category metadata).
This module re-exports the same names so `reports/generator.py` and its
Jinja2 templates don't need to change their imports.
"""

from llmscan_engine.core.taxonomy import ComplianceRefs, compliance_refs

__all__ = ["ComplianceRefs", "compliance_refs"]
