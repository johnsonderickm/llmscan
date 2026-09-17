"""Static OWASP LLM Top 10 → compliance framework cross-reference.

Used by the CXO report to show which control frameworks a finding puts
at risk. This is a fixed reference table, not a legal determination.
"""

from typing import TypedDict


class ComplianceRefs(TypedDict):
    soc2: str
    iso27001: str
    eu_ai_act: str


COMPLIANCE_MAPPING: dict[str, ComplianceRefs] = {
    "LLM01": {
        "soc2": "CC6.1 — Logical access security",
        "iso27001": "A.8.2 — Privileged access rights",
        "eu_ai_act": "Article 9 — Risk management system",
    },
    "LLM02": {
        "soc2": "CC6.7 — Data transmission and disposal",
        "iso27001": "A.8.11 — Data masking",
        "eu_ai_act": "Article 10 — Data and data governance",
    },
    "LLM03": {
        "soc2": "CC7.1 — System operations monitoring",
        "iso27001": "A.8.28 — Secure coding",
        "eu_ai_act": "Article 15 — Accuracy, robustness, cybersecurity",
    },
    "LLM04": {
        "soc2": "A1.1 — Availability capacity management",
        "iso27001": "A.8.14 — Redundancy of processing facilities",
        "eu_ai_act": "Article 15 — Accuracy, robustness, cybersecurity",
    },
    "LLM05": {
        "soc2": "CC9.2 — Vendor and third-party risk management",
        "iso27001": "A.5.19 — Supplier relationships in ICT",
        "eu_ai_act": "Article 10 — Data and data governance",
    },
    "LLM06": {
        "soc2": "CC6.3 — Role-based access restriction",
        "iso27001": "A.8.2 — Privileged access rights",
        "eu_ai_act": "Article 14 — Human oversight",
    },
    "LLM07": {
        "soc2": "CC6.1 — Logical access security",
        "iso27001": "A.8.11 — Data masking",
        "eu_ai_act": "Article 10 — Data and data governance",
    },
    "LLM08": {
        "soc2": "CC3.2 — Risk identification and analysis",
        "iso27001": "A.5.7 — Threat intelligence",
        "eu_ai_act": "Article 14 — Human oversight",
    },
    "LLM09": {
        "soc2": "CC6.7 — Data transmission and disposal",
        "iso27001": "A.8.12 — Data leakage prevention",
        "eu_ai_act": "Article 10 — Data and data governance",
    },
    "LLM10": {
        "soc2": "CC7.1 — System operations monitoring",
        "iso27001": "A.8.28 — Secure coding",
        "eu_ai_act": "Article 15 — Accuracy, robustness, cybersecurity",
    },
}


def compliance_refs(owasp_id: str) -> ComplianceRefs:
    """Return compliance framework references for an OWASP LLM category."""
    return COMPLIANCE_MAPPING.get(
        owasp_id,
        {"soc2": "—", "iso27001": "—", "eu_ai_act": "—"},
    )
