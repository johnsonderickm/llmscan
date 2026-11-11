"""
Single source of truth for the OWASP Top 10 for LLM Applications (2025).

Every other module that needs a category's name, description, or compliance
cross-references should import `TAXONOMY` / `compliance_refs` from here
rather than hardcoding its own copy. `GET /api/taxonomy` serves this to the
dashboard so category labels live in exactly one place.
"""

from __future__ import annotations

from pydantic import BaseModel


class ComplianceRefs(BaseModel):
    """Compliance framework cross-references for one OWASP LLM category.

    A fixed reference table, not a legal determination — reports label
    these rows "indicative — requires analyst review".
    """

    soc2: str
    iso27001: str
    eu_ai_act: str


class TaxonomyEntry(BaseModel):
    """One category in the OWASP LLM Top 10 (2025)."""

    id: str
    name: str
    short_label: str
    description: str
    v1_1_equivalent: list[str]
    compliance: ComplianceRefs


TAXONOMY: dict[str, TaxonomyEntry] = {
    "LLM01": TaxonomyEntry(
        id="LLM01",
        name="Prompt Injection",
        short_label="Injection",
        description=(
            "User-supplied (direct) or third-party (indirect, via retrieved "
            "documents, tool output, or other untrusted content) input "
            "alters the model's behavior or output in unintended ways."
        ),
        v1_1_equivalent=["LLM01"],
        compliance=ComplianceRefs(
            soc2="CC6.1 — Logical access security",
            iso27001="A.8.2 — Privileged access rights",
            eu_ai_act="Article 9 — Risk management system",
        ),
    ),
    "LLM02": TaxonomyEntry(
        id="LLM02",
        name="Sensitive Information Disclosure",
        short_label="Sensitive Data",
        description=(
            "The model reveals PII, credentials, proprietary algorithms, or "
            "other confidential details through its responses."
        ),
        v1_1_equivalent=["LLM06"],
        compliance=ComplianceRefs(
            soc2="CC6.7 — Data transmission and disposal",
            iso27001="A.8.11 — Data masking",
            eu_ai_act="Article 10 — Data and data governance",
        ),
    ),
    "LLM03": TaxonomyEntry(
        id="LLM03",
        name="Supply Chain",
        short_label="Supply Chain",
        description=(
            "Vulnerabilities in the model's training, deployment, or "
            "distribution pipeline — compromised third-party models, "
            "datasets, fine-tunes, LoRA adapters, or plugins."
        ),
        v1_1_equivalent=["LLM05"],
        compliance=ComplianceRefs(
            soc2="CC9.2 — Vendor and third-party risk management",
            iso27001="A.5.19 — Supplier relationships in ICT",
            eu_ai_act="Article 10 — Data and data governance",
        ),
    ),
    "LLM04": TaxonomyEntry(
        id="LLM04",
        name="Data and Model Poisoning",
        short_label="Poisoning",
        description=(
            "Training, fine-tuning, or embedding data is tampered with to "
            "introduce vulnerabilities, backdoors, or biases that degrade "
            "security, effectiveness, or ethical behavior."
        ),
        v1_1_equivalent=["LLM03"],
        compliance=ComplianceRefs(
            soc2="CC3.2 — Risk identification and analysis",
            iso27001="A.5.7 — Threat intelligence",
            eu_ai_act="Article 10 — Data and data governance",
        ),
    ),
    "LLM05": TaxonomyEntry(
        id="LLM05",
        name="Improper Output Handling",
        short_label="Output Handling",
        description=(
            "Insufficient validation, sanitization, or encoding of model "
            "output before it reaches downstream components, enabling XSS, "
            "CSRF, SSRF, privilege escalation, or remote code execution."
        ),
        v1_1_equivalent=["LLM02"],
        compliance=ComplianceRefs(
            soc2="CC7.1 — System operations monitoring",
            iso27001="A.8.28 — Secure coding",
            eu_ai_act="Article 15 — Accuracy, robustness, cybersecurity",
        ),
    ),
    "LLM06": TaxonomyEntry(
        id="LLM06",
        name="Excessive Agency",
        short_label="Agency",
        description=(
            "The model is granted excessive functionality, permissions, or "
            "autonomy, letting it take damaging actions in response to "
            "unexpected or ambiguous outputs."
        ),
        v1_1_equivalent=["LLM08"],
        compliance=ComplianceRefs(
            soc2="CC6.3 — Role-based access restriction",
            iso27001="A.8.2 — Privileged access rights",
            eu_ai_act="Article 14 — Human oversight",
        ),
    ),
    "LLM07": TaxonomyEntry(
        id="LLM07",
        name="System Prompt Leakage",
        short_label="Sys Prompt Leak",
        description=(
            "The system prompt — which may contain sensitive configuration, "
            "credentials, or business logic — can be extracted by an "
            "attacker through adversarial querying."
        ),
        v1_1_equivalent=[],
        compliance=ComplianceRefs(
            soc2="CC6.1 — Logical access security",
            iso27001="A.8.11 — Data masking",
            eu_ai_act="Article 10 — Data and data governance",
        ),
    ),
    "LLM08": TaxonomyEntry(
        id="LLM08",
        name="Vector and Embedding Weaknesses",
        short_label="Vector/Embedding",
        description=(
            "Weaknesses in how vectors and embeddings are generated, "
            "stored, or retrieved in RAG systems, including cross-tenant "
            "data leakage and poisoned retrieval content."
        ),
        v1_1_equivalent=[],
        compliance=ComplianceRefs(
            soc2="CC6.7 — Data transmission and disposal",
            iso27001="A.8.11 — Data masking",
            eu_ai_act="Article 10 — Data and data governance",
        ),
    ),
    "LLM09": TaxonomyEntry(
        id="LLM09",
        name="Misinformation",
        short_label="Misinformation",
        description=(
            "The model produces false or misleading information presented "
            "as fact, including hallucinated APIs, packages, citations, or "
            "confirmation of a user's false premise."
        ),
        v1_1_equivalent=["LLM09"],
        compliance=ComplianceRefs(
            soc2="CC3.2 — Risk identification and analysis",
            iso27001="A.5.7 — Threat intelligence",
            eu_ai_act="Article 14 — Human oversight",
        ),
    ),
    "LLM10": TaxonomyEntry(
        id="LLM10",
        name="Unbounded Consumption",
        short_label="Unbounded Consumption",
        description=(
            "The model performs inference operations without limits, "
            "enabling denial of service, economic drain, or model "
            "extraction via excessive or crafted queries."
        ),
        v1_1_equivalent=["LLM04"],
        compliance=ComplianceRefs(
            soc2="A1.1 — Availability capacity management",
            iso27001="A.8.14 — Redundancy of processing facilities",
            eu_ai_act="Article 15 — Accuracy, robustness, cybersecurity",
        ),
    ),
}

ALL_OWASP_IDS: list[str] = [f"LLM{i:02d}" for i in range(1, 11)]


def get_taxonomy_entry(owasp_id: str) -> TaxonomyEntry | None:
    """Return the taxonomy entry for *owasp_id*, or None if unrecognised."""
    return TAXONOMY.get(owasp_id)


def compliance_refs(owasp_id: str) -> ComplianceRefs:
    """Return compliance framework references for an OWASP LLM category.

    Falls back to placeholder dashes for an unrecognised id rather than
    raising, so a plugin reporting a stale/wrong id degrades to a visible
    "—" instead of crashing report generation.
    """
    entry = TAXONOMY.get(owasp_id)
    if entry is not None:
        return entry.compliance
    return ComplianceRefs(soc2="—", iso27001="—", eu_ai_act="—")
