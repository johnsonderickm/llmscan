from typing import List

from fastapi import APIRouter

from llmscan_engine.core.taxonomy import TAXONOMY, TaxonomyEntry

router = APIRouter(tags=["taxonomy"])


@router.get("/taxonomy", response_model=List[TaxonomyEntry])
async def list_taxonomy() -> List[TaxonomyEntry]:
    """Return the OWASP LLM Top 10 (2025) category definitions, LLM01-LLM10 in order."""
    return [TAXONOMY[f"LLM{i:02d}"] for i in range(1, 11)]
