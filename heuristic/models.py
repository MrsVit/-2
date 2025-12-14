from pydantic import BaseModel
from typing import List, Dict, Optional, Any


class SecretFinding(BaseModel):
    report_id: str
    rule_id: str
    secret: str
    filepath: str
    line_number: int
    context: str = ""
    raw: Dict[str, Any] = {}


class ClassificationResult(BaseModel):
    secret: str
    entropy: float
    features: Dict[str, Any]
    score: float
    verdict: str  # "fp", "review"
    matched_heuristics: List[str]
    description: str
    llm_used: bool = False
    llm_reason: Optional[str] = None
    

class ClassifyRequest(BaseModel):
    findings: List[SecretFinding]