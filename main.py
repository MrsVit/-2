from fastapi import FastAPI, HTTPException
from typing import List
import json

from db import init_database, get_active_features, get_active_heuristics, save_classification
from engine import extract_features
from  heuristic import apply_heuristics
# from llm import llm_judge  # раскомментируем к мл-ке или подвяжем в другим способом

from models import ClassifyRequest, ClassificationResult

app = FastAPI(
    title="MWS AI: FP Classifier",
    description="Автоматическая фильтрация false-positive при поиске секретов",
    version="1.0"
)

@app.on_event("startup")
def startup():
    init_database()

@app.get("/")
def index():
    return {"status": "ok", "docs": "/docs"}

@app.post("/classify", response_model=List[ClassificationResult])
def classify(req: ClassifyRequest):
    if not req.findings:
        raise HTTPException(400, "findings is empty")

    feat_cfg = get_active_features()
    heur_cfg = get_active_heuristics()
    results = []

    for f in req.findings:
        feats = extract_features(f.secret, f.filepath, f.context, f.rule_id, feat_cfg)
        entropy = feats.get("entropy", 0.0)
        score, matched, desc = apply_heuristics(feats, heur_cfg)
        verdict = "fp" if score >= 2.0 else "review"
        llm_used, llm_reason = False, None

        save_classification(
            f.report_id, f.secret, f.filepath, f.rule_id, entropy, feats,
            score, verdict, matched, desc, llm_used, llm_reason
        )

        results.append(ClassificationResult(
            secret=f.secret,
            entropy=round(entropy, 2),
            features=feats,
            score=round(score, 2),
            verdict=verdict,
            matched_heuristics=matched,
            description=desc,
            llm_used=llm_used,
            llm_reason=llm_reason
        ))

    return results