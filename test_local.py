from models import ClassifyRequest, SecretFinding
from db import init_database, get_active_features, get_active_heuristics, save_classification
from engine import extract_features
from heuristic import apply_heuristics
import json

init_database()
finding = SecretFinding(
    report_id="test-run-001",
    rule_id="aws-access-key",
    filepath="/src",
    secret="1023456",
    line_number=15,
    context='AKIAIOSFODNN7EXAMPLE'
)

request = ClassifyRequest(findings=[finding])

feat_cfg = get_active_features()
heur_cfg = get_active_heuristics()

results = []

for f in request.findings:
    # Извлечение фич
    feats = extract_features(f.secret, f.filepath, f.context, f.rule_id, feat_cfg)
    entropy = feats.get("entropy", 0.0)
    print("Фичи:")
    for k, v in feats.items():
        print(f"  {k}: {v}")

    # Применение эвристик
    score, matched, desc = apply_heuristics(feats, heur_cfg)
    print(f"\n  Score: {score}, Matched: {matched}")
    print(f" Description: {desc}")

    # Решение
    verdict = "fp" if score >= 2.0 else "review"
    save_classification(
        f.report_id, f.secret, f.filepath, f.rule_id, entropy, feats,
        score, verdict, matched, desc
    )

    results.append({
        "secret": f.secret,
        "verdict": verdict,
        "score": score,
        "description": desc,
        "features": feats
    })

print("=" * 60)
print("Результат (как от /classify):")
print(json.dumps(results, indent=2, ensure_ascii=False))