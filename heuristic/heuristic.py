from typing import Dict, Any, List, Tuple


def apply_heuristics(
    features: Dict[str, Any],
    heuristic_configs: List[Dict[str, Any]]
) -> Tuple[float, List[str], str]:
    score = 0.0
    matched = []
    reasons = []

    OP_MAP = {
        "<": lambda a, b: a < b,
        "<=": lambda a, b: a <= b,
        ">": lambda a, b: a > b,
        ">=": lambda a, b: a >= b,
        "==": lambda a, b: a == b,
        "!=": lambda a, b: a != b,
    }

    for h in heuristic_configs:
        cond = h["condition"]
        feat = features.get(cond["feature"])
        if feat is None:
            continue
        op = cond["operator"]
        val = cond["value"]
        if op in OP_MAP and OP_MAP[op](feat, val):
            score += h["weight"]
            matched.append(h["name"])
            reasons.append(h["description"])

    desc = "FP: " + "; ".join(reasons) if reasons else "Сложный случай"
    return score, matched, desc