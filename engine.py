import math
import re
from collections import Counter
from typing import Dict, Any, List

#оценка по теореме Шеннона
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    counts = Counter(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


BUILTIN_FUNCS = {
    "shannon_entropy": shannon_entropy,
    "len": len,
    "unique_chars": lambda s: len(set(s)),
}


def _safe_eval(expr: str, context: Dict[str, Any]) -> Any:
    allowed = {
        "__builtins__": {},
        "len": len, "str": str, "int": int, "float": float,
        "abs": abs, "min": min, "max": max, "sum": sum
    }
    allowed.update(context)
    code = compile(expr, "<string>", "eval")
    for name in code.co_names:
        if name not in allowed:
            raise ValueError(f"Запрещённое имя: {name}")
    return eval(code, {"__builtins__": {}}, allowed)


def extract_features(
    secret: str,
    filepath: str,
    context: str,
    rule_id: str,
    feature_configs: List[Dict[str, Any]]
) -> Dict[str, Any]:
    targets = {
        "secret": secret,
        "filepath": filepath,
        "context": context,
        "rule_id": rule_id,
    }

    result = {}

    for cfg in feature_configs:
        name = cfg["name"]
        ftype = cfg["type"]
        config = cfg["config"]

        try:
            if ftype == "builtin":
                func = BUILTIN_FUNCS[config["function"]]
                val = targets[config["target"]]
                result[name] = func(val)

            elif ftype == "keyword":
                target = targets[config["target"]]
                kws = config["keywords"]
                case = config.get("case_sensitive", False)
                if not case:
                    target = target.lower()
                    kws = [kw.lower() for kw in kws]
                match_sub = config.get("match_substring", True)
                if match_sub:
                    result[name] = any(kw in target for kw in kws)
                else:
                    result[name] = target in kws

            elif ftype == "regex":
                target = targets.get("secret", "")
                result[name] = bool(re.search(config["pattern"], target))

            elif ftype == "custom_expr":
                expr = config["expr"]
                target_name = config.get("target", "secret")
                result[name] = _safe_eval(expr, {target_name: targets[target_name]})

            else:
                result[name] = None

        except Exception:
            result[name] = None

    return result