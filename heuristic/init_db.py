import sqlite3
import json
from db import init_database  

DB_PATH = "fp_agent.db"

FEATURES = [
    {"name": "entropy", "type": "builtin", "config": {"function": "shannon_entropy", "target": "secret"}},
    {"name": "length", "type": "builtin", "config": {"function": "len", "target": "secret"}},
    {"name": "has_placeholder", "type": "keyword", "config": {
        "target": "secret", "keywords": ["test", "fake", "example", "xxx", "dummy", "placeholder"], "case_sensitive": False
    }},
    {"name": "in_test_path", "type": "keyword", "config": {
        "target": "filepath",
        "keywords": ["/test/", "\\test\\", "/mock/", "\\mock\\", "/example/", "\\example\\", "/examples/", "\\examples\\"],
        "match_substring": True
    }},
    {"name": "has_dev_comment", "type": "keyword", "config": {
        "target": "context", "keywords": ["TODO", "FIXME", "debug", "not real"], "case_sensitive": False
    }},
    {"name": "is_url", "type": "regex", "config": {"pattern": r"https?://[\w\./\-]+"}},
]

HEURISTICS = [
    {"name": "low_entropy", "description": "низкая энтропия (< 3.0)", "condition": {"feature": "entropy", "operator": "<", "value": 3.0}, "weight": 1.2},
    {"name": "placeholder_word", "description": "секрет содержит 'test'/'fake'", "condition": {"feature": "has_placeholder", "operator": "==", "value": True}, "weight": 1.5},
    {"name": "test_file", "description": "файл в test/mock/examples", "condition": {"feature": "in_test_path", "operator": "==", "value": True}, "weight": 1.3},
    {"name": "dev_comment", "description": "контекст с TODO/FIXME", "condition": {"feature": "has_dev_comment", "operator": "==", "value": True}, "weight": 1.0},
    {"name": "url_instead_of_secret", "description": "значение — URL", "condition": {"feature": "is_url", "operator": "==", "value": True}, "weight": 0.8},
]

def seed_db():
    init_database()

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    for f in FEATURES:
        cur.execute(
            "INSERT OR IGNORE INTO features (name, type, config) VALUES (?, ?, ?)",
            (f["name"], f["type"], json.dumps(f["config"]))
        )

    for h in HEURISTICS:
        cur.execute(
            "INSERT OR IGNORE INTO heuristics (name, description, condition, weight) VALUES (?, ?, ?, ?)",
            (h["name"], h["description"], json.dumps(h["condition"]), h["weight"])
        )

    conn.commit()
    conn.close()
    print("success") #ради отладки тут

if __name__ == "__main__":
    seed_db()