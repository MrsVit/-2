#для динамического хранения ключей/фич
import sqlite3
from pathlib import Path
import json 
from typing import List, Dict, Any

DB_PATH = Path("fp_agent.db")


def init_database():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS features (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        description TEXT,
        type TEXT NOT NULL CHECK(type IN ('builtin','keyword','regex','custom_expr')),
        config TEXT NOT NULL,  -- JSON
        enabled BOOLEAN DEFAULT TRUE
    );
    """)

    # Таблица эвристик
    cur.execute("""
    CREATE TABLE IF NOT EXISTS heuristics (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        condition TEXT NOT NULL,  -- JSON: {"feature": "...", "operator": "...", "value": ...}
        weight REAL DEFAULT 1.0,
        enabled BOOLEAN DEFAULT TRUE
    );
    """)

    # резы
    cur.execute("""
    CREATE TABLE IF NOT EXISTS classifications (
        id INTEGER PRIMARY KEY,
        report_id TEXT,
        secret TEXT NOT NULL,
        filepath TEXT,
        rule_id TEXT,
        entropy REAL,
        features_json TEXT,
        score REAL,
        verdict TEXT CHECK(verdict IN ('fp','review')),
        matched_heuristics TEXT,  -- JSON list
        description TEXT,
        llm_used BOOLEAN DEFAULT FALSE,
        llm_reason TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)

    conn.commit()
    conn.close()


def get_active_features() -> List[Dict[str, Any]]:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT name, type, config FROM features WHERE enabled = 1")
    rows = cur.fetchall()
    conn.close()
    return [
        {"name": r[0], "type": r[1], "config": json.loads(r[2])}
        for r in rows
    ]


def get_active_heuristics() -> List[Dict[str, Any]]:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT name, description, condition, weight FROM heuristics WHERE enabled = 1")
    rows = cur.fetchall()
    conn.close()
    return [
        {
            "name": r[0],
            "description": r[1],
            "condition": json.loads(r[2]),
            "weight": r[3]
        }
        for r in rows
    ]


def save_classification(
    report_id: str,
    secret: str,
    filepath: str,
    rule_id: str,
    entropy: float,
    features: Dict[str, Any],
    score: float,
    verdict: str,
    matched: List[str],
    description: str,
    llm_used: bool = False,
    llm_reason: str = None
) -> int:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO classifications (
            report_id, secret, filepath, rule_id, entropy, features_json,
            score, verdict, matched_heuristics, description, llm_used, llm_reason
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        report_id, secret, filepath, rule_id, entropy, json.dumps(features),
        score, verdict, json.dumps(matched), description, llm_used, llm_reason
    ))
    fid = cur.lastrowid
    conn.commit()
    conn.close()
    return fid