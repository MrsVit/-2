#!/usr/bin/env python3
import json
import random
import string
import math
import argparse
from pathlib import Path


# --- Эвристики и шаблоны (реальные, как в gitleaks/trufflehog) ---
SECRET_PATTERNS = {
    # GitHub
    "github_pat": {
        "prefixes": ["ghp_", "gho_", "ghu_", "ghs_", "ght_"],
        "entropy_min": 3.5,
        "entropy_max": 5.5,
        "length": 36,
        "chars": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        "context_files": ["src/config.py", ".env", "infra/bad-vars.tf", "public/config.js"],
        "rule_name": "GitHub Personal Access Token",
        "tool": "gitleaks"
    },
    # AWS
    "aws_access_key": {
        "prefixes": ["AKIA", "ABIA", "ACCA", "ASIA"],
        "entropy_min": 2.5,
        "entropy_max": 4.0,
        "length": 16,
        "chars": "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        "context_files": ["infra/bad-vars.tf", "src/main/java/org/owasp/wrongsecrets/challenges/Challenge15.java", "config/local.json"],
        "rule_name": "AWS Access Key ID",
        "tool": "trufflehog"
    },
    # Slack
    "slack_token": {
        "prefixes": ["xoxb-", "xoxp-", "xoxa-", "xoxr-"],
        "entropy_min": 3.8,
        "entropy_max": 5.2,
        "length": {"xoxb-": 46, "xoxp-": 131, "xoxa-": 131, "xoxr-": 51},
        "chars": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        "context_files": ["public/config.js", ".env.local", "config/local.json"],
        "rule_name": "Slack Token",
        "tool": "git-secrets"
    },
    # PyPI
    "pypi_token": {
        "prefixes": ["pypi-"],
        "entropy_min": 4.0,
        "entropy_max": 5.5,
        "length": 74,
        "chars": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        "context_files": ["scripts/deploy.sh", "scripts/publish.sh"],
        "rule_name": "PyPI API Token",
        "tool": "detect-secrets"
    },
    # JWT (header.payload.signature)
    "jwt": {
        "prefixes": ["eyJ"],
        "entropy_min": 3.0,
        "entropy_max": 5.0,
        "length": None,
        "chars": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.",
        "context_files": [
            "src/main/java/org/owasp/wrongsecrets/challenges/Challenge23.java",
            "mocks/auth_response.json",
            "src/auth/auth_service.js"
        ],
        "rule_name": "Hardcoded JWT",
        "tool": "whispers"
    },
    # Private Key (PEM)
    "private_key": {
        "prefixes": ["-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----"],
        "entropy_min": 4.5,
        "entropy_max": 6.0,
        "length": 1200,
        "chars": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=\n",
        "context_files": ["certs/debug.key", "backups/cert_backup_2024.key", "k8s/secrets-config.yml"],
        "rule_name": "Private Key in PEM",
        "tool": "gitleaks"
    },
    # Generic API Key
    "api_key": {
        "prefixes": ["sk-", "api_key =", "token =", "key ="],
        "entropy_min": 3.6,
        "entropy_max": 5.3,
        "length": 40,
        "chars": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        "context_files": ["tests/e2e/secret_test.py", "src/config.py", "mocks/local_storage.json"],
        "rule_name": "Generic API Key",
        "tool": "detect-secrets"
    },
    # Vault Token
    "vault_token": {
        "prefixes": ["hvs.", "s.", "token: "],
        "entropy_min": 3.7,
        "entropy_max": 5.4,
        "length": 32,
        "chars": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        "context_files": ["logs/app.log", "src/main/resources/application.properties"],
        "rule_name": "Vault Token",
        "tool": "trufflehog"
    },
    # SSH Public Key (для x509/SSH challenge-53)
    "ssh_public_key": {
        "prefixes": ["ssh-rsa AAAAB3"],
        "entropy_min": 4.0,
        "entropy_max": 5.8,
        "length": 200,
        "chars": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=",
        "context_files": ["k8s/sealed-challenge48.json", "config/known_hosts"],
        "rule_name": "SSH Public Key",
        "tool": "gitleaks"
    },
    # PII (для AquilaX)
    "pii": {
        "prefixes": ["@example.", "+1"],
        "entropy_min": 2.0,
        "entropy_max": 3.5,
        "length": 50,
        "chars": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@+-. ",
        "context_files": ["tests/data/pii_test.txt", "logs/user_dump.csv"],
        "rule_name": "PII Exposure",
        "tool": "pii-scanner"
    }
}

# --- Утилиты ---
def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy -= p_x * math.log2(p_x)
    return entropy

def generate_token(spec, use_entropy=True):
    prefix = random.choice(spec["prefixes"])
    chars = spec["chars"]
    if spec["name"] == "jwt":
        # eyJxxx.xxx.xxx
        parts = [
            ''.join(random.choices(chars.replace('_.', ''), k=10)),
            ''.join(random.choices(chars.replace('_.', ''), k=20)),
            ''.join(random.choices(chars.replace('.=', ''), k=30))
        ]
        token = f"eyJ{parts[0]}.{parts[1]}.{parts[2]}"
    elif spec["name"] == "private_key":
        body = ''.join(random.choices(chars, k=1000))
        token = f"{prefix}\n{body}\n-----END {' '.join(prefix.split()[1:])}"
    elif spec["name"] == "ssh_public_key":
        body = ''.join(random.choices(chars, k=180))
        comment = f" user{random.randint(1,999)}@example.fake"
        token = f"{prefix}{body}{comment}"
    elif spec["name"] == "pii":
        names = ["john.doe", "jane.smith", "alex.wong"]
        domains = ["example.fake", "test.org", "demo.net"]
        nums = [f"+1 (555) {random.randint(100,999)}-{random.randint(1000,9999)}"]
        ssn = f"{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}"
        token = f"{random.choice(names)}@{random.choice(domains)},{random.choice(nums)},{ssn}"
    else:
        length = spec["length"]
        if isinstance(length, dict):
            length = length.get(prefix, 40)
        body = ''.join(random.choices(chars, k=length - len(prefix)))
        token = f"{prefix}{body}"

    # Принудительная подстройка энтропии (если нужно)
    if use_entropy:
        ent = shannon_entropy(token)
        target_min = spec["entropy_min"]
        target_max = spec["entropy_max"]
        # Простой fallback: заменяем символы, пока не в диапазоне (для демо — достаточно)
        attempts = 0
        while not (target_min <= ent <= target_max) and attempts < 5:
            token = token[:-1] + random.choice(chars)
            ent = shannon_entropy(token)
            attempts += 1
    return token

# --- Генерация SARIF ---
def generate_sarif_report(
    count: int = 1000,
    entropy_enabled: bool = True,
    leak_ratio: float = 0.7  # 70% утечек, 30% безопасных
):
    results = []
    spec_list = [{"name": k, **v} for k, v in SECRET_PATTERNS.items()]

    for i in range(1, count + 1):
        # Решаем: утечка или безопасный файл?
        is_leak = random.random() < leak_ratio

        if is_leak:
            spec = random.choice(spec_list)
            token = generate_token(spec, use_entropy=entropy_enabled)
            uri = random.choice(spec["context_files"])
            snippet = f"secret = '{token}'"
            if spec["name"] == "private_key":
                snippet = token
            elif spec["name"] == "pii":
                snippet = token
            rule_id = f"{spec['name']}"
            message = f"Hardcoded {spec['rule_name']}"
            tool_name = spec["tool"]
        else:
            # Безопасный файл
            safe_files = [
                ("src/utils/string_helpers.py", "def truncate(s, n=20): return s[:n] + '...' if len(s) > n else s"),
                ("tests/unit/test_string.py", "assert truncate('hello', 10) == 'hello'"),
                ("Dockerfile", "USER 1001\nCOPY . /app\nCMD [\"gunicorn\", \"app:app\"]"),
                (".gitignore", ".env\n__pycache__/\n*.log"),
                ("README.md", "# WrongSecrets Playground\nAll secrets here are fake."),
                ("k8s/app-deployment.yaml", "env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: db-secret\n        key: password")
            ]
            uri, snippet = random.choice(safe_files)
            rule_id = "no-secret"
            message = "No secret found — clean file"
            tool_name = "semgrep"

        results.append({
            "ruleId": rule_id,
            "rule": {"id": rule_id, "name": message},
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {
                        "startLine": random.randint(1, 50),
                        "snippet": {"text": snippet}
                    }
                }
            }],
            "properties": {
                "entropy": round(shannon_entropy(snippet), 2) if is_leak else 0.0
            }
        })

    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "SARIF Secret Generator"}},
            "results": results
        }]
    }
    return sarif

# --- CLI ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate SARIF reports with fake secrets (OWASP WrongSecrets / AquilaX style)")
    parser.add_argument("-n", "--count", type=int, default=1000, help="Number of results (default: 1000)")
    parser.add_argument("-e", "--entropy", action="store_true", help="Enable entropy tuning (default: off for speed)")
    parser.add_argument("-r", "--leak-ratio", type=float, default=0.7, help="Fraction of files with leaks (0.0–1.0, default: 0.7)")
    parser.add_argument("-o", "--output", default="201.json")
    args = parser.parse_args()

    print(f"🚀 Generating {args.count} SARIF results ({int(args.leak_ratio*100)}% with leaks, entropy={'on' if args.entropy else 'off'})...")
    sarif = generate_sarif_report(
        count=args.count,
        entropy_enabled=args.entropy,
        leak_ratio=args.leak_ratio
    )

    Path(args.output).write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    print(f"✅ Saved to `{args.output}`")
    print(f"🔍 Example result:\n{json.dumps(sarif['runs'][0]['results'][0], indent=2)[:500]}...")