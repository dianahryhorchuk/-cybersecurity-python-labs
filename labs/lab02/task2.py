import csv
from dataclasses import dataclass
import json
import logging
from pathlib import Path
import re

REQUIRED_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
]


VERSION_LEAK_REGEX = re.compile(r"([a-zA-Z\-]+/[\d.]+)")

@dataclass
class HeaderAuditResult:
    target: str
    security_score: int
    score_grade: str
    status: str
    missing_headers: list
    leaks: list


def evaluate_resource(target: str, raw_headers: dict, strict: bool = False):
    headers_lower = {}
    for key, value in raw_headers.items():
        headers_lower[key.lower()] = (key, str(value))

    missing = []
    for req_header in REQUIRED_SECURITY_HEADERS:
        if req_header.lower() not in headers_lower:
            missing.append(req_header)

    # Перевірка на витік версій сервера
    leaks = []
    for check_hdr in ["server", "x-powered-by"]:
        if check_hdr in headers_lower:
            orig_name, val = headers_lower[check_hdr]
            if VERSION_LEAK_REGEX.search(val):
                leaks.append(f"leaks version in '{orig_name}': {val}")

    # Підрахунок балів
    deduction_per_missing = 25 if strict else 20
    score = 100 - (len(missing) * deduction_per_missing) - (len(leaks) * 10)
    
    if score < 0:
        score = 0

    if score >= 90:
        grade = "A+"
        status = "PASS"
    elif score >= 60:
        grade = "C"
        status = "WARN"
    else:
        grade = "F"
        status = "FAIL"

    return HeaderAuditResult(
        target=target,
        security_score=score,
        score_grade=grade,
        status=status,
        missing_headers=missing,
        leaks=leaks,
    )


def audit_headers(headers_path: Path, output_csv: Path, strict: bool = False):
    logging.info("Auditing HTTP response headers from %s...", headers_path)
    
    if not headers_path.exists():
        logging.error("Файл не знайдено: %s", headers_path)
        raise FileNotFoundError(f"Файл не знайдено: {headers_path}")

    
    with open(headers_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    
    items = []
    if isinstance(data, dict):
        for target, hdrs in data.items():
            items.append((target, hdrs))
    else:
        for item in data:
            target = item.get("url", item.get("target", "unknown"))
            hdrs = item.get("headers", {})
            items.append((target, hdrs))

    results = []
    for target, hdrs in items:
        res = evaluate_resource(target, hdrs, strict=strict)
        results.append(res)

    print("\nTarget Resource                  Security Score  Status  Missing Security Headers")
    print("-" * 85)
    
    for r in results:
        if r.missing_headers:
            missing_str = ", ".join(r.missing_headers)
        else:
            missing_str = "None"
            
        score_display = f"{r.security_score}/100 ({r.score_grade})"
        print(f"{r.target:<32} {score_display:<15} {r.status:<7} {missing_str}")

    # Вивід витоків версій ПЗ 
    print("\n Server Software Leak Alerts")
    for r in results:
        for leak in r.leaks:
            alert = f"[LEAK] {r.target} {leak}"
            print(alert)
            logging.warning(alert)

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with open(output_csv, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(
            [
                "Target",
                "SecurityScore",
                "Grade",
                "Status",
                "MissingHeaders",
                "VersionLeaks",
            ]
        )
        for r in results:
            writer.writerow(
                [
                    r.target,
                    r.security_score,
                    r.score_grade,
                    r.status,
                    "; ".join(r.missing_headers),
                    "; ".join(r.leaks),
                ]
            )

    logging.info("Header audit report generated at %s", output_csv)
    return results