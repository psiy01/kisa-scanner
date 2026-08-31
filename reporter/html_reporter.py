"""진단 결과를 HTML 리포트로 렌더링."""
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from scanner.models import Result, Status, result_to_dict

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def build_summary(results: list[Result]) -> dict:
    """리포트 상단에 표시할 요약 통계를 계산."""
    total = len(results)
    counts = Counter(r.status for r in results)
    vulnerable = counts[Status.VULNERABLE]
    safe = counts[Status.SAFE]
    error = counts[Status.ERROR]

    # 준수율: 점검 가능한 항목 중 양호 비율
    checkable = safe + vulnerable
    compliance = round(safe / checkable * 100, 1) if checkable else 0.0

    # 취약 항목의 위험도 분포
    severity = Counter(
        r.rule.severity for r in results if r.status is Status.VULNERABLE
    )

    # 카테고리별 집계
    by_category = defaultdict(lambda: {"total": 0, "vulnerable": 0})
    for r in results:
        cat = by_category[r.rule.category]
        cat["total"] += 1
        if r.status is Status.VULNERABLE:
            cat["vulnerable"] += 1

    return {
        "total": total,
        "safe": safe,
        "vulnerable": vulnerable,
        "error": error,
        "compliance": compliance,
        "severity": {
            "high": severity.get("high", 0),
            "medium": severity.get("medium", 0),
            "low": severity.get("low", 0),
        },
        "categories": dict(by_category),
    }


def generate(results: list[Result], target: str, output_path: Path) -> Path:
    """HTML 리포트를 생성하고 저장 경로를 반환."""
    template_dir = Path(__file__).parent / "templates"
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=True,
    )
    template = env.get_template("report.html")

    # 취약 항목을 위험도순으로 정렬 (조치 우선순위)
    items = [result_to_dict(r) for r in results]
    priority = sorted(
        (i for i in items if i["status"] == "취약"),
        key=lambda i: SEVERITY_ORDER.get(i["severity"], 9),
    )

    html = template.render(
        target=target,
        scanned_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        summary=build_summary(results),
        priority=priority,
        items=items,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    return output_path

def generate_comparison(
    before: dict, after: dict, output_path: Path
) -> Path:
    """전후 비교 리포트를 생성."""
    template_dir = Path(__file__).parent / "templates"
    env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)
    template = env.get_template("comparison.html")

    fixed, remaining, regressed = [], [], []
    for rid, b in before.items():
        a = after.get(rid)
        if a is None:
            continue
        pair = {"before": b, "after": a}
        if b["status"] == "취약" and a["status"] == "양호":
            fixed.append(pair)
        elif b["status"] == "취약" and a["status"] == "취약":
            remaining.append(pair)
        elif b["status"] == "양호" and a["status"] == "취약":
            regressed.append(pair)

    b_vuln = sum(1 for r in before.values() if r["status"] == "취약")
    a_vuln = sum(1 for r in after.values() if r["status"] == "취약")
    rate = round((b_vuln - a_vuln) / b_vuln * 100, 1) if b_vuln else 0.0

    html = template.render(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        before_vuln=b_vuln,
        after_vuln=a_vuln,
        rate=rate,
        fixed=sorted(fixed, key=lambda p: SEVERITY_ORDER.get(
            p["after"]["severity"], 9)),
        remaining=sorted(remaining, key=lambda p: SEVERITY_ORDER.get(
            p["after"]["severity"], 9)),
        regressed=regressed,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    return output_path