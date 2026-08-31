"""1차/2차 진단 결과를 비교해 개선 현황을 출력."""
import argparse
import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

console = Console()


def load(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    return {r["id"]: r for r in data["results"]}


def main() -> None:
    parser = argparse.ArgumentParser(description="진단 결과 전후 비교")
    parser.add_argument("--before", default="output/scan-before.json")
    parser.add_argument("--after", default="output/scan-after.json")
    args = parser.parse_args()

    before = load(Path(args.before))
    after = load(Path(args.after))

    fixed, remaining, regressed = [], [], []

    for rid, b in before.items():
        a = after.get(rid)
        if a is None:
            continue
        if b["status"] == "취약" and a["status"] == "양호":
            fixed.append(a)
        elif b["status"] == "취약" and a["status"] == "취약":
            remaining.append(a)
        elif b["status"] == "양호" and a["status"] == "취약":
            regressed.append(a)

    b_vuln = sum(1 for r in before.values() if r["status"] == "취약")
    a_vuln = sum(1 for r in after.values() if r["status"] == "취약")
    rate = round((b_vuln - a_vuln) / b_vuln * 100, 1) if b_vuln else 0.0

    console.print(f"\n[bold]조치 전 취약 {b_vuln}건 → 조치 후 {a_vuln}건[/bold]")
    console.print(f"[bold green]개선율 {rate}%[/bold green]\n")

    if fixed:
        t = Table(title=f"조치 완료 ({len(fixed)}건)")
        t.add_column("ID"); t.add_column("항목"); t.add_column("위험도")
        for r in fixed:
            t.add_row(r["id"], r["title"], r["severity"])
        console.print(t)

    if remaining:
        t = Table(title=f"미조치 ({len(remaining)}건)")
        t.add_column("ID"); t.add_column("항목"); t.add_column("위험도")
        for r in remaining:
            t.add_row(r["id"], r["title"], r["severity"])
        console.print(t)

    if regressed:
        t = Table(title=f"[red]악화 ({len(regressed)}건)[/red]")
        t.add_column("ID"); t.add_column("항목")
        for r in regressed:
            t.add_row(r["id"], r["title"])
        console.print(t)

    from reporter.html_reporter import generate_comparison
    path = generate_comparison(before, after, Path("output") / "comparison.html")
    console.print(f"\n[bold]비교 리포트: {path}[/bold]")


if __name__ == "__main__":
    main()