"""KISA 서버 취약점 진단 도구 진입점."""
import argparse
import json
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table

from reporter import html_reporter
from scanner.engine import load_rules, run_scan
from scanner.executor import SSHExecutor
from scanner.models import Status, result_to_dict

console = Console()

STATUS_STYLE = {
    Status.SAFE: "green",
    Status.VULNERABLE: "red",
    Status.ERROR: "yellow",
}


def main() -> None:
    parser = argparse.ArgumentParser(description="KISA 서버 취약점 진단 도구")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--password", default="toor1234")
    parser.add_argument("--rules", default="rules/ubuntu")
    parser.add_argument("--label", default="before",
                        help="결과 파일 구분용 라벨 (before/after)")
    args = parser.parse_args()

    rules = load_rules(Path(args.rules))
    console.print(f"[bold]룰 {len(rules)}개 로드 완료[/bold]")

    executor = SSHExecutor(args.host, args.port, args.user, args.password)
    console.print(f"[bold]{args.host}:{args.port} 접속 성공[/bold]\n")

    results = run_scan(executor, rules)
    executor.close()

    table = Table(title="진단 결과")
    table.add_column("ID")
    table.add_column("항목")
    table.add_column("위험도")
    table.add_column("결과")

    for r in results:
        table.add_row(
            r.rule.id,
            r.rule.title,
            r.rule.severity,
            f"[{STATUS_STYLE[r.status]}]{r.status.value}[/]",
        )

    console.print(table)

    vuln = sum(1 for r in results if r.status is Status.VULNERABLE)
    console.print(f"\n취약 {vuln}건 / 전체 {len(results)}건")

    # 진단 결과를 JSON으로 저장 (전후 비교용)
    snapshot = {
        "target": f"{args.host}:{args.port}",
        "scanned_at": datetime.now().isoformat(),
        "results": [result_to_dict(r) for r in results],
    }
    snap_path = Path("output") / f"scan-{args.label}.json"
    snap_path.parent.mkdir(parents=True, exist_ok=True)
    snap_path.write_text(
        json.dumps(snapshot, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    console.print(f"결과 저장: {snap_path}")

    report_path = html_reporter.generate(
        results,
        target=f"{args.host}:{args.port}",
        output_path=Path("output") / "report.html",
    )
    console.print(f"[bold]리포트 생성: {report_path}[/bold]")


if __name__ == "__main__":
    main()