"""룰을 읽어 실행하고 결과를 모으는 오케스트레이터."""
from pathlib import Path

import yaml

from .evaluator import evaluate
from .executor import Executor
from .models import Result, Rule, Status


def load_rules(rules_dir: Path) -> list[Rule]:
    """디렉터리의 모든 YAML 룰을 읽어 Rule 객체로 변환."""
    rules = []
    for path in sorted(rules_dir.glob("*.yaml")):
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        rules.append(Rule.from_dict(data))
    return rules


def run_scan(executor: Executor, rules: list[Rule]) -> list[Result]:
    """각 룰을 실행하고 판정 결과를 반환."""
    results = []
    for rule in rules:
        try:
            output, exit_code = executor.run(rule.check["command"])
            status = evaluate(output, exit_code, rule.evaluate)
            results.append(Result(rule=rule, status=status, raw_output=output))
        except Exception as exc:
            results.append(
                Result(rule=rule, status=Status.ERROR,
                       raw_output="", message=str(exc))
            )
    return results