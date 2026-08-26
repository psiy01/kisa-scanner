"""점검 결과를 양호/취약으로 판정."""
import re

from .models import Status


def evaluate(output: str, exit_code: int, spec: dict) -> Status:
    eval_type = spec["type"]

    if not output.strip():
        on_empty = spec.get("on_empty")
        return Status[on_empty.upper()] if on_empty else Status.ERROR

    if eval_type == "regex_match":
        matched = bool(re.search(spec["pattern"], output))
    elif eval_type == "regex_not_match":
        matched = not re.search(spec["pattern"], output)
    elif eval_type == "exit_code":
        matched = exit_code == spec["expected"]
    else:
        return Status.ERROR

    on_match = spec.get("on_match", "vulnerable")
    if matched:
        return Status.VULNERABLE if on_match == "vulnerable" else Status.SAFE
    return Status.SAFE if on_match == "vulnerable" else Status.VULNERABLE