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
    elif eval_type == "numeric_compare":
        found = re.search(spec.get("extract", r"(\d+)"), output)
        if not found:
            return Status.ERROR
        value = int(found.group(1))
        op = spec["operator"]
        expected = spec["value"]
        matched = {
            ">=": value >= expected,
            "<=": value <= expected,
            ">": value > expected,
            "<": value < expected,
            "==": value == expected,
        }.get(op, False)
    elif eval_type == "permission_check":
        found = re.search(r'(\d{3,4})', output)
        if not found:
            return Status.ERROR
        actual = int(found.group(1)[-3:], 8)
        maximum = int(str(spec["max_permission"]), 8)
        # 허용 범위를 넘는 비트가 하나라도 켜져 있으면 위반
        matched = (actual & ~maximum) == 0
    else:
        return Status.ERROR

    on_match = spec.get("on_match", "vulnerable")
    if matched:
        return Status.VULNERABLE if on_match == "vulnerable" else Status.SAFE
    return Status.SAFE if on_match == "vulnerable" else Status.VULNERABLE