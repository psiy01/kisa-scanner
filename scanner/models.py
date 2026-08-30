"""진단 룰과 결과를 표현하는 데이터 구조."""
from dataclasses import dataclass
from enum import Enum
from typing import Any


class Status(str, Enum):
    SAFE = "양호"
    VULNERABLE = "취약"
    ERROR = "점검불가"


@dataclass
class Rule:
    id: str
    category: str
    title: str
    severity: str
    description: str
    check: dict[str, Any]
    evaluate: dict[str, Any]
    remediation: str
    reference: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "Rule":
        return cls(
            id=data["id"],
            category=data["category"],
            title=data["title"],
            severity=data["severity"],
            description=data.get("description", "").strip(),
            check=data["check"],
            evaluate=data["evaluate"],
            remediation=data.get("remediation", "").strip(),
            reference=data.get("reference", ""),
        )


@dataclass
class Result:
    rule: Rule
    status: Status
    raw_output: str
    message: str = ""

def result_to_dict(result: "Result") -> dict:
    """Result 객체를 JSON 직렬화 가능한 딕셔너리로 변환."""
    return {
        "id": result.rule.id,
        "category": result.rule.category,
        "title": result.rule.title,
        "severity": result.rule.severity,
        "status": result.status.value,
        "description": result.rule.description,
        "remediation": result.rule.remediation,
        "reference": result.rule.reference,
        "command": result.rule.check.get("command", ""),
        "raw_output": result.raw_output,
        "message": result.message,
    }