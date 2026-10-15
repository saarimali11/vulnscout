from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    message: str
    severity: Severity
    owasp: str  # e.g. "A03:2021-Injection"
    file: str
    line: int
    col: int = 0