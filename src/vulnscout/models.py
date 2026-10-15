# This file defines the data objects the rest of the program passes around.

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    """How serious a finding is.

    Inheriting from str means each value is also a normal string,
    which makes it easy to print and to put into JSON later.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# frozen=True means a Finding can't be changed after it's created.
# That prevents bugs where one part of the code accidentally edits a result.
# @dataclass automatically writes __init__ and __repr__ for us.
@dataclass(frozen=True)
class Finding:
    """One security issue found in one spot of a file."""

    rule_id: str      # short ID of the rule that fired, e.g. "VS001"
    message: str      # human-readable explanation of the problem
    severity: Severity
    owasp: str        # OWASP Top 10 category, e.g. "A03:2021-Injection"
    file: str         # path of the file the issue is in
    line: int         # line number (starts at 1)
    col: int = 0      # column number, defaults to 0 if unknown