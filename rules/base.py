import ast

from ..models import Finding, Severity


class Rule(ast.NodeVisitor):
    """Base class for all detection rules. Subclasses define metadata
    and implement visit_* methods that call self.report()."""

    id: str = ""
    owasp: str = ""
    severity: Severity = Severity.LOW

    def __init__(self, path: str):
        self.path = path
        self.findings: list[Finding] = []

    def report(self, node: ast.AST, message: str) -> None:
        self.findings.append(
            Finding(
                rule_id=self.id,
                message=message,
                severity=self.severity,
                owasp=self.owasp,
                file=self.path,
                line=getattr(node, "lineno", 0),
                col=getattr(node, "col_offset", 0),
            )
        )