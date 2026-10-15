# This file holds the base class every detection rule will inherit from.
# Having one shared base means all rules work the same way,
# so adding a new rule later is just writing a small subclass.

import ast

# Two dots = go up one folder (out of rules/) and import from models.py
from ..models import Finding, Severity


class Rule(ast.NodeVisitor):
    """Base class for all rules.

    ast.NodeVisitor walks through a parsed Python syntax tree.
    For each node type, it looks for a method named visit_<NodeType>.
    Example: a method called visit_Call runs for every function call in the code.
    Subclasses define those methods and call self.report() when they spot a problem.
    """

    # Each rule overrides these three with its own values
    id: str = ""
    owasp: str = ""
    severity: Severity = Severity.LOW

    def __init__(self, path: str):
        # Remember which file we're scanning so findings can say where they came from
        self.path = path
        # Every issue this rule finds gets added to this list
        self.findings: list[Finding] = []

    def report(self, node: ast.AST, message: str) -> None:
        """Record a finding at the location of the given syntax tree node."""
        self.findings.append(
            Finding(
                rule_id=self.id,
                message=message,
                severity=self.severity,
                owasp=self.owasp,
                file=self.path,
                # getattr with a default is safe if a node has no line info
                line=getattr(node, "lineno", 0),
                col=getattr(node, "col_offset", 0),
            )
        )