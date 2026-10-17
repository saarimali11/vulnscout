# VS001: flags calls to eval() and exec().
# Both run a string as Python code. If an attacker controls that string,
# they control the program. That's code injection, OWASP A03.

import ast

from ..models import Severity
from .base import Rule

# The names of the dangerous builtin functions.
# A set makes the "is it in here?" check fast and easy to extend.
DANGEROUS_BUILTINS = {"eval", "exec"}


class EvalExecRule(Rule):
    # Metadata for this rule. These override the empty defaults in Rule.
    id = "VS001"
    owasp = "A03:2021-Injection"
    severity = Severity.HIGH

    def visit_Call(self, node: ast.Call) -> None:
        """Runs once for every function call in the file being scanned."""
        # eval("x") is a call where node.func is a plain name (ast.Name).
        # Something like ast.literal_eval("x") has node.func as an ast.Attribute
        # (a dotted name), so it fails this check and is correctly ignored.
        # literal_eval is the SAFE alternative, so we don't want to flag it.
        if isinstance(node.func, ast.Name) and node.func.id in DANGEROUS_BUILTINS:
            self.report(
                node,
                f"{node.func.id}() runs arbitrary code; avoid it on untrusted "
                "input (use ast.literal_eval for plain data)",
            )

        # IMPORTANT: once I define visit_Call, the visitor stops walking
        # into the children of every call node. generic_visit() tells it to
        # keep going, so something like eval(eval("1")) still finds both calls.
        self.generic_visit(node)