# VS002: flags ways of running shell commands that are open to injection.
# If part of the command string comes from a user, they can add their own
# commands, e.g. "; rm -rf ~". That's OWASP A03 (Injection).
#
# What it catches:
#   subprocess.run("...", shell=True)   (also call, check_call, check_output, Popen)
#   os.system("...")
#   os.popen("...")
#
# Known limitation: it only matches the "module.function" style. It won't see
# "from subprocess import run" yet.

import ast

from ..models import Severity
from .base import Rule

# subprocess functions that accept a shell=True argument
SUBPROCESS_FUNCS = {"run", "call", "check_call", "check_output", "Popen"}

# os functions that ALWAYS go through the shell, so they're always flagged
OS_SHELL_FUNCS = {"system", "popen"}


class ShellInjectionRule(Rule):
    id = "VS002"
    owasp = "A03:2021-Injection"
    severity = Severity.HIGH

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func

        # I only care about calls shaped like  something.something(...)
        # e.g. subprocess.run(...) is an Attribute whose value is the Name "subprocess"
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            module = func.value.id # e.g. "subprocess"
            name = func.attr # e.g. "run"

            if module == "subprocess" and name in SUBPROCESS_FUNCS:
                # subprocess is only risky when shell=True is passed
                if self._has_shell_true(node):
                    self.report(
                        node,
                        f"subprocess.{name}() with shell=True is vulnerable to "
                        "command injection; pass a list of args instead",
                    )
            elif module == "os" and name in OS_SHELL_FUNCS:
                self.report(
                    node,
                    f"os.{name}() runs its input through the shell; use "
                    "subprocess.run([...]) with a list of args instead",
                )

        # Keep walking so calls nested inside this call are checked too
        self.generic_visit(node)

    @staticmethod
    def _has_shell_true(node: ast.Call) -> bool:
        """True if the call includes the keyword argument shell=True."""
        # node.keywords holds keyword args, e.g. shell=True or check=True
        for kw in node.keywords:
            # kw.arg is the name; kw.value is the value, here an ast.Constant
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) \
                    and kw.value.value is True:
                return True
        # shell=some_variable isn't flagged: we can't know its value statically
        return False