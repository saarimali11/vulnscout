# VS002: flags ways of running shell commands that are open to injection.
# If part of the command string comes from a user, they can add their own
# commands, e.g. "; rm -rf ~". That's OWASP A03 (Injection).
#
# What it catches:
# subprocess.run("...", shell=True)   (also call, check_call, check_output, Popen)
# os.system("...")
# os.popen("...")


import ast

from ..models import Severity
from .import_aware import ImportAwareRule

# Fully qualified names of subprocess functions that accept shell=True
SUBPROCESS_NAMES = {
    f"subprocess.{f}" for f in ("run", "call", "check_call", "check_output", "Popen")
}

# os functions that ALWAYS go through the shell, so they're always flagged
OS_SHELL_NAMES = {"os.system", "os.popen"}


class ShellInjectionRule(ImportAwareRule):
    id = "VS002"
    owasp = "A03:2021-Injection"
    severity = Severity.HIGH

    def visit_Call(self, node: ast.Call) -> None:
        # Resolve the call target to its real name, however it was imported
        name = self.qualified_name(node.func)

        if name in SUBPROCESS_NAMES:
            # subprocess is only risky when shell=True is passed
            if self._has_shell_true(node):
                self.report(
                    node,
                    f"{name}() with shell=True is vulnerable to command "
                    "injection; pass a list of args instead",
                )
        elif name in OS_SHELL_NAMES:
            self.report(
                node,
                f"{name}() runs its input through the shell; use "
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