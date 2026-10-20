# VS005: flags weak hash algorithms (MD5 and SHA-1).
# Both are broken for security: attackers can create two different inputs with
# the same hash (collisions), so they shouldn't be used for passwords, signatures,
# or integrity checks. Use SHA-256 or better (and bcrypt/argon2 for passwords).
# OWASP: A02 Cryptographic Failures.
#
# What it catches:
#   hashlib.md5(...)   hashlib.sha1(...)   hashlib.new("md5")   hashlib.new("sha1")
# (including aliased imports, thanks to ImportAwareRule)
#
# What it deliberately skips:
#   hashlib.md5(data, usedforsecurity=False)
# That flag is the official way to say "this is just a checksum or cache key,
# not security", so flagging it would be a false positive.

import ast

from ..models import Severity
from .import_aware import ImportAwareRule

WEAK_FUNCS = {"hashlib.md5", "hashlib.sha1"}
WEAK_ALGORITHMS = {"md5", "sha1"}


class WeakHashRule(ImportAwareRule):
    id = "VS005"
    owasp = "A02:2021-Cryptographic Failures"
    severity = Severity.MEDIUM

    def visit_Call(self, node: ast.Call) -> None:
        name = self.qualified_name(node.func)

        # Only look further if it's a hashlib call that isn't opted out
        if name and not self._opted_out(node):
            algorithm = None

            if name in WEAK_FUNCS:
                # "hashlib.md5" -> "md5"
                algorithm = name.split(".")[1]

            elif name == "hashlib.new" and node.args:
                # hashlib.new("MD5", data): the algorithm is the first argument
                first = node.args[0]
                if (isinstance(first, ast.Constant) and isinstance(first.value, str)
                        and first.value.lower() in WEAK_ALGORITHMS):
                    algorithm = first.value.lower()

            if algorithm:
                self.report(
                    node,
                    f"{algorithm.upper()} is a weak hash; use SHA-256 or better "
                    "(or bcrypt/argon2 for passwords)",
                )

        # Keep walking so nested calls are checked too
        self.generic_visit(node)

    @staticmethod
    def _opted_out(node: ast.Call) -> bool:
        """True if the call has usedforsecurity=False."""
        for kw in node.keywords:
            if (kw.arg == "usedforsecurity" and isinstance(kw.value, ast.Constant)
                    and kw.value.value is False):
                return True
        return False