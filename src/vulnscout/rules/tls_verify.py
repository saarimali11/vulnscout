# VS006: flags code that turns off TLS certificate checking.
# With verification off, anyone on the network path can pretend to be the
# server (a man-in-the-middle attack) and read or change the traffic, even
# though the URL says https. OWASP: A02 Cryptographic Failures.
#
# What it catches:
# call with verify=False e.g. requests.get(url, verify=False),
# session.post(url, verify=False), httpx.get(...)
# ssl._create_unverified_context()
#
# Why "any call" for verify=False: matching just the keyword catches session
# objects too (session.get), which we can't resolve to a library statically.
# verify=False is a very specific keyword, so false positives should be rare.
#


import ast

from ..models import Severity
from .import_aware import ImportAwareRule


class TlsVerificationRule(ImportAwareRule):
    id = "VS006"
    owasp = "A02:2021-Cryptographic Failures"
    severity = Severity.HIGH

    def visit_Call(self, node: ast.Call) -> None:
        # Check 1: any keyword argument that is exactly verify=False
        for kw in node.keywords:
            if (kw.arg == "verify" and isinstance(kw.value, ast.Constant)
                    and kw.value.value is False):
                self.report(
                    node,
                    "TLS certificate verification is disabled (verify=False); "
                    "connections can be intercepted. Remove it or pass a CA bundle path",
                )
                break   # one finding per call is enough

        # Check 2: the ssl helper whose whole purpose is skipping verification.
        # qualified_name resolves aliases like "from ssl import _create_unverified_context"
        if self.qualified_name(node.func) == "ssl._create_unverified_context":
            self.report(
                node,
                "ssl._create_unverified_context() disables certificate checks; "
                "use ssl.create_default_context() instead",
            )

        # Keep walking so nested calls are checked too
        self.generic_visit(node)