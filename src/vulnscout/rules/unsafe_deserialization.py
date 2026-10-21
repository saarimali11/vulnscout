# VS007: flags loading data with formats that can execute code.
# Formats like pickle rebuild Python objects, and an attacker can craft a file
# that runs ANY code the moment it's loaded (no further action needed).
# If the data could come from a user, a download, or a shared folder, that's
# remote code execution. OWASP: A08 Software and Data Integrity Failures.
#
# What it catches:
# 1. Always unsafe:  pickle.load/loads/Unpickler, dill.load/loads,
# marshal.load/loads, shelve.open, pandas.read_pickle
# 2. YAML: yaml.load / yaml.load_all with no Loader, or an unsafe one
# (yaml.safe_load and Loader=yaml.SafeLoader are fine)
# 3. NumPy: numpy.load(..., allow_pickle=True)
#
#
# Known limits:
# - a Loader stored in a variable (Loader=my_loader) isn't flagged, since we
# can't tell what it holds
# - it flags every pickle.load, even on files you wrote yourself, because the
# scanner can't know where the data came from. The safe fix is a different
# format (JSON), and Day 9 adds comments to suppress known-safe cases.

import ast

from ..models import Severity
from .import_aware import ImportAwareRule

# Functions that are unsafe no matter how they're called.
# qualified name -> short label used in the message
ALWAYS_UNSAFE = {
    "pickle.load": "pickle",
    "pickle.loads": "pickle",
    "pickle.Unpickler": "pickle",
    "_pickle.load": "pickle",
    "_pickle.loads": "pickle",
    "dill.load": "dill",
    "dill.loads": "dill",
    "marshal.load": "marshal",
    "marshal.loads": "marshal",
    "shelve.open": "shelve (it stores values with pickle)",
    "pandas.read_pickle": "pickle",
}

# yaml functions that are only safe when given a safe Loader
YAML_LOADERS = {"yaml.load", "yaml.load_all"}

# yaml functions that are unsafe by definition (the name says it)
YAML_ALWAYS_UNSAFE = {"yaml.unsafe_load", "yaml.unsafe_load_all"}

# Loaders that can build arbitrary Python objects. If one of these is passed,
# yaml.load is dangerous. (SafeLoader and BaseLoader are not in this set.)
UNSAFE_YAML_LOADERS = {"yaml.Loader", "yaml.UnsafeLoader", "yaml.CLoader",
                       "yaml.CUnsafeLoader"}


class UnsafeDeserializationRule(ImportAwareRule):
    id = "VS007"
    owasp = "A08:2021-Software and Data Integrity Failures"
    severity = Severity.HIGH

    def visit_Call(self, node: ast.Call) -> None:
        # Resolve the call to its real name, however it was imported
        name = self.qualified_name(node.func)

        if name in ALWAYS_UNSAFE:
            self.report(
                node,
                f"{name}() can run arbitrary code while loading "
                f"({ALWAYS_UNSAFE[name]}); only load data you created yourself, "
                "or use a safe format like JSON",
            )

        elif name in YAML_ALWAYS_UNSAFE:
            self.report(
                node,
                f"{name}() can build arbitrary Python objects; use yaml.safe_load() instead",
            )

        elif name in YAML_LOADERS and self._yaml_loader_is_unsafe(node):
            self.report(
                node,
                f"{name}() without a safe Loader can run arbitrary code; "
                "use yaml.safe_load() or pass Loader=yaml.SafeLoader",
            )

        elif name == "numpy.load" and self._allows_pickle(node):
            self.report(
                node,
                "numpy.load(allow_pickle=True) can run arbitrary code while loading; "
                "leave allow_pickle off (the default) unless you trust the file",
            )

        # Keep walking so nested calls are checked too
        self.generic_visit(node)

    # helpers  

    @staticmethod
    def _loader_argument(node: ast.Call) -> ast.AST | None:
        """Find the Loader argument of yaml.load(stream, Loader), or None."""
        # Keyword form: yaml.load(text, Loader=yaml.SafeLoader)
        for kw in node.keywords:
            if kw.arg == "Loader":
                return kw.value
        # Positional form: yaml.load(text, yaml.SafeLoader). Loader is argument #2
        if len(node.args) >= 2:
            return node.args[1]
        return None

    def _yaml_loader_is_unsafe(self, node: ast.Call) -> bool:
        loader = self._loader_argument(node)
        if loader is None:
            # No Loader at all: older PyYAML defaulted to the unsafe one
            return True
        # Resolve the Loader's real name (handles "from yaml import Loader" too).
        # Anything we don't recognize as unsafe is left alone (no false alarm).
        return self.qualified_name(loader) in UNSAFE_YAML_LOADERS

    @staticmethod
    def _allows_pickle(node: ast.Call) -> bool:
        """True if the call includes the keyword argument allow_pickle=True."""
        for kw in node.keywords:
            if (kw.arg == "allow_pickle" and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True):
                return True
        return False