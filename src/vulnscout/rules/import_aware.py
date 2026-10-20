# A base class for rules that need to know what names really refer to.
#
# Problem: all of these call the same function, but look different in the AST:
# import hashlib; hashlib.md5(x)
# import hashlib as h; h.md5(x)
# from hashlib import md5; md5(x)
# from hashlib import md5 as quick; quick(x)
#
# Fix: before visiting anything, read every import in the file and build a
# table of aliases, e.g. {"h": "hashlib", "quick": "hashlib.md5"}.
# Then qualified_name() turns any call target back into its real dotted name,
# so rules can just check for "hashlib.md5" and not care how it was imported.
#
# Known limits:
# - one alias table per file (no scoping), so a local variable that has the
# same name as an import could confuse it
# - "from x import *" and relative imports (from . import y) are ignored
#
# IMPORTANT for subclasses: don't define visit_Module, and call
# self.generic_visit(node) at the end of visit_Call.

import ast

from .base import Rule


class ImportAwareRule(Rule):
    def __init__(self, path: str):
        super().__init__(path)
        # local name -> real dotted name, e.g. {"h": "hashlib"}
        self.aliases: dict[str, str] = {}

    def visit_Module(self, node: ast.Module) -> None:
        """Runs once at the top of the file, before any calls are visited."""
        # ast.walk goes through EVERY node in the tree (including imports inside
        # functions), so the table is complete before we check a single call.
        for child in ast.walk(node):
            if isinstance(child, ast.Import):
                # import hashlib  / import hashlib as h  / import os.path
                for item in child.names:
                    if item.asname:
                        # "import os.path as p" means p -> os.path
                        self.aliases[item.asname] = item.name
                    else:
                        # "import os.path" only binds the name "os"
                        top = item.name.split(".")[0]
                        self.aliases[top] = top

            elif isinstance(child, ast.ImportFrom):
                # from hashlib import md5 / from hashlib import md5 as quick
                # module is None for "from . import x", level > 0 for relative
                # imports. We skip both since we can't resolve them here.
                if child.module is None or child.level > 0:
                    continue
                for item in child.names:
                    if item.name == "*":
                        continue
                    local = item.asname or item.name
                    self.aliases[local] = f"{child.module}.{item.name}"

        # Now visit the rest of the file as normal
        self.generic_visit(node)

    def qualified_name(self, node: ast.AST) -> str | None:
        """Turn a call target into its real dotted name, or None if we can't.

        Examples (with import hashlib as h):
            h.md5          -> "hashlib.md5"
            os.path.join   -> "os.path.join"
            foo().bar      -> None  (it's a method on a call result, can't resolve)
        """
        parts: list[str] = []

        # Peel off attributes from the outside in: a.b.c gives [c, b], leaving Name(a)
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value

        # The chain has to start at a plain name, otherwise we give up
        if not isinstance(node, ast.Name):
            return None

        # Swap the first name for its real name if it was imported under an alias
        parts.append(self.aliases.get(node.id, node.id))

        # parts is backwards (innermost last), so flip it and join with dots
        return ".".join(reversed(parts))