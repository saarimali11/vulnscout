# VS003: flags SQL queries built by gluing strings together.
# If a user's input gets pasted into the query text, they can change what
# the query does (e.g. name = "x' OR '1'='1"). That's SQL injection, OWASP A03.
#
# Vulnerable: cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
# Safe: cur.execute("SELECT * FROM users WHERE name = ?", (name,))
# (the database inserts the value itself, so it can't become SQL)
#
# What it detects as "built dynamically":
# f-strings with {placeholders}, "..." + var, "..." % var, "...".format(var)
# It also tracks one step of variables:
# query = "..." + name
# cur.execute(query) <- flagged because query was built dynamically
#
# Known limits (static analysis can't see everything):
#   - it doesn't follow values passed between functions
#   - it only checks the FIRST argument of execute (the query text)

import ast

from ..models import Severity
from .base import Rule

# Method names that run SQL. We match on the method name only, since we
# can't know statically whether "cur" is a sqlite3 cursor, psycopg2, etc.
EXECUTE_METHODS = {"execute", "executemany", "executescript"}


def _is_constant_string(node: ast.AST) -> bool:
    """True if node is a plain string, or plain strings joined with +."""
    # A normal string literal like "SELECT 1"
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    # "SELECT " + "1" is still fully constant, so check both sides
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_constant_string(node.left) and _is_constant_string(node.right)
    return False


class SqlInjectionRule(Rule):
    id = "VS003"
    owasp = "A03:2021-Injection"
    severity = Severity.HIGH

    def __init__(self, path: str):
        super().__init__(path)
        # Names of variables currently known to hold a dynamically built string.
        # visit_Assign fills this in as we walk through the code top to bottom.
        self.dynamic_names: set[str] = set()

    # helper: is this expression a dynamically built string?

    def _is_dynamic(self, node: ast.AST) -> bool:
        # f"... {x} ..." is a JoinedStr. It's only dynamic if it actually
        # contains a {placeholder} (a FormattedValue). f"SELECT 1" is safe.
        if isinstance(node, ast.JoinedStr):
            return any(isinstance(part, ast.FormattedValue) for part in node.values)

        # "..." + something. Safe only if everything being added is constant.
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return not _is_constant_string(node)

        # "... %s ..." % value. Dynamic if the left side is a string
        # and the right side isn't a plain constant.
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            left_is_str = isinstance(node.left, ast.Constant) and isinstance(node.left.value, str)
            return left_is_str and not isinstance(node.right, ast.Constant)

        # "... {} ...".format(value). Dynamic if any argument isn't a constant.
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
            and isinstance(node.func.value, ast.Constant)
            and isinstance(node.func.value.value, str)
        ):
            args_dynamic = any(not isinstance(a, ast.Constant) for a in node.args)
            kwargs_dynamic = any(not isinstance(k.value, ast.Constant) for k in node.keywords)
            return args_dynamic or kwargs_dynamic

        # A variable we already marked as dynamic earlier in the file
        if isinstance(node, ast.Name):
            return node.id in self.dynamic_names

        # Anything else (plain constants, function calls, etc.) isn't flagged
        return False

    # ---- visitors ----

    def visit_Assign(self, node: ast.Assign) -> None:
        """query = <something>: remember whether query is now dynamic."""
        dynamic = self._is_dynamic(node.value)
        for target in node.targets:
            # Only simple names (query = ...), not things like obj.attr = ...
            if isinstance(target, ast.Name):
                if dynamic:
                    self.dynamic_names.add(target.id)
                else:
                    # Reassigned to something safe, so stop tracking it
                    self.dynamic_names.discard(target.id)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        """query += something: if we append a non-constant, query is dynamic."""
        if (
            isinstance(node.op, ast.Add)
            and isinstance(node.target, ast.Name)
            and not _is_constant_string(node.value)
        ):
            self.dynamic_names.add(node.target.id)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Give each function its own copy of the tracking set.

        Without this, a variable called "query" built dynamically in one
        function would cause false alarms in another function's "query".
        """
        outer = self.dynamic_names
        self.dynamic_names = set(outer) # copy so edits inside don't leak out
        self.generic_visit(node)
        self.dynamic_names = outer # restore when the function ends

    # async def functions need the exact same treatment
    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node: ast.Call) -> None:
        """Check every call; if it's something.execute(<dynamic>), report it."""
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in EXECUTE_METHODS
            and node.args # needs at least a query argument
            and self._is_dynamic(node.args[0]) # first arg = the SQL text
        ):
            self.report(
                node,
                "SQL query built with string formatting or concatenation; "
                "use parameterized queries, e.g. cursor.execute(sql, params)",
            )
        # Keep walking so nested calls are checked too
        self.generic_visit(node)