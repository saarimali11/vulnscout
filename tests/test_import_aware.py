# Tests for the import resolver, plus VS002 catching aliased imports.

import ast

from vulnscout.rules.import_aware import ImportAwareRule
from vulnscout.rules.shell_injection import ShellInjectionRule
from vulnscout.scanner import scan_file


# A tiny throwaway rule that just records what every call resolves to,
# so we can test qualified_name() directly.
class Probe(ImportAwareRule):
    id = "PROBE"

    def __init__(self, path):
        super().__init__(path)
        self.seen = []

    def visit_Call(self, node):
        self.seen.append(self.qualified_name(node.func))
        self.generic_visit(node)


def resolve(code):
    """Parse code and return what each call resolved to, outermost first."""
    probe = Probe("sample.py")
    probe.visit(ast.parse(code))
    return probe.seen


# ---- resolver ----

def test_plain_import(tmp_path):
    assert resolve("import os\nos.system('x')\n") == ["os.system"]


def test_import_alias():
    assert resolve("import os as o\no.system('x')\n") == ["os.system"]


def test_from_import():
    assert resolve("from os import system\nsystem('x')\n") == ["os.system"]


def test_from_import_alias():
    code = "from os import system as run_cmd\nrun_cmd('x')\n"
    assert resolve(code) == ["os.system"]


def test_dotted_import():
    # "import os.path" binds the name "os", so os.path.join resolves fully
    assert resolve("import os.path\nos.path.join('a', 'b')\n") == ["os.path.join"]


def test_unimported_name_stays_as_is():
    assert resolve("foo.bar()\n") == ["foo.bar"]


def test_import_after_use_still_resolves():
    # Imports are collected up front, so order in the file doesn't matter
    code = "def f():\n    os.system('x')\n\nimport os\n"
    assert resolve(code) == ["os.system"]


def test_method_on_call_result_is_unresolved():
    # a().b(): the outer call can't be resolved (None), the inner one is "a"
    assert resolve("a().b()\n") == [None, "a"]


# ---- VS002 now catches aliased imports ----

def scan_code(tmp_path, code):
    f = tmp_path / "sample.py"
    f.write_text(code)
    return scan_file(f, [ShellInjectionRule])


def test_from_import_run_is_flagged(tmp_path):
    code = 'from subprocess import run\nrun("ls " + x, shell=True)\n'
    assert len(scan_code(tmp_path, code)) == 1


def test_module_alias_is_flagged(tmp_path):
    code = "import subprocess as sp\nsp.run(cmd, shell=True)\n"
    assert len(scan_code(tmp_path, code)) == 1


def test_from_import_os_system_is_flagged(tmp_path):
    assert len(scan_code(tmp_path, "from os import system\nsystem(cmd)\n")) == 1


def test_own_function_named_run_is_not_flagged(tmp_path):
    # No import of subprocess anywhere, so "run" is just the user's own function
    code = "def run(cmd, shell=False):\n    pass\n\nrun('ls', shell=True)\n"
    assert scan_code(tmp_path, code) == []