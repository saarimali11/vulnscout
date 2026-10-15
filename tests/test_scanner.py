# Tests for the scanning logic. pytest runs any function starting with "test_".
# tmp_path is a built-in pytest fixture that gives each test its own empty temp folder.

from vulnscout.models import Severity
from vulnscout.rules import Rule
from vulnscout.scanner import iter_python_files, scan_file


# A fake rule used only for testing. It flags every "pass" statement,
# which lets us test the scanner without needing real rules yet.
class PassRule(Rule):
    id = "TEST001"
    owasp = "A00"
    severity = Severity.LOW

    # Runs once for every "pass" in the code being scanned
    def visit_Pass(self, node):
        self.report(node, "pass statement found")


def test_scan_file_reports_findings(tmp_path):
    # Write a small Python file into the temp folder
    f = tmp_path / "a.py"
    f.write_text("def x():\n    pass\n")

    findings = scan_file(f, [PassRule])

    # Exactly one "pass" exists, on line 2
    assert len(findings) == 1
    assert findings[0].line == 2
    assert findings[0].rule_id == "TEST001"


def test_syntax_error_is_skipped(tmp_path):
    # "def (:" is invalid Python. The scanner should skip it, not crash.
    f = tmp_path / "bad.py"
    f.write_text("def (:\n")
    assert scan_file(f, [PassRule]) == []


def test_ignored_dirs_are_skipped(tmp_path):
    # Make a fake .venv folder with a file inside it
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "lib.py").write_text("x = 1\n")
    (tmp_path / "ok.py").write_text("x = 1\n")

    # Only ok.py should be found; the .venv file must be ignored
    assert [p.name for p in iter_python_files(tmp_path)] == ["ok.py"]