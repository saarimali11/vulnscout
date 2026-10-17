# Tests for VS001. Each test writes a tiny Python snippet to a temp file,
# scans it, and checks what the rule reports.

from vulnscout.cli import main
from vulnscout.rules.eval_exec import EvalExecRule
from vulnscout.scanner import scan_file


def scan_code(tmp_path, code):
    """Helper: write code to a temp file and scan it with only VS001."""
    f = tmp_path / "sample.py"
    f.write_text(code)
    return scan_file(f, [EvalExecRule])


def test_flags_eval(tmp_path):
    findings = scan_code(tmp_path, "x = eval(user_input)\n")
    assert len(findings) == 1
    assert findings[0].rule_id == "VS001"
    assert findings[0].line == 1


def test_flags_exec(tmp_path):
    findings = scan_code(tmp_path, "exec(code)\n")
    assert len(findings) == 1


def test_literal_eval_is_safe(tmp_path):
    # ast.literal_eval only parses plain data, so it must NOT be flagged
    code = "import ast\nx = ast.literal_eval(text)\n"
    assert scan_code(tmp_path, code) == []


def test_method_named_eval_is_ignored(tmp_path):
    # model.eval() is a method call (common in PyTorch), not the builtin
    assert scan_code(tmp_path, "model.eval()\n") == []


def test_nested_calls_both_flagged(tmp_path):
    # This only works because the rule calls generic_visit()
    findings = scan_code(tmp_path, 'eval(eval("1"))\n')
    assert len(findings) == 2


def test_cli_exits_one_when_findings(tmp_path, capsys):
    f = tmp_path / "bad.py"
    f.write_text('eval("1+1")\n')
    # Exit code 1 = findings were found (what CI uses to fail a build)
    assert main(["scan", str(f)]) == 1
    # The rule ID should show up in the printed report
    assert "VS001" in capsys.readouterr().out