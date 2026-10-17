# Tests for VS002: both the vulnerable and the safe patterns.

from vulnscout.rules.shell_injection import ShellInjectionRule
from vulnscout.scanner import scan_file


def scan_code(tmp_path, code):
    """Helper: write code to a temp file and scan it with only VS002."""
    f = tmp_path / "sample.py"
    f.write_text(code)
    return scan_file(f, [ShellInjectionRule])


def test_flags_subprocess_run_shell_true(tmp_path):
    code = 'import subprocess\nsubprocess.run("ls " + name, shell=True)\n'
    findings = scan_code(tmp_path, code)
    assert len(findings) == 1
    assert findings[0].rule_id == "VS002"
    assert findings[0].line == 2


def test_flags_popen_shell_true(tmp_path):
    code = 'import subprocess\nsubprocess.Popen(cmd, shell=True)\n'
    assert len(scan_code(tmp_path, code)) == 1


def test_shell_false_is_safe(tmp_path):
    code = 'import subprocess\nsubprocess.run(["ls"], shell=False)\n'
    assert scan_code(tmp_path, code) == []


def test_list_args_without_shell_is_safe(tmp_path):
    # This is the recommended way, so it must not be flagged
    code = 'import subprocess\nsubprocess.run(["ls", "-l", path])\n'
    assert scan_code(tmp_path, code) == []


def test_flags_os_system(tmp_path):
    code = 'import os\nos.system("echo " + name)\n'
    assert len(scan_code(tmp_path, code)) == 1


def test_flags_os_popen(tmp_path):
    code = 'import os\nos.popen(cmd)\n'
    assert len(scan_code(tmp_path, code)) == 1