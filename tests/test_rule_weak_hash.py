# Tests for VS005.

from vulnscout.rules.weak_hash import WeakHashRule
from vulnscout.scanner import scan_file


def scan_code(tmp_path, code):
    """Helper: write code to a temp file and scan it with only VS005."""
    f = tmp_path / "sample.py"
    f.write_text(code)
    return scan_file(f, [WeakHashRule])


# vulnerable: each should produce one finding  

def test_flags_md5(tmp_path):
    findings = scan_code(tmp_path, "import hashlib\nh = hashlib.md5(data)\n")
    assert len(findings) == 1
    assert findings[0].rule_id == "VS005"
    assert findings[0].line == 2


def test_flags_sha1(tmp_path):
    assert len(scan_code(tmp_path, "import hashlib\nhashlib.sha1(data)\n")) == 1


def test_flags_new_with_weak_name(tmp_path):
    assert len(scan_code(tmp_path, 'import hashlib\nhashlib.new("md5", data)\n')) == 1


def test_flags_new_case_insensitive(tmp_path):
    assert len(scan_code(tmp_path, 'import hashlib\nhashlib.new("SHA1", data)\n')) == 1


def test_flags_from_import_alias(tmp_path):
    code = "from hashlib import md5 as quick\nquick(data)\n"
    assert len(scan_code(tmp_path, code)) == 1


def test_flags_module_alias(tmp_path):
    code = "import hashlib as hl\nhl.sha1(data)\n"
    assert len(scan_code(tmp_path, code)) == 1


# ---- safe: none of these should be flagged ----

def test_sha256_is_safe(tmp_path):
    assert scan_code(tmp_path, "import hashlib\nhashlib.sha256(data)\n") == []


def test_new_with_strong_name_is_safe(tmp_path):
    assert scan_code(tmp_path, 'import hashlib\nhashlib.new("sha256", data)\n') == []


def test_usedforsecurity_false_is_safe(tmp_path):
    code = "import hashlib\nhashlib.md5(data, usedforsecurity=False)\n"
    assert scan_code(tmp_path, code) == []


def test_own_function_named_md5_is_safe(tmp_path):
    # No hashlib import, so this md5 is just the user's own function
    code = "def md5(x):\n    return x\n\nmd5('a')\n"
    assert scan_code(tmp_path, code) == []