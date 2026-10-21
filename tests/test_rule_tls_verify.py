# Tests for VS006.

from vulnscout.rules.tls_verify import TlsVerificationRule
from vulnscout.scanner import scan_file


def scan_code(tmp_path, code):
    """Helper: write code to a temp file and scan it with only VS006."""
    f = tmp_path / "sample.py"
    f.write_text(code)
    return scan_file(f, [TlsVerificationRule])


# vulnerable

def test_flags_requests_verify_false(tmp_path):
    code = 'import requests\nrequests.get(url, verify=False)\n'
    findings = scan_code(tmp_path, code)
    assert len(findings) == 1
    assert findings[0].rule_id == "VS006"
    assert findings[0].line == 2


def test_flags_session_method(tmp_path):
    # We can't resolve "session", but the verify=False keyword gives it away
    assert len(scan_code(tmp_path, "session.post(url, verify=False)\n")) == 1


def test_flags_unverified_context(tmp_path):
    assert len(scan_code(tmp_path, "import ssl\nssl._create_unverified_context()\n")) == 1


def test_flags_unverified_context_alias(tmp_path):
    code = "from ssl import _create_unverified_context as make_ctx\nmake_ctx()\n"
    assert len(scan_code(tmp_path, code)) == 1


# safe

def test_verify_true_is_safe(tmp_path):
    assert scan_code(tmp_path, "requests.get(url, verify=True)\n") == []


def test_no_verify_argument_is_safe(tmp_path):
    assert scan_code(tmp_path, "requests.get(url)\n") == []


def test_ca_bundle_path_is_safe(tmp_path):
    # verify can be a path to a custom CA bundle, which is a good practice
    assert scan_code(tmp_path, 'requests.get(url, verify="ca.pem")\n') == []


def test_default_context_is_safe(tmp_path):
    assert scan_code(tmp_path, "import ssl\nssl.create_default_context()\n") == []