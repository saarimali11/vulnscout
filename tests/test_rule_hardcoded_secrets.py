# Tests for VS004. The fake credentials are built by joining two strings
# ("AKIA" + "...") so GitHub's secret scanner doesn't mistake this test
# file for a real leak and block the push.

from vulnscout.rules.hardcoded_secrets import HardcodedSecretsRule, shannon_entropy
from vulnscout.scanner import scan_file

# A fake AWS-style key: "AKIA" followed by exactly 16 uppercase characters
FAKE_AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"


def scan_code(tmp_path, code):
    """Helper: write code to a temp file and scan it with only VS004."""
    f = tmp_path / "sample.py"
    f.write_text(code)
    return scan_file(f, [HardcodedSecretsRule])


# vulnerable patterns: each should produce exactly one finding  

def test_flags_password_assignment(tmp_path):
    findings = scan_code(tmp_path, 'password = "hunter2"\n')
    assert len(findings) == 1
    assert findings[0].rule_id == "VS004"
    assert findings[0].line == 1


def test_flags_camel_case_name(tmp_path):
    assert len(scan_code(tmp_path, 'apiKey = "abc12345"\n')) == 1


def test_flags_uppercase_constant(tmp_path):
    assert len(scan_code(tmp_path, 'API_KEY = "abc12345"\n')) == 1


def test_flags_attribute_target(tmp_path):
    assert len(scan_code(tmp_path, 'self.password = "hunter2"\n')) == 1


def test_flags_subscript_target(tmp_path):
    assert len(scan_code(tmp_path, 'config["password"] = "hunter2"\n')) == 1


def test_flags_annotated_assignment(tmp_path):
    assert len(scan_code(tmp_path, 'password: str = "hunter2"\n')) == 1


def test_flags_dict_key(tmp_path):
    assert len(scan_code(tmp_path, 'cfg = {"db_password": "letmein123"}\n')) == 1


def test_flags_keyword_argument(tmp_path):
    code = 'connect(user="admin", password="letmein123")\n'
    assert len(scan_code(tmp_path, code)) == 1


def test_flags_known_token_pattern(tmp_path):
    # The variable name is harmless, so only the pattern check can catch this
    code = f'config = "{FAKE_AWS_KEY}"\n'
    findings = scan_code(tmp_path, code)
    assert len(findings) == 1
    assert "AWS" in findings[0].message


def test_flags_private_key_header(tmp_path):
    header = "-----BEGIN RSA " + "PRIVATE KEY-----"
    assert len(scan_code(tmp_path, f'x = "{header}"\n')) == 1


def test_flags_high_entropy_string(tmp_path):
    # 32 different characters = 5.0 bits per character
    code = 'blob = "Zk3vQ9xT7pLw2RmN8cYb5HdJ4fGs6AeU"\n'
    assert len(scan_code(tmp_path, code)) == 1


def test_one_finding_per_secret(tmp_path):
    # Name AND pattern both match here, but we want a single finding
    code = f'secret_key = "{FAKE_AWS_KEY}"\n'
    assert len(scan_code(tmp_path, code)) == 1


# safe patterns: none of these should be flagged  

def test_empty_and_placeholder_values_are_safe(tmp_path):
    for value in ["", "changeme", "<your-password>", "${DB_PASS}",
                  "your_password_here", "xxxxxxxx"]:
        assert scan_code(tmp_path, f'password = "{value}"\n') == [], value


def test_environment_lookup_is_safe(tmp_path):
    code = 'import os\npassword = os.environ["DB_PASSWORD"]\n'
    assert scan_code(tmp_path, code) == []


def test_non_string_values_are_safe(tmp_path):
    assert scan_code(tmp_path, "max_tokens = 100\nsecret = None\n") == []


def test_similar_names_are_not_flagged(tmp_path):
    # Whole-word matching: none of these contain a secret word on its own
    code = 'tokenizer = "gpt2"\nkeyboard = "qwerty"\nusername = "saarim"\n'
    assert scan_code(tmp_path, code) == []


def test_plain_sentence_is_safe(tmp_path):
    # Long, but it has spaces, so it's text and not a token
    code = 'msg = "The quick brown fox jumps over the lazy dog again"\n'
    assert scan_code(tmp_path, code) == []


def test_hex_hash_is_safe(tmp_path):
    # A sha256 hash is long but hex-only, so its entropy stays at or under 4.0
    sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    assert scan_code(tmp_path, f'checksum = "{sha}"\n') == []


def test_shannon_entropy_values():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0 # no randomness at all
    assert shannon_entropy("ab") == 1.0 # two equally likely characters = 1 bit