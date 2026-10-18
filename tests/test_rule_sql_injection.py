# Tests for VS003. For each way of building a query, we check the
# vulnerable version IS flagged and the safe version is NOT.

from vulnscout.rules.sql_injection import SqlInjectionRule
from vulnscout.scanner import scan_file


def scan_code(tmp_path, code):
    """Helper: write code to a temp file and scan it with only VS003."""
    f = tmp_path / "sample.py"
    f.write_text(code)
    return scan_file(f, [SqlInjectionRule])


# vulnerable patterns: each should produce exactly one finding 

def test_flags_fstring_query(tmp_path):
    findings = scan_code(tmp_path, 'cur.execute(f"SELECT * FROM t WHERE a = {x}")\n')
    assert len(findings) == 1
    assert findings[0].rule_id == "VS003"
    assert findings[0].line == 1


def test_flags_concatenation(tmp_path):
    code = 'cur.execute("SELECT * FROM t WHERE a = \'" + x + "\'")\n'
    assert len(scan_code(tmp_path, code)) == 1


def test_flags_percent_formatting(tmp_path):
    code = 'cur.execute("SELECT * FROM t WHERE a = \'%s\'" % x)\n'
    assert len(scan_code(tmp_path, code)) == 1


def test_flags_dot_format(tmp_path):
    code = 'cur.execute("SELECT * FROM t WHERE a = \'{}\'".format(x))\n'
    assert len(scan_code(tmp_path, code)) == 1



def test_flags_executemany(tmp_path):
    code = 'cur.executemany(f"INSERT INTO t VALUES ({x})", rows)\n'
    assert len(scan_code(tmp_path, code)) == 1


def test_flags_query_variable_built_dynamically(tmp_path):
    # The query is built on one line and executed on another
    code = 'q = "SELECT * FROM t WHERE a = " + x\ncur.execute(q)\n'
    findings = scan_code(tmp_path, code)
    assert len(findings) == 1
    assert findings[0].line == 2 # reported where it's executed


def test_flags_augmented_assignment(tmp_path):
    # query += user_value makes the query dynamic
    code = 'q = "SELECT * FROM t WHERE a = "\nq += x\ncur.execute(q)\n'
    assert len(scan_code(tmp_path, code)) == 1


# safe patterns: none of these should be flagged

def test_parameterized_query_is_safe(tmp_path):
    code = 'cur.execute("SELECT * FROM t WHERE a = ?", (x,))\n'
    assert scan_code(tmp_path, code) == []


def test_constant_concatenation_is_safe(tmp_path):
    # Joining two fixed strings never involves user input
    code = 'cur.execute("SELECT * " + "FROM t")\n'
    assert scan_code(tmp_path, code) == []


def test_fstring_without_placeholders_is_safe(tmp_path):
    assert scan_code(tmp_path, 'cur.execute(f"SELECT 1")\n') == []


def test_constant_variable_is_safe(tmp_path):
    code = 'q = "SELECT 1"\ncur.execute(q)\n'
    assert scan_code(tmp_path, code) == []


def test_non_execute_call_is_ignored(tmp_path):
    # Building a string and printing it is not a SQL problem
    assert scan_code(tmp_path, 'print(f"hello {x}")\n') == []


def test_function_scopes_are_separate(tmp_path):
    # "q" is dynamic inside a(), but b() has its own safe "q".
    # Without per-function tracking, b() would be a false positive.
    code = (
        "def a(x):\n"
        "    q = f'SELECT {x}'\n"
        "\n"
        "def b():\n"
        "    q = 'SELECT 1'\n"
        "    cur.execute(q)\n"
    )
    assert scan_code(tmp_path, code) == []