# Tests for VS007. Vulnerable patterns first, then safe ones.

from vulnscout.rules.unsafe_deserialization import UnsafeDeserializationRule
from vulnscout.scanner import scan_file


def scan_code(tmp_path, code):
    """Helper: write code to a temp file and scan it with only VS007."""
    f = tmp_path / "sample.py"
    f.write_text(code)
    return scan_file(f, [UnsafeDeserializationRule])


# always unsafe loaders  

def test_flags_pickle_load(tmp_path):
    findings = scan_code(tmp_path, "import pickle\nobj = pickle.load(f)\n")
    assert len(findings) == 1
    assert findings[0].rule_id == "VS007"
    assert findings[0].line == 2

def test_flags_pickle_loads(tmp_path):
    assert len(scan_code(tmp_path, "import pickle\npickle.loads(data)\n")) == 1

def test_flags_from_import_alias(tmp_path):
    code = "from pickle import loads as unpack\nunpack(data)\n"
    assert len(scan_code(tmp_path, code)) == 1

def test_flags_unpickler(tmp_path):
    assert len(scan_code(tmp_path, "import pickle\npickle.Unpickler(f)\n")) == 1

def test_flags_marshal(tmp_path):
    assert len(scan_code(tmp_path, "import marshal\nmarshal.loads(data)\n")) == 1


def test_flags_shelve_open(tmp_path):
    assert len(scan_code(tmp_path, 'import shelve\nshelve.open("cache")\n')) == 1


def test_flags_dill(tmp_path):
    assert len(scan_code(tmp_path, "import dill\ndill.loads(data)\n")) == 1


def test_flags_pandas_read_pickle_alias(tmp_path):
    code = 'import pandas as pd\ndf = pd.read_pickle("df.pkl")\n'
    assert len(scan_code(tmp_path, code)) == 1


# yaml: unsafe

def test_flags_yaml_load_without_loader(tmp_path):
    assert len(scan_code(tmp_path, "import yaml\nyaml.load(text)\n")) == 1


def test_flags_yaml_unsafe_loader_keyword(tmp_path):
    code = "import yaml\nyaml.load(text, Loader=yaml.Loader)\n"
    assert len(scan_code(tmp_path, code)) == 1


def test_flags_yaml_unsafe_loader_positional(tmp_path):
    code = "import yaml\nyaml.load(text, yaml.UnsafeLoader)\n"
    assert len(scan_code(tmp_path, code)) == 1


def test_flags_yaml_unsafe_load(tmp_path):
    assert len(scan_code(tmp_path, "import yaml\nyaml.unsafe_load(text)\n")) == 1


def test_flags_yaml_load_all(tmp_path):
    assert len(scan_code(tmp_path, "import yaml\nyaml.load_all(text)\n")) == 1


# yaml: safe

def test_yaml_safe_load_is_safe(tmp_path):
    assert scan_code(tmp_path, "import yaml\nyaml.safe_load(text)\n") == []

def test_yaml_safe_loader_keyword_is_safe(tmp_path):
    code = "import yaml\nyaml.load(text, Loader=yaml.SafeLoader)\n"
    assert scan_code(tmp_path, code) == []


def test_yaml_safe_loader_from_import_is_safe(tmp_path):
    code = "from yaml import load, SafeLoader\nload(text, Loader=SafeLoader)\n"
    assert scan_code(tmp_path, code) == []


def test_yaml_safe_loader_positional_is_safe(tmp_path):
    code = "import yaml\nyaml.load(text, yaml.SafeLoader)\n"
    assert scan_code(tmp_path, code) == []


def test_yaml_csafe_loader_is_safe(tmp_path):
    code = "import yaml\nyaml.load(text, Loader=yaml.CSafeLoader)\n"
    assert scan_code(tmp_path, code) == []


# numpy 

def test_flags_numpy_allow_pickle_true(tmp_path):
    code = "import numpy as np\nnp.load(p, allow_pickle=True)\n"
    assert len(scan_code(tmp_path, code)) == 1

def test_numpy_default_is_safe(tmp_path):
    assert scan_code(tmp_path, "import numpy as np\nnp.load(p)\n") == []

def test_numpy_allow_pickle_false_is_safe(tmp_path):
    code = "import numpy as np\nnp.load(p, allow_pickle=False)\n"
    assert scan_code(tmp_path, code) == []


# other safe patterns

def test_json_is_safe(tmp_path):
    assert scan_code(tmp_path, "import json\njson.loads(text)\njson.load(f)\n") == []

def test_pickle_dumps_is_safe(tmp_path):
    # Writing a pickle isn't the risk but loading untrusted ones is
    assert scan_code(tmp_path, "import pickle\npickle.dumps(obj)\n") == []


def test_own_function_named_load_is_safe(tmp_path):
    # No pickle import, so this "load" is just the user's own function
    code = "def load(x):\n    return x\n\nload(data)\n"
    assert scan_code(tmp_path, code) == []