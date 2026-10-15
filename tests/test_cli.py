# Tests for the command-line interface.
# I call main() directly with a list of arguments instead of running a terminal command.

import json

from vulnscout.cli import main


def test_clean_file_exits_zero(tmp_path):
    f = tmp_path / "ok.py"
    f.write_text("x = 1\n")
    # No rules exist yet, so any file is clean and the exit code should be 0
    assert main(["scan", str(f)]) == 0


def test_missing_path_exits_two(tmp_path):
    # A path that doesn't exist should return 2 (bad input)
    assert main(["scan", str(tmp_path / "nope.py")]) == 2


def test_json_output_is_valid(tmp_path, capsys):
    f = tmp_path / "ok.py"
    f.write_text("x = 1\n")
    main(["scan", str(f), "--format", "json"])
    # capsys captures whatever was printed.
    # No findings means the JSON output should be an empty list.
    assert json.loads(capsys.readouterr().out) == []