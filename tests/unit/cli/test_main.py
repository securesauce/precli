# Copyright 2024 Secure Sauce LLC
# SPDX-License-Identifier: BUSL-1.1
import json
import os
import tempfile

import pytest

import precli
from precli.cli import main


class TestMain:
    def test_main_target_not_found(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["precli", "missing_file.py"])
        with pytest.raises(SystemExit) as excinfo:
            main.main()
        assert excinfo.value.code == 2

    def test_main_enable_and_disable(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "sys.argv",
            ["precli", "--enable", "PY001", "--disable", "PY004"],
        )
        with pytest.raises(SystemExit) as excinfo:
            main.main()
        assert excinfo.value.code == 2
        captured = capsys.readouterr()
        assert "not allowed with argument" in captured.err

    def test_main_config_not_found(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["precli", "-c", "missing_file.toml"])
        with pytest.raises(SystemExit) as excinfo:
            main.main()
        assert excinfo.value.code == 2

    def test_main_invalid_config(self, monkeypatch, capsys):
        temp_dir = tempfile.mkdtemp()
        config_path = os.path.join(temp_dir, "not_toml.toml")
        config = {"enable": ["PY001"]}
        with open(config_path, "w") as fd:
            json.dump(config, fd)

        monkeypatch.setattr("sys.argv", ["precli", "-c", config_path, "."])
        with pytest.raises(SystemExit) as excinfo:
            main.main()
        assert excinfo.value.code == 2
        captured = capsys.readouterr()
        assert "argument -c/--config: can't load" in captured.err

    def test_main_invalid_output(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["precli", "-o", "../does/not/exist"])
        with pytest.raises(SystemExit) as excinfo:
            main.main()
        assert excinfo.value.code == 2

    def test_main_output_already_exists(self, monkeypatch, capsys):
        temp_dir = tempfile.mkdtemp()
        output_path = os.path.join(temp_dir, "output.txt")
        with open(output_path, "w") as fd:
            fd.write("This file already exists. Do not overwrite.")

        monkeypatch.setattr("sys.argv", ["precli", ".", "-o", output_path])
        with pytest.raises(SystemExit) as excinfo:
            main.main()
        assert excinfo.value.code == 2
        captured = capsys.readouterr()
        assert "[Errno 17] File exists" in captured.err

    def test_main_more_than_one_renderer(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.argv", ["precli", "--json", "--markdown"])
        with pytest.raises(SystemExit) as excinfo:
            main.main()
        assert excinfo.value.code == 2
        captured = capsys.readouterr()
        assert "not allowed with argument" in captured.err

    def test_main_gist_no_github_token(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.argv", ["precli", ".", "--gist"])
        with pytest.raises(SystemExit) as excinfo:
            main.main()
        assert excinfo.value.code == 2
        captured = capsys.readouterr()
        assert "environment variable GITHUB_TOKEN undefined" in captured.err

    def test_main_recursive_flag(self, monkeypatch):
        temp_dir = tempfile.mkdtemp()
        nested_dir = os.path.join(temp_dir, "nested")
        os.makedirs(nested_dir)
        with open(os.path.join(nested_dir, "test_file.py"), "w") as f:
            f.write("print('test')")

        monkeypatch.setattr("sys.argv", ["precli", "--recursive", temp_dir])
        with pytest.raises(SystemExit) as excinfo:
            main.main()
        assert excinfo.value.code == 0

    def test_main_exit_code_0(self, monkeypatch):
        temp_dir = tempfile.mkdtemp()
        monkeypatch.setattr("sys.argv", ["precli", temp_dir])
        with pytest.raises(SystemExit) as excinfo:
            main.main()
        assert excinfo.value.code == 0

    def test_main_version(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.argv", ["precli", "--version"])
        with pytest.raises(SystemExit) as excinfo:
            main.main()
        assert excinfo.value.code == 0
        captured = capsys.readouterr()
        assert f"precli {precli.__version__}" in captured.out
