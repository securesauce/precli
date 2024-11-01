# Copyright 2024 Secure Sauce LLC
# SPDX-License-Identifier: BUSL-1.1
import json
import os
import tempfile
from io import StringIO
from unittest import mock

import pytest

import precli
from precli.cli import main


class TestMain:
    @classmethod
    def setup_class(cls):
        cls.current_dir = os.getcwd()

    @classmethod
    def teardown_class(cls):
        os.chdir(cls.current_dir)

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

    def test_main_invalid_config(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["precli", "-c", "not_toml.json", "."])
        temp_dir = tempfile.mkdtemp()
        os.chdir(temp_dir)
        config = {
            "enable": ["PY001"]
        }
        with open("not_toml.json", "w") as fd:
            json.dump(config, fd)

        with pytest.raises(SystemExit) as excinfo:
            main.main()
        assert excinfo.value.code == 2

    def test_main_invalid_output(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["precli", "-o", "../does/not/exists"])
        with pytest.raises(SystemExit) as excinfo:
            main.main()
        assert excinfo.value.code == 2

    @mock.patch("builtins.input", lambda _: "no")
    def test_main_output_already_exists(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.argv", ["precli", "-o", "output.txt"])
        temp_dir = tempfile.mkdtemp()
        os.chdir(temp_dir)
        with open("output.txt", "w") as fd:
            fd.write("This file already exists. Do not overwrite.")

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

    def test_main_version(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.argv", ["precli", "--version"])
        with pytest.raises(SystemExit) as excinfo:
            main.main()
        assert excinfo.value.code == 0
        captured = capsys.readouterr()
        assert f"precli {precli.__version__}" in captured.out
