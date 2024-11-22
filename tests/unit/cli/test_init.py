# Copyright 2024 Secure Sauce LLC
# SPDX-License-Identifier: BUSL-1.1
import os
import tempfile
from unittest import mock

import pytest
import tomli_w

from precli.cli import init


class TestInit:
    @classmethod
    def test_main_output_already_exists(self, monkeypatch, capsys):
        temp_dir = tempfile.mkdtemp()
        output_path = os.path.join(temp_dir, "output.txt")
        with open(output_path, "w") as fd:
            fd.write("This file already exists. Do not overwrite.")

        monkeypatch.setattr("sys.argv", ["precli-init", "-o", output_path])
        with pytest.raises(SystemExit) as excinfo:
            init.main()
        assert excinfo.value.code == 2
        captured = capsys.readouterr()
        assert "[Errno 17] File exists" in captured.err

    def test_main_pyproject_config_already_exists(self, monkeypatch, capsys):
        temp_dir = tempfile.mkdtemp()
        output_path = os.path.join(temp_dir, "pyproject.toml")
        config = {"tool": {"precli": {"rule": {}}}}
        with open(output_path, "wb") as fd:
            tomli_w.dump(config, fd)

        monkeypatch.setattr("sys.argv", ["precli-init", "-o", output_path])
        with pytest.raises(SystemExit) as excinfo:
            init.main()
        assert excinfo.value.code == 2
        captured = capsys.readouterr()
        assert "argument -o/--output: can't write" in captured.err
