# Copyright 2024 Secure Sauce LLC
# SPDX-License-Identifier: BUSL-1.1
import json
import os
import tempfile
from unittest import mock

import pytest

from precli.cli import main


class TestMain:
    @classmethod
    def setup_class(cls):
        cls.base_path = os.path.join(
            "tests",
            "unit",
            "cli",
            "examples",
        )
        cls.current_dir = os.getcwd()

    @classmethod
    def teardown_class(cls):
        os.chdir(cls.current_dir)


    @mock.patch("sys.argv", ["precli", "-c", "missing_file.toml"])
    def test_main_config_not_found(self):
        with pytest.raises(SystemExit) as excinfo:
            main.main()
        assert str(excinfo.value) == "2"

    @mock.patch("sys.argv", ["precli", "-c", "not_toml.json", "."])
    def test_main_invalid_config(self):
        temp_dir = tempfile.mkdtemp()
        os.chdir(temp_dir)
        config = {
            "enable": ["PY001"]
        }
        with open("not_toml.json", "w") as fd:
            json.dump(config, fd)

        with pytest.raises(SystemExit) as excinfo:
            main.main()
        assert str(excinfo.value) == "2"

    @mock.patch("sys.argv", ["precli", "-o", "../does/not/exists"])
    def test_main_invalid_output(self):
        with pytest.raises(SystemExit) as excinfo:
            main.main()
        assert str(excinfo.value) == "2"

    @mock.patch("sys.argv", ["precli", "-o", "output.txt"])
    @mock.patch("builtins.input", lambda _: "no")
    def test_main_output_already_exists(self):
        temp_dir = tempfile.mkdtemp()
        os.chdir(temp_dir)
        with open("output.txt", "w") as fd:
            fd.write("This file already exists. Do not overwrite.")

        with pytest.raises(SystemExit) as excinfo:
            main.main()
        assert str(excinfo.value) == "1"
