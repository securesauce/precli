# Copyright 2024 Secure Sauce LLC
# SPDX-License-Identifier: BUSL-1.1
import json
import os
import tempfile
from unittest import mock

import pytest

from precli.cli import init


class TestInit:
    @classmethod
    def setup_class(cls):
        cls.current_dir = os.getcwd()

    @classmethod
    def teardown_class(cls):
        os.chdir(cls.current_dir)

    def test_main_invalid_output(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["precli-init", "-o", "../does/not/exists"])
        with pytest.raises(SystemExit) as excinfo:
            init.main()
        assert excinfo.value.code == 2

    @mock.patch("builtins.input", lambda _: "no")
    def test_main_output_already_exists(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["precli-init", "-o", "output.txt"])
        temp_dir = tempfile.mkdtemp()
        os.chdir(temp_dir)
        with open("output.txt", "w") as fd:
            fd.write("This file already exists. Do not overwrite.")

        with pytest.raises(SystemExit) as excinfo:
            init.main()
        assert excinfo.value.code == 1
