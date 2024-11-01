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
    def test_main_invalid_output(self, monkeypatch):
        monkeypatch.setattr(
            "sys.argv",
            ["precli-init", "-o", "../does/not/exist"],
        )
        with pytest.raises(SystemExit) as excinfo:
            init.main()
        assert excinfo.value.code == 2

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
