# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Common unit test fixtures for `grizzly.replay`."""

from itertools import count
from pathlib import Path

from pytest import fixture

from sapphire import Sapphire

from ..common.report import Report


@fixture
def server(mocker):
    """Mock Sapphire server"""
    srv = mocker.Mock(spec_set=Sapphire, port=1337, timeout=10)
    srv_cls = mocker.patch("grizzly.replay.main.Sapphire", autospec=True)
    srv_cls.return_value.__enter__.return_value = srv
    return srv


@fixture
def fake_create_report(tmp_path):
    """Factory fixture that creates Reports from fake log data in tmp_path."""
    _counter = count()

    def _create(is_hang=False, unstable=False):
        log_path = tmp_path / f"logs_{next(_counter)}"
        log_path.mkdir()
        (log_path / "log_stderr.txt").write_text("STDERR log\n")
        (log_path / "log_stdout.txt").write_text("STDOUT log\n")
        with (log_path / "log_asan_blah.txt").open("w") as log_fp:
            log_fp.write("==1==ERROR: AddressSanitizer: ")
            log_fp.write("SEGV on unknown address 0x0 (pc 0x0 bp 0x0 sp 0x0 T0)\n")
            log_fp.write("    #0 0xbad000 in foo /file1.c:123:234\n")
            log_fp.write("    #1 0x1337dd in bar /file2.c:1806:19\n")
        return Report(log_path, Path("bin"), is_hang=is_hang, unstable=unstable)

    return _create
