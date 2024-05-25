# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
from base64 import b64encode
from zipfile import ZipFile

from bugsy import Attachment, Bug, BugsyException
from pytest import mark
from requests.exceptions import ConnectionError as RequestsConnectionError

from .bugzilla import BugzillaBug


def test_bugzilla_01(mocker):
    """test BugzillaBug._fetch_attachments()"""
    bug = mocker.Mock(spec=Bug, id=123)
    bug.get_attachments.return_value = (
        # ignored obsolete
        mocker.Mock(spec=Attachment, is_obsolete=True),
        # ignored content type
        mocker.Mock(
            spec=Attachment,
            is_obsolete=False,
            content_type="text/x-phabricator-request",
        ),
        # ignored file extension
        mocker.Mock(
            spec=Attachment,
            is_obsolete=False,
            content_type="text/plain",
            file_name="ignore.txt",
        ),
        # valid test case
        mocker.Mock(
            spec=Attachment,
            is_obsolete=False,
            content_type="text/html",
            file_name="test.html",
            data=b64encode(b"foo"),
        ),
        # corrupted data
        mocker.Mock(
            spec=Attachment,
            is_obsolete=False,
            content_type="text/html",
            file_name="broken.html",
            data=b"bad-b64",
        ),
    )
    with BugzillaBug(bug) as bz_bug:
        assert len(tuple(bz_bug._data.iterdir())) == 1
        assert (bz_bug._data / "test.html").is_file()
        assert (bz_bug._data / "test.html").read_text() == "foo"


@mark.parametrize(
    "exc",
    [
        BugsyException("foo", error_code=101),
        BugsyException("access denied", error_code=102),
        RequestsConnectionError(),
    ],
)
def test_bugzilla_02(mocker, exc):
    """test BugzillaBug.load() - errors"""
    bugsy = mocker.patch("grizzly.common.bugzilla.Bugsy", autospec=True)
    bugsy.return_value.get.side_effect = exc
    bugsy.return_value.bugzilla_url = "foo"
    assert BugzillaBug.load(123) is None


def test_bugzilla_03(mocker):
    """test BugzillaBug.load()"""
    bugsy = mocker.patch("grizzly.common.bugzilla.Bugsy", autospec=True)
    bugsy.return_value.get.return_value = mocker.MagicMock(spec=Bug, id=123)
    with BugzillaBug.load(123):
        pass


def test_bugzilla_04(mocker):
    """test BugzillaBug.assets()"""
    bug = mocker.Mock(spec=Bug, id=123)
    bug.get_attachments.return_value = []
    with BugzillaBug(bug) as bz_bug:
        (bz_bug._data / "prefs.js").touch()
        (bz_bug._data / "test.html").touch()
        # load prefs.js asset
        results = tuple(bz_bug.assets())
        assert len(results) == 1
        assert results[0] == ("prefs", bz_bug._data / "prefs.js")
        # load ignore prefs.js asset
        assert not any(bz_bug.assets(ignore=["prefs"]))


@mark.parametrize("archive_count", [0, 1, 2])
def test_bugzilla_05(mocker, tmp_path, archive_count):
    """test BugzillaBug._unpack_archive()"""
    (tmp_path / "test.html").write_text("foo")
    bug = mocker.Mock(spec=Bug, id=123)
    bug.get_attachments.return_value = []
    with BugzillaBug(bug) as bz_bug:
        (bz_bug._data / "not_archive.txt").touch()
        for num in range(archive_count):
            with ZipFile(bz_bug._data / f"archive{num:02d}.zip", "w") as zfp:
                zfp.write(tmp_path / "test.html", arcname="test.html")
        bz_bug._unpack_archives()
        results = tuple(x for x in bz_bug._data.iterdir() if x.is_dir())
        assert len(results) == archive_count
        for num in range(archive_count):
            assert not (bz_bug._data / f"archive{num:02d}.zip").is_file()
        for path in results:
            assert (path / "test.html").is_file()


@mark.parametrize(
    "files, count",
    [
        # no files
        ((), 0),
        # single test case
        (("test.html",), 1),
        # multiple test cases (add the path and both files individually)
        (("a.html", "b.html"), 3),
        # test case and asset
        (("prefs.js", "test.html"), 1),
        # test loading archive
        (("archive.zip",), 1),
        # test loading archive and standalone test
        (("archive.zip", "test.html"), 2),
    ],
)
def test_bugzilla_06(mocker, tmp_path, files, count):
    """test BugzillaBug.testcases()"""
    (tmp_path / "test.html").write_text("foo")
    bug = mocker.Mock(spec=Bug, id=123)
    bug.get_attachments.return_value = []
    with BugzillaBug(bug) as bz_bug:
        for file in files:
            if file.endswith("zip"):
                with ZipFile(bz_bug._data / file, "w") as zfp:
                    zfp.write(tmp_path / "test.html", arcname="test.html")
            else:
                (bz_bug._data / file).touch()
        assert len(bz_bug.testcases()) == count
