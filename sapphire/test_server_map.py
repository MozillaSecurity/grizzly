# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import pytest

from .server_map import InvalidURLError, MapCollisionError, Resource, ServerMap


def test_servermap_01():
    """test empty ServerMap"""
    srv_map = ServerMap()
    assert not srv_map.dynamic
    assert not srv_map.include
    assert not srv_map.redirect


def test_servermap_02(tmp_path):
    """test ServerMap dynamic responses"""
    srv_map = ServerMap()
    srv_map.set_dynamic_response("url_01", lambda _: 0, mime_type="test/type")
    assert len(srv_map.dynamic) == 1
    assert "url_01" in srv_map.dynamic
    assert srv_map.dynamic["url_01"].mime == "test/type"
    assert callable(srv_map.dynamic["url_01"].target)
    assert srv_map.dynamic["url_01"].type == Resource.URL_DYNAMIC
    srv_map.set_dynamic_response("url_02", lambda _: 0, mime_type="foo")
    assert len(srv_map.dynamic) == 2
    assert not srv_map.include
    assert not srv_map.redirect
    with pytest.raises(TypeError, match="callback must be callable"):
        srv_map.set_dynamic_response("x", None)
    with pytest.raises(TypeError, match="callback requires 1 argument"):
        srv_map.set_dynamic_response("x", lambda: 0)
    with pytest.raises(TypeError, match="mime_type must be of type 'str'"):
        srv_map.set_dynamic_response("x", lambda _: 0, None)
    # test detecting collisions
    with pytest.raises(MapCollisionError):
        srv_map.set_include("url_01", str(tmp_path))
    with pytest.raises(MapCollisionError):
        srv_map.set_redirect("url_01", "test_file")


def test_servermap_03(tmp_path):
    """test ServerMap includes"""
    srv_map = ServerMap()
    with pytest.raises(IOError, match="Include path not found: no_dir"):
        srv_map.set_include("test_url", "no_dir")
    assert not srv_map.include
    srv_map.set_include("url_01", str(tmp_path))
    assert len(srv_map.include) == 1
    assert "url_01" in srv_map.include
    assert srv_map.include["url_01"].target == str(tmp_path)
    # overwrite existing
    inc1 = tmp_path / "includes" / "a"
    inc1.mkdir(parents=True)
    srv_map.set_include("url_01", str(inc1))
    assert srv_map.include["url_01"].target == str(inc1)
    # add another
    inc2 = tmp_path / "includes" / "b"
    inc2.mkdir()
    srv_map.set_include("url_02", str(inc2))
    assert len(srv_map.include) == 2
    assert not srv_map.dynamic
    assert not srv_map.redirect
    # test detecting collisions
    with pytest.raises(MapCollisionError, match="URL collision on 'url_01'"):
        srv_map.set_redirect("url_01", "test_file")
    with pytest.raises(MapCollisionError):
        srv_map.set_dynamic_response("url_01", lambda _: 0, mime_type="test/type")
    # test overlapping includes
    with pytest.raises(MapCollisionError, match=r"'url_01' and '\w+' include"):
        srv_map.set_include("url_01", str(tmp_path))
    inc3 = tmp_path / "includes" / "b" / "c"
    inc3.mkdir()
    with pytest.raises(MapCollisionError, match=r"'url_01' and '\w+' include"):
        srv_map.set_include("url_01", str(inc3))


def test_servermap_04(tmp_path):
    """test ServerMap redirects"""
    srv_map = ServerMap()
    srv_map.set_redirect("url_01", "test_file", required=True)
    assert len(srv_map.redirect) == 1
    assert "url_01" in srv_map.redirect
    assert srv_map.redirect["url_01"].target == "test_file"
    assert srv_map.redirect["url_01"].required
    srv_map.set_redirect("url_02", "test_file", required=False)
    assert len(srv_map.redirect) == 2
    assert not srv_map.redirect["url_02"].required
    assert not srv_map.dynamic
    assert not srv_map.include
    with pytest.raises(TypeError, match="target must not be an empty string"):
        srv_map.set_redirect("x", "")
    with pytest.raises(TypeError, match="target must be of type 'str'"):
        srv_map.set_redirect("x", None)
    # test detecting collisions
    with pytest.raises(MapCollisionError):
        srv_map.set_include("url_01", str(tmp_path))
    with pytest.raises(MapCollisionError):
        srv_map.set_dynamic_response("url_01", lambda _: 0, mime_type="test/type")


def test_servermap_05():
    """test ServerMap._check_url()"""
    # pylint: disable=protected-access
    assert ServerMap._check_url("test") == "test"
    assert ServerMap._check_url("") == ""
    # only alphanumeric is allowed
    with pytest.raises(InvalidURLError):
        ServerMap._check_url("asd!@#")
    # '..' should not be accepted
    with pytest.raises(InvalidURLError):
        ServerMap._check_url("/..")
    # cannot map more than one '/' deep
    with pytest.raises(InvalidURLError):
        ServerMap._check_url("/test/test")
