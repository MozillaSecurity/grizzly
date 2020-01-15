# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import pytest

from .server_map import ServerMap

def test_servermap_01():
    """test empty ServerMap"""
    srv_map = ServerMap()
    assert not srv_map.dynamic_responses
    assert not srv_map.includes
    assert not srv_map.redirects
    with pytest.raises(AssertionError) as exc:
        srv_map.reset()
    assert "At least one kwarg should be True" in str(exc.value)

def test_servermap_02():
    """test ServerMap dynamic responses"""
    def fake_cb():
        pass
    srv_map = ServerMap()
    srv_map.set_dynamic_response("url_01", fake_cb, mime_type="test/type")
    assert len(srv_map.dynamic_responses) == 1
    assert srv_map.dynamic_responses[0]["url"] == "url_01"
    assert srv_map.dynamic_responses[0]["mime"] == "test/type"
    assert callable(srv_map.dynamic_responses[0]["callback"])
    srv_map.set_dynamic_response("url_02", fake_cb, mime_type="foo")
    assert len(srv_map.dynamic_responses) == 2
    srv_map.remove_dynamic_response("url_02")
    assert len(srv_map.dynamic_responses) == 1
    srv_map.reset(dynamic_response=True)
    assert not srv_map.dynamic_responses

def test_servermap_03(tmp_path):
    """test ServerMap includes"""
    srv_map = ServerMap()
    with pytest.raises(IOError) as exc:
        srv_map.set_include("test_url", "no_dir")
    assert "'no_dir' does not exist" in str(exc.value)
    assert not srv_map.includes
    srv_map.set_include("url_01", str(tmp_path))
    assert len(srv_map.includes) == 1
    assert srv_map.includes[0][0] == "url_01"
    assert srv_map.includes[0][1] == str(tmp_path)
    srv_map.set_include("url_02", str(tmp_path))
    assert len(srv_map.includes) == 2
    srv_map.remove_include("url_02")
    assert len(srv_map.includes) == 1
    srv_map.reset(include=True)
    assert not srv_map.includes

def test_servermap_04():
    """test ServerMap redirects"""
    srv_map = ServerMap()
    srv_map.set_redirect("url_01", "test_file", required=True)
    assert len(srv_map.redirects) == 1
    assert srv_map.redirects[0]["url"] == "url_01"
    assert srv_map.redirects[0]["file_name"] == "test_file"
    assert srv_map.redirects[0]["required"]
    srv_map.set_redirect("url_02", "test_file", required=False)
    assert len(srv_map.redirects) == 2
    srv_map.remove_redirect("url_02")
    assert len(srv_map.redirects) == 1
    srv_map.reset(redirect=True)
    assert not srv_map.redirects
