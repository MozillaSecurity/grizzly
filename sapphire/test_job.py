# coding=utf-8
"""
Job unit tests
"""
# pylint: disable=protected-access

import platform

import pytest

from .job import Job, SERVED_ALL, SERVED_NONE, SERVED_REQUEST
from .server_map import Resource, ServerMap


def test_job_01(tmp_path):
    """test creating an empty Job"""
    job = Job(str(tmp_path))
    assert not job.forever
    assert job.status == SERVED_ALL
    assert job.check_request("") is None
    assert job.check_request("test") is None
    assert job.check_request("test/test/") is None
    assert job.check_request("test/../../") is None
    assert not job.is_forbidden(str(tmp_path))
    assert not job.is_forbidden(str(tmp_path / "missing_file"))
    assert job.pending == 0
    assert not job.is_complete()
    assert job.remove_pending("no_file.test")
    job.finish()
    assert not any(job.served)
    assert job.is_complete()

def test_job_02(tmp_path):
    """test Job two required files and one optional file"""
    opt_path = tmp_path / "opt_file.txt"
    opt_path.write_bytes(b"a")
    req1_path = tmp_path / "req_file_1.txt"
    req1_path.write_bytes(b"a")
    (tmp_path / "test").mkdir()
    req2_path = tmp_path / "test" / "req_file_2.txt"
    req2_path.write_bytes(b"a")
    job = Job(str(tmp_path), optional_files=[opt_path.name])
    assert job.status == SERVED_NONE
    assert not job.is_complete()
    resource = job.check_request("req_file_1.txt")
    assert resource.required
    assert resource.target == str(tmp_path / "req_file_1.txt")
    assert resource.type == Resource.URL_FILE
    assert not job.is_forbidden(str(req1_path))
    assert not job.remove_pending("no_file.test")
    assert job.pending == 2
    assert not job.remove_pending(str(req1_path))
    assert job.status == SERVED_REQUEST
    assert job.pending == 1
    assert job.remove_pending(str(req2_path))
    assert job.status == SERVED_ALL
    assert job.pending == 0
    assert job.remove_pending(str(req1_path))
    resource = job.check_request("opt_file.txt")
    assert not resource.required
    assert resource.target == str(tmp_path / "opt_file.txt")
    assert resource.type == Resource.URL_FILE
    assert job.remove_pending(str(opt_path))
    job.finish()
    assert job.is_complete()

def test_job_03(tmp_path):
    """test Job redirects"""
    smap = ServerMap()
    smap.set_redirect("one", "somefile.txt", required=False)
    smap.set_redirect("two", "reqfile.txt")
    job = Job(str(tmp_path), server_map=smap)
    assert job.status == SERVED_NONE
    resource = job.check_request("one")
    assert resource.type == Resource.URL_REDIRECT
    resource = job.check_request("two?q=123")
    assert resource is not None
    assert resource.type == Resource.URL_REDIRECT
    assert job.pending == 1
    assert job.remove_pending("two")
    assert job.pending == 0

def test_job_04(mocker, tmp_path):
    """test Job includes"""
    srv_root = tmp_path / "root"
    srv_include = tmp_path / "test"
    srv_include_2 = tmp_path / "test_2"
    srv_include_nested = srv_include / "nested"
    srv_root.mkdir()
    srv_include.mkdir()
    srv_include_2.mkdir()
    srv_include_nested.mkdir()
    test_1 = srv_root / "req_file.txt"
    test_1.write_bytes(b"a")
    inc_1 = srv_include / "test_file.txt"
    inc_1.write_bytes(b"b")
    nst_1 = srv_include_nested / "nested_file.txt"
    nst_1.write_bytes(b"c")
    inc_2 = srv_include_2 / "test_file_2.txt"
    inc_2.write_bytes(b"d")
    # stub out ServerMap._check_url() because it is too
    # restrictive to allow testing of some functionality
    mocker.patch.object(ServerMap, "_check_url", side_effect=lambda x: x)
    smap = ServerMap()
    smap.set_include("testinc", str(srv_include))
    # add manually to avoid sanity checks in ServerMap.set_include()
    smap.include["testinc/fakedir"] = Resource(Resource.URL_INCLUDE, str(srv_include))
    smap.include["testinc/1/2/3"] = Resource(Resource.URL_INCLUDE, str(srv_include))
    smap.include[""] = Resource(Resource.URL_INCLUDE, str(srv_include))
    smap.set_include("testinc/inc2", str(srv_include_2))
    job = Job(str(srv_root), server_map=smap)
    assert job.status == SERVED_NONE
    # test includes that map to 'srv_include'
    for incl, inc_path in smap.include.items():
        if inc_path != str(srv_include):  # only check 'srv_include' mappings
            continue
        resource = job.check_request("/".join([incl, "test_file.txt"]))
        assert resource.type == Resource.URL_INCLUDE
        assert resource.target == str(inc_1)
    # test nested include path pointing to a different include
    resource = job.check_request("testinc/inc2/test_file_2.txt?q=123")
    assert resource.type == Resource.URL_INCLUDE
    assert resource.target == str(inc_2)
    # test redirect root without leading '/'
    resource = job.check_request("test_file.txt")
    assert resource.type == Resource.URL_INCLUDE
    assert resource.target == str(srv_include / "test_file.txt")
    # test redirect with file in a nested directory
    resource = job.check_request("/".join(["testinc", "nested", "nested_file.txt"]))
    assert resource.type == Resource.URL_INCLUDE
    assert resource.target == str(nst_1)
    assert not job.is_forbidden(str(srv_root / ".." / "test" / "test_file.txt"))
    assert not job.is_forbidden(str(srv_include / ".." / "root" / "req_file.txt"))

def test_job_05(tmp_path):
    """test Job.check_request() with tricky includes"""
    srv_root = tmp_path / "root"
    srv_root.mkdir()
    req = srv_root / "req_file.txt"
    req.write_bytes(b"a")
    inc_dir = tmp_path / "inc"
    inc_dir.mkdir()
    (inc_dir / "sub").mkdir()
    inc_file1 = inc_dir / "sub" / "include.js"
    inc_file1.write_bytes(b"a")
    inc_file2 = inc_dir / "test_inc.html"
    inc_file2.write_bytes(b"a")
    # test url matching part of the file name
    smap = ServerMap()
    smap.include["inc"] = Resource(Resource.URL_INCLUDE, str(inc_dir))
    job = Job(str(srv_root), server_map=smap)
    resource = job.check_request("inc/sub/include.js")
    assert resource.type == Resource.URL_INCLUDE
    assert resource.target == str(inc_file1)
    # test checking only the include url
    assert job.check_request("inc") is None
    # file and include file collision (files should always win)
    smap.include.clear()
    inc_a = inc_dir / "a.bin"
    inc_a.write_bytes(b"a")
    file_a = srv_root / "a.bin"
    file_a.write_bytes(b"a")
    smap.include["/"] = Resource(Resource.URL_INCLUDE, str(inc_dir))
    resource = job.check_request("a.bin")
    assert resource.type == Resource.URL_FILE
    assert resource.target == str(file_a)
    # inc and inc subdir collision
    # TODO: This can fail. How do we detect or support it?
    #smap.include.clear()
    #(inc_dir / "c").mkdir()
    #inc_c_d = (inc_dir / "c" / "d.bin")
    #inc_c_d.write_bytes(b"a")
    #inc_d = (inc_dir / "d.bin")
    #inc_d.write_bytes(b"a")
    #smap.include["c"] = Resource(Resource.URL_INCLUDE, str(inc_dir))
    #smap.include[""] = Resource(Resource.URL_INCLUDE, str(inc_dir / "c"))
    #resource = job.check_request("c/d.bin")
    #assert resource.type == Resource.URL_INCLUDE
    #assert resource.target == str(inc_c_d)

def test_job_06(tmp_path):
    """test Job dynamic"""
    smap = ServerMap()
    smap.set_dynamic_response("cb1", lambda: 0, mime_type="mime_type")
    smap.set_dynamic_response("cb2", lambda: 1)
    job = Job(str(tmp_path), server_map=smap)
    assert job.status == SERVED_ALL
    assert job.pending == 0
    resource = job.check_request("cb1")
    assert resource.type == Resource.URL_DYNAMIC
    assert callable(resource.target)
    assert isinstance(resource.mime, str)
    resource = job.check_request("cb2?q=123")
    assert resource is not None
    assert resource.type == Resource.URL_DYNAMIC
    assert callable(resource.target)
    assert isinstance(resource.mime, str)

def test_job_07(tmp_path):
    """test accessing forbidden files"""
    srv_root = tmp_path / "root"
    srv_root.mkdir()
    test_1 = srv_root / "req_file.txt"
    test_1.write_bytes(b"a")
    no_access = tmp_path / "no_access.txt"
    no_access.write_bytes(b"a")
    job = Job(str(srv_root))
    assert job.status == SERVED_NONE
    assert job.pending == 1
    resource = job.check_request("../no_access.txt")
    assert resource.target == str(no_access)
    assert resource.type == Resource.URL_FILE
    assert not job.is_forbidden(str(test_1))
    assert job.is_forbidden(str(srv_root / "../no_access.txt"))

@pytest.mark.skipif(platform.system() == "Windows",
                    reason="Unsupported on Windows")
def test_job_08(tmp_path):
    """test Job with file names containing invalid characters"""
    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"a")
    (tmp_path / "?_2.txt").write_bytes(b"a")
    job = Job(str(tmp_path))
    assert job.status == SERVED_NONE
    assert job.pending == 1
    assert job.check_request("test.txt").target == str(test_file)

def test_job_09():
    """test Job with missing directory"""
    with pytest.raises(OSError):
        Job("missing")

def test_job_10(tmp_path):
    """test Job.increment_served() and Job.served"""
    job = Job(str(tmp_path))
    assert not any(job.served)
    job.increment_served(str(tmp_path / "file.bin"))
    assert "file.bin" in job.served
    job.increment_served("/some/include/path/inc.bin")
    assert "/some/include/path/inc.bin" in job.served

def test_job_11():
    """test Job.lookup_mime()"""
    assert Job.lookup_mime("unknown") == "application/octet-stream"
    # look up from Job.MIME_MAP
    assert ".avif" in Job.MIME_MAP, "test is broken"
    assert Job.lookup_mime("test.avif") == "image/avif"
    # look up known ext
    assert Job.lookup_mime("test.html") == "text/html"
