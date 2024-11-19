"""
Job unit tests
"""

# pylint: disable=protected-access
from pathlib import Path
from platform import system

from pytest import mark, raises

from .job import Job, Served
from .server_map import (
    DynamicResource,
    FileResource,
    IncludeResource,
    RedirectResource,
    ServerMap,
)


def test_job_01(tmp_path):
    """test creating a simple Job"""
    with raises(RuntimeError, match="Empty Job"):
        Job(tmp_path)
    test_file = tmp_path / "test.txt"
    test_file.touch()
    job = Job(tmp_path, required_files=[test_file.name])
    assert not job.forever
    assert job.status == Served.NONE
    assert job.lookup_resource("") is None
    assert job.lookup_resource("test") is None
    assert job.lookup_resource("test/test/") is None
    assert job.lookup_resource("test/../../") is None
    assert job.lookup_resource("\x00\x0B\xAD\xF0\x0D") is None
    assert job.lookup_resource("test.txt")
    assert job.pending == 1
    assert not job.is_complete()
    assert job.remove_pending(str(test_file))
    assert job.pending == 0
    job.finish()
    assert not any(job.served)
    assert job.is_complete(wait=0.01)


def test_job_02(tmp_path):
    """test Job proper handling of required and optional files"""
    opt = []
    opt.append(tmp_path / "opt_file_1.txt")
    opt[-1].write_bytes(b"a")
    req = []
    req.append(tmp_path / "req_file_1.txt")
    req[-1].write_bytes(b"b")
    (tmp_path / "nested").mkdir()
    opt.append(tmp_path / "nested" / "opt_file_2.txt")
    opt[-1].write_bytes(b"c")
    req.append(tmp_path / "nested" / "req_file_2.txt")
    req[-1].write_bytes(b"d")
    job = Job(tmp_path, required_files=[req[0].name, f"nested/{req[1].name}"])
    assert job.status == Served.NONE
    assert not job.is_complete()
    resource = job.lookup_resource("req_file_1.txt")
    assert isinstance(resource, FileResource)
    assert resource.required
    assert job.pending == 2
    assert resource.target == tmp_path / "req_file_1.txt"
    assert not job.remove_pending("no_file.test")
    assert job.pending == 2
    assert not job.remove_pending(str(req[0]))
    job.mark_served(resource)
    assert len(job._served.files) == 1
    assert job.status == Served.REQUEST
    assert job.pending == 1
    resource = job.lookup_resource("nested/req_file_2.txt")
    assert job.remove_pending(str(req[1]))
    job.mark_served(resource)
    assert len(job._served.files) == 2
    assert job.status == Served.ALL
    assert job.pending == 0
    assert job.remove_pending(str(req[0]))
    job.mark_served(resource)
    assert len(job._served.files) == 2
    resource = job.lookup_resource("opt_file_1.txt")
    assert isinstance(resource, FileResource)
    assert not resource.required
    assert resource.target == opt[0]
    assert job.remove_pending(str(opt[0]))
    job.mark_served(resource)
    assert len(job._served.files) == 3
    assert len(job.served) == 3
    resource = job.lookup_resource("nested/opt_file_2.txt")
    assert isinstance(resource, FileResource)
    assert resource.target == opt[1]
    assert not resource.required
    job.finish()
    assert job.is_complete()


def test_job_03(tmp_path):
    """test Job redirects"""
    smap = ServerMap()
    smap.set_redirect("one", "somefile.txt", required=False)
    smap.set_redirect("two", "reqfile.txt")
    job = Job(tmp_path, server_map=smap)
    assert job.status == Served.NONE
    resource = job.lookup_resource("one")
    assert isinstance(resource, RedirectResource)
    resource = job.lookup_resource("two")
    assert isinstance(resource, RedirectResource)
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
    smap.set_include("testinc", srv_include)
    # add manually to avoid sanity checks in ServerMap.set_include()
    smap.include["testinc/fakedir"] = IncludeResource(
        "testinc/fakedir", False, srv_include
    )
    smap.include["testinc/1/2/3"] = IncludeResource("testinc/1/2/3", False, srv_include)
    smap.include[""] = IncludeResource("", False, srv_include)
    smap.set_include("testinc/inc2", srv_include_2)
    job = Job(srv_root, server_map=smap, required_files=[test_1.name])
    assert job.status == Served.NONE
    # test include path pointing to a missing file
    assert job.lookup_resource("testinc/missing") is None
    # test include path pointing to an invalid file name
    assert job.lookup_resource("testinc/\x00\x0B\xAD\xF0\x0D") is None
    # test includes that map to 'srv_include'
    includes = [res for res in smap.include.values() if res.target == srv_include]
    assert includes
    for include in includes:
        request = f"{include.url}/test_file.txt"
        resource = job.lookup_resource(request)
        assert isinstance(resource, FileResource)
        assert srv_include in resource.target.parents
        assert resource.url == request.lstrip("/")
    # test nested include path pointing to a different include
    request = "testinc/inc2/test_file_2.txt"
    resource = job.lookup_resource(request)
    assert isinstance(resource, FileResource)
    assert resource.target == inc_2
    assert resource.url == request
    # test redirect root without leading '/'
    request = "test_file.txt"
    resource = job.lookup_resource(request)
    assert isinstance(resource, FileResource)
    assert resource.target == srv_include / "test_file.txt"
    assert resource.url == request
    # test redirect with file in a nested directory
    request = "testinc/nested/nested_file.txt"
    resource = job.lookup_resource(request)
    assert isinstance(resource, FileResource)
    assert resource.target == nst_1
    assert resource.url == request


def test_job_05(tmp_path):
    """test Job.lookup_resource() with tricky includes"""
    srv_root = tmp_path / "root"
    srv_root.mkdir()
    req = srv_root / "req_file.txt"
    req.write_bytes(b"a")
    inc_dir = tmp_path / "inc_dir"
    inc_dir.mkdir()
    (inc_dir / "sub").mkdir()
    inc_file1 = inc_dir / "sub" / "include.js"
    inc_file1.write_bytes(b"a")
    inc_file2 = inc_dir / "test_inc.html"
    inc_file2.write_bytes(b"a")
    # test url matching part of the file name
    smap = ServerMap()
    smap.include["inc_url"] = IncludeResource("inc_url", False, inc_dir)
    job = Job(srv_root, server_map=smap, required_files=[req.name])
    resource = job.lookup_resource("inc_url/sub/include.js")
    assert isinstance(resource, FileResource)
    assert resource.target == inc_file1
    # test checking only the include url
    assert job.lookup_resource("inc_url") is None
    # file and include file collision (files should always win)
    smap.include.clear()
    inc_a = inc_dir / "a.bin"
    inc_a.write_bytes(b"a")
    file_a = srv_root / "a.bin"
    file_a.write_bytes(b"a")
    smap.include["/"] = IncludeResource("", False, inc_dir)
    resource = job.lookup_resource("a.bin")
    assert isinstance(resource, FileResource)
    assert resource.target == file_a
    # TODO: inc and inc subdir collision can fail.
    # /inc/a file
    # /inc   a/file
    # Should we detect and support it? Does it matter?


def test_job_06(tmp_path):
    """test Job dynamic"""
    smap = ServerMap()
    smap.set_dynamic_response("cb1", lambda _: b"0", mime_type="a/a", required=True)
    smap.set_dynamic_response("cb2", lambda _: b"1")
    job = Job(tmp_path, server_map=smap)
    assert job.status == Served.NONE
    assert job.pending == 1
    resource = job.lookup_resource("cb1")
    assert isinstance(resource, DynamicResource)
    assert callable(resource.target)
    assert isinstance(resource.mime, str)
    resource = job.lookup_resource("cb2")
    assert isinstance(resource, DynamicResource)
    assert callable(resource.target)
    assert isinstance(resource.mime, str)


def test_job_07(tmp_path):
    """test accessing forbidden files"""
    srv_root = tmp_path / "root"
    srv_root.mkdir()
    test_file = srv_root / "req_file.txt"
    test_file.write_bytes(b"a")
    no_access = tmp_path / "no_access.txt"
    no_access.write_bytes(b"a")
    job = Job(srv_root, required_files=[test_file.name])
    assert job.status == Served.NONE
    assert job.pending == 1
    assert job.lookup_resource("../no_access.txt") is None


@mark.skipif(system() == "Windows", reason="Unsupported on Windows")
def test_job_08(tmp_path):
    """test Job with file names containing invalid characters"""
    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"a")
    (tmp_path / "?_2.txt").write_bytes(b"a")
    job = Job(tmp_path, required_files=[test_file.name])
    assert job.status == Served.NONE
    assert job.pending == 1
    resource = job.lookup_resource("test.txt")
    assert resource
    assert resource.target == test_file


def test_job_09(tmp_path):
    """test Job.lookup_resource() with file name that is too long"""
    (tmp_path / "test.txt").touch()
    job = Job(tmp_path, required_files=["test.txt"])
    assert job.status == Served.NONE
    assert job.pending == 1
    assert job.lookup_resource(f"/{'a' * 8192}.txt") is None


def test_job_10(tmp_path):
    """test Job with missing directory"""
    with raises(OSError):
        Job(tmp_path / "missing")


def test_job_11(tmp_path):
    """test Job.mark_served() and Job.served"""
    (tmp_path / "test.txt").touch()
    job = Job(tmp_path, required_files=["test.txt"])
    assert not any(job.served)
    # add first resource
    resource = FileResource("a.bin", False, tmp_path / "a.bin", "mine/mime")
    job.mark_served(resource)
    assert "a.bin" in job.served
    assert job.served[resource.url] == resource.target
    assert len(job.served) == 1
    # add a resource with the same url
    job.mark_served(FileResource("a.bin", False, tmp_path / "a.bin", "mine/mime"))
    assert len(job._served.files) == 1
    assert len(job.served) == 1
    # add a nested resource
    resource = FileResource("nested/b.bin", False, tmp_path / "nested" / "b.bin", "a/a")
    job.mark_served(resource)
    assert "nested/b.bin" in job.served
    assert job.served[resource.url] == resource.target
    assert len(job.served) == 2
    # add an include resource
    resource = IncludeResource("inc.bin", False, Path("/some/include/path/inc.bin"))
    job.mark_served(resource)
    assert "inc.bin" in job.served
    assert job.served[resource.url] == resource.target
    assert len(job.served) == 3
    # add an include resource pointing to a common file with unique url
    resource = IncludeResource("alt_path", False, Path("/some/include/path/inc.bin"))
    job.mark_served(resource)
    assert "alt_path" in job.served
    assert len(job.served) == 4
    assert job.served[resource.url] == resource.target


def test_job_12():
    """test Job.lookup_mime()"""
    assert Job.lookup_mime("unknown") == "application/octet-stream"
    # look up from Job.MIME_MAP
    assert ".avif" in Job.MIME_MAP, "test is broken"
    assert Job.lookup_mime("test.avif") == "image/avif"
    # look up known ext
    assert Job.lookup_mime("test.html") == "text/html"
