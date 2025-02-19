"""
CertificateBundle unit tests
"""

# pylint: disable=protected-access

from pytest import raises

from .certificate_bundle import CertificateBundle


def test_certificate_bundle_basic(mocker, tmp_path):
    """test CertificateBundle"""
    mocker.patch("sapphire.certificate_bundle.mkdtemp", return_value=str(tmp_path))
    # create a bundle
    bundle = CertificateBundle.create()
    assert bundle.root.is_file()
    assert bundle.host.is_file()
    assert bundle.key.is_file()
    # load a bundle
    bundle = CertificateBundle.load(bundle._base)
    assert bundle.root.is_file()
    assert bundle.host.is_file()
    assert bundle.key.is_file()
    # remove bundle
    bundle.cleanup()
    assert not bundle._base.exists()
    # load empty path
    with raises(FileNotFoundError, match="does not exist"):
        CertificateBundle.load(tmp_path)
