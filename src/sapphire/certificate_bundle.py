# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address
from logging import getLogger
from os import getpid
from pathlib import Path
from shutil import rmtree
from tempfile import mkdtemp

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.x509.oid import NameOID

LOG = getLogger(__name__)


def generate_certificates(cert_dir: Path) -> dict[str, Path]:
    """Generate a root CA and host certificate.

    Credit to https://stackoverflow.com/a/56292132
    """
    root_key = generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    root_sub = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Grizzly Root CA")])
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_sub)
        .issuer_name(root_sub)
        .public_key(root_key.public_key())
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .sign(root_key, hashes.SHA256(), default_backend())
    )

    # Now we want to generate a cert from that root
    host_key = generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    host_sub = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Grizzly Test Cert")])
    host_cert = (
        x509.CertificateBuilder()
        .subject_name(host_sub)
        .issuer_name(root_cert.issuer)
        .public_key(host_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(root_key, hashes.SHA256(), default_backend())
    )

    root_file = cert_dir / "root.pem"
    root_file.write_bytes(root_cert.public_bytes(serialization.Encoding.PEM))
    cert_file = cert_dir / "host.pem"
    cert_file.write_bytes(host_cert.public_bytes(serialization.Encoding.PEM))
    key_file = cert_dir / "host.key"
    key_file.write_bytes(
        host_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    return {"root": root_file, "host": cert_file, "key": key_file}


class CertificateBundle:
    """Contains root CA, host CA and private key files."""

    def __init__(self, path: Path, root: Path, host: Path, key: Path) -> None:
        self._base = path
        self.root = root
        self.host = host
        self.key = key

    @classmethod
    def create(cls, path: Path | None = None) -> CertificateBundle:
        """Create certificate files.

        Args:
            path: Location to store generated files.

        Returns:
            CertificateBundle
        """
        if path is None:
            path = Path(mkdtemp(prefix=f"sapphire_certs_{getpid()}_"))
        certs = generate_certificates(path)
        return cls(path, certs["root"], certs["host"], certs["key"])

    def cleanup(self) -> None:
        """Remove certificate files.

        Args:
            None

        Returns:
            None
        """
        LOG.debug("removing certificate path (%s)", self._base)
        rmtree(self._base, ignore_errors=True)
