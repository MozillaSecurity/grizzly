# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import datetime
from enum import IntEnum, unique
from importlib.metadata import PackageNotFoundError, version
from ipaddress import IPv4Address
from logging import DEBUG, basicConfig, getLogger
from math import ceil
from os import getenv, getpid
from pathlib import Path
from shutil import rmtree
from tempfile import gettempdir

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.x509.oid import NameOID

__all__ = (
    "CertificateBundle",
    "ConfigError",
    "configure_logging",
    "display_time_limits",
    "DEFAULT_TIME_LIMIT",
    "Exit",
    "generate_certificates",
    "grz_tmp",
    "HARNESS_FILE",
    "time_limits",
    "TIMEOUT_DELAY",
)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

try:
    __version__ = version("grizzly-framework")
except PackageNotFoundError:  # pragma: no cover
    # package is not installed
    __version__ = None

DEFAULT_TIME_LIMIT = 30
GRZ_TMP = Path(getenv("GRZ_TMP", gettempdir()), "grizzly")
HARNESS_FILE = Path(__file__).parent / "harness.html"
LOG = getLogger(__name__)
# TIMEOUT_DELAY is added to the test time limit to create the default timeout
TIMEOUT_DELAY = 15


class CertificateBundle:
    """Contains root CA, host CA and private key files."""

    def __init__(self, path, root, host, key):
        self._base = path
        self.root = root
        self.host = host
        self.key = key

    @classmethod
    def create(cls, path=None):
        """Create certificate files.

        Args:
            path: Location to store generated files.

        Returns:
            CertificateBundle
        """
        if path is None:
            path = grz_tmp("certs", str(getpid()))
        certs = generate_certificates(path)
        return cls(path, certs["root"], certs["host"], certs["key"])

    def cleanup(self):
        """Remove certificate files.

        Args:
            None

        Returns:
            None
        """
        LOG.debug("removing certificate path (%s)", self._base)
        rmtree(self._base, ignore_errors=True)


class ConfigError(Exception):
    """Raised to indicate invalid configuration a state"""

    def __init__(self, message, exit_code):
        super().__init__(message)
        self.exit_code = exit_code


@unique
class Exit(IntEnum):
    """Exit codes"""

    SUCCESS = 0
    # unexpected error occurred (invalid input, unhanded exception, etc)
    ERROR = 1
    # invalid argument
    ARGS = 2
    # run aborted (ctrl+c, etc)
    ABORT = 3
    # unrelated Target failure (browser startup crash, etc)
    LAUNCH_FAILURE = 4
    # expected results not reproduced (opposite of SUCCESS)
    FAILURE = 5


def configure_logging(log_level):
    """Configure log output level and formatting.

    Args:
        log_level (int): Set log level.

    Returns:
        None
    """
    # allow force enabling log_level via environment
    if getenv("DEBUG", "0").lower() in ("1", "true"):
        log_level = DEBUG
    if log_level == DEBUG:
        date_fmt = None
        log_fmt = "%(asctime)s %(levelname).1s %(name)s | %(message)s"
    else:
        date_fmt = "%Y-%m-%d %H:%M:%S"
        log_fmt = "[%(asctime)s] %(message)s"
    basicConfig(format=log_fmt, datefmt=date_fmt, level=log_level)


def display_time_limits(time_limit, timeout, no_harness):
    """Output configuration of time limits and harness.

    Args:
        time_limit (int): Time in seconds before harness attempts to close current test.
        timeout (int): Time in seconds before iteration is considered a timeout.
        no_harness (bool): Indicate whether harness will is disabled.

    Returns:
        None
    """
    if timeout > 0:
        if no_harness:
            LOG.info("Using timeout: %ds, harness: DISABLED", timeout)
        else:
            LOG.info("Using time limit: %ds, timeout: %ds", time_limit, timeout)
            if time_limit == timeout:
                LOG.info("To avoid unnecessary relaunches set timeout > time limit")
    else:
        if no_harness:
            LOG.info("Using timeout: DISABLED, harness: DISABLED")
        else:
            LOG.info("Using time limit: %ds, timeout: DISABLED,", time_limit)
        LOG.warning("TIMEOUT DISABLED, not recommended for automation")


def grz_tmp(*subdir):
    path = Path(GRZ_TMP, *subdir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def generate_certificates(cert_dir: Path):
    """Generate a root CA and host certificate.

    Taken from https://stackoverflow.com/a/56292132
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
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=30))
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
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=30))
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

    root_file = Path(cert_dir / "root.pem")
    root_file.write_bytes(root_cert.public_bytes(serialization.Encoding.PEM))
    cert_file = Path(cert_dir / "host.pem")
    cert_file.write_bytes(host_cert.public_bytes(serialization.Encoding.PEM))
    key_file = Path(cert_dir / "host.key")
    key_file.write_bytes(
        host_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    return {"root": root_file, "host": cert_file, "key": key_file}


def time_limits(
    time_limit,
    timeout,
    tests=None,
    default_limit=DEFAULT_TIME_LIMIT,
    timeout_delay=TIMEOUT_DELAY,
):
    """Determine the test time limit and timeout. If time_limit or timeout is None
    it is calculated otherwise the provided value is used.

    Args:
        time_limit (int): Test time limit.
        timeout (int): Iteration timeout.
        tests (iterable): Testcases that may contain time limit values.
        default_limit (int): Value to used as default time limit.
        timeout_delay (int): Value to used as delay when calculating timeout.

    Returns:
        tuple (int, int): Time limit and timeout.
    """
    assert default_limit > 0
    assert timeout_delay >= 0
    # calculate time limit
    calc_limit = time_limit is None
    if calc_limit:
        # use default_limit as a minimum
        test_limits = [default_limit]
        if tests:
            test_limits.extend(int(ceil(x.duration)) for x in tests if x.duration)
        time_limit = max(test_limits)
    assert time_limit > 0
    # calculate timeout
    calc_timeout = timeout is None
    if calc_timeout:
        timeout = time_limit + timeout_delay
    elif calc_limit and time_limit > timeout > 0:
        LOG.debug("calculated time limit > given timeout, using timeout")
        time_limit = timeout
    assert timeout >= 0
    # timeout should always be >= time limit unless timeout is disabled
    assert timeout >= time_limit or timeout == 0
    return time_limit, timeout
