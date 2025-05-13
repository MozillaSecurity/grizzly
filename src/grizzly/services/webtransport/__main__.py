# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

import argparse
import shutil
from logging import DEBUG, INFO, getLogger
from pathlib import Path
from time import sleep

from grizzly.common.frontend import configure_logging
from grizzly.services import WebServices
from sapphire import CertificateBundle, Sapphire, ServerMap

LOG = getLogger(__name__)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    # log levels for console logging
    level_map = {"DEBUG": DEBUG, "INFO": INFO}
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--log-level",
        choices=sorted(level_map),
        default="INFO",
        help="Configure console logging (default: %(default)s)",
    )
    parser.add_argument(
        "--serve-path",
        type=Path,
        required=True,
        help="Path containing resources to serve",
    )
    parser.add_argument(
        "--cert-path",
        type=Path,
        required=True,
        help="Path to store generated certificates",
    )
    parser.add_argument(
        "--port", default=0, type=int, help="Specify port (default: automatic)"
    )
    parser.add_argument(
        "--timeout",
        default=0,
        type=int,
        help="Duration in seconds to serve before exiting (default: 0 - no timeout)",
    )

    return parser.parse_args(argv)


def main() -> None:
    args = parse_args()
    configure_logging(args.log_level)

    if args.cert_path.exists():
        LOG.warning("Certificate directory already exists!  Overwriting...")
        shutil.rmtree(args.cert_path)

    LOG.info("Generating certificates at %s", args.cert_path.absolute())
    args.cert_path.mkdir(parents=True)
    certs = CertificateBundle.create(args.cert_path.absolute())

    with Sapphire(port=args.port, timeout=args.timeout, certs=certs) as server:
        LOG.info(
            "Serving %s @ https://127.0.0.1:%d/",
            args.serve_path.absolute(),
            server.port,
        )
        services = WebServices.start_services(certs.host, certs.key)

        server_map = ServerMap()
        services.map_locations(server_map)

        server.serve_path(args.serve_path, forever=True, server_map=server_map)

    LOG.info("Services are running. Press Ctrl+C to shut down.")

    try:
        sleep(1e9)  # sleep for 31 years (or until Ctrl+C)
    except KeyboardInterrupt:
        LOG.info("Ctrl+C detected. Shutting down services...")
    finally:
        services.cleanup()


if __name__ == "__main__":
    main()
