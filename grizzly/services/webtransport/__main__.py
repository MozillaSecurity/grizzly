import argparse
import logging

from .. import WebServices
from .core import WebTransportServer

LOG = logging.getLogger(__name__)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("certificate")
    parser.add_argument("key")
    args = parser.parse_args(argv)

    port = WebServices.get_free_port()
    wt_service = WebTransportServer(port, args.certificate, args.key)
    wt_service.start()


SystemExit(main())
