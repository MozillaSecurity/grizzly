import argparse
import asyncio
import logging

from .core import WebTransportServer

LOG = logging.getLogger(__name__)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("certificate")
    parser.add_argument("key")
    args = parser.parse_args(argv)

    loop = asyncio.get_event_loop()
    wt_service = WebTransportServer()
    loop.create_task(wt_service.start(args.certificate, args.key))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass


SystemExit(main())
