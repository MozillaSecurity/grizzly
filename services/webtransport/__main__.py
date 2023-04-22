import argparse
import asyncio
import logging

from .core import WebTransportServer

logger = logging.getLogger(__name__)

log_level = logging.DEBUG
log_fmt = "%(levelname).1s %(name)s [%(asctime)s] %(message)s"
logging.basicConfig(format=log_fmt, datefmt="%Y-%m-%d %H:%M:%S", level=log_level)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("certificate")
    parser.add_argument("key")
    args = parser.parse_args(argv)

    loop = asyncio.get_event_loop()
    wt_server = WebTransportServer()
    loop.create_task(wt_server.start(args.certificate, args.key))
    try:
        logging.info(f"Starting server on https://127.0.0.1:{wt_server.port}")
        loop.run_forever()
    except KeyboardInterrupt:
        pass


SystemExit(main())
