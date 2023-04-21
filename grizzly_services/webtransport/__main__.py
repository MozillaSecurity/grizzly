import argparse
import asyncio
import logging

from .core import WebTransportServer

LOG = logging.getLogger(__name__)

log_level = logging.DEBUG
log_fmt = "%(levelname).1s %(name)s [%(asctime)s] %(message)s"
logging.basicConfig(format=log_fmt, datefmt="%Y-%m-%d %H:%M:%S", level=log_level)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("certificate")
    parser.add_argument("key")
    args = parser.parse_args(argv)

    loop = asyncio.get_event_loop()
    wt_service = WebTransportServer()
    asyncio.run_coroutine_threadsafe(wt_service.start(args.certificate, args.key), loop=loop)
    loop.run_until_complete(wt_service.is_running())
    # loop.create_task(wt_service.start(args.certificate, args.key))
    # try:
    #     loop.run_forever()
    # except KeyboardInterrupt:
    #     pass


SystemExit(main())
