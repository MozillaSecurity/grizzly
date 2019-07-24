import argparse
import logging
import os
import sys

from .adb_process import ADBProcess
from .adb_session import ADBSession

log = logging.getLogger("adb_device")  # pylint: disable=invalid-name

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


def main(argv=None):  # pylint: disable=missing-docstring
    # set output verbosity
    if bool(os.getenv("DEBUG")):
        log_level = logging.DEBUG
        log_fmt = "%(levelname).1s %(name)s [%(asctime)s] %(message)s"
    else:
        log_level = logging.INFO
        log_fmt = "[%(asctime)s] %(message)s"
    logging.basicConfig(format=log_fmt, datefmt="%Y-%m-%d %H:%M:%S", level=log_level)

    parser = argparse.ArgumentParser(description="ADB Device Wrapper")
    parser.add_argument(
        "--airplane-mode", default=None, type=int,
        help="Enable(1) or disable(0) airplane mode")
    parser.add_argument(
        "--install", help="Path to APK to install")
    parser.add_argument(
        "--install-asan", help="Path to NDK")
    parser.add_argument(
        "--launch", help="Path to APK to launch")
    parser.add_argument(
        "--logs", help="Location to save logs")
    parser.add_argument(
        "--ip", help="IP address of target device")
    parser.add_argument(
        "--port", default=5555, type=int,
        help="ADB listening port on target device")
    args = parser.parse_args(argv)

    log.info("Opening a session")
    session = ADBSession.create(args.ip, args.port, as_root=True)
    if session is None:
        log.error("Failed to connect to IP:%r port:%r", args.ip, args.port)
        return 1

    if args.install is not None:
        log.info("Installing %r ...", args.install)
        package = session.install(args.install)
        if not package:
            log.error("Could not install %r", args.install)
            return 1
        log.info("Installed %r", package)
    elif args.airplane_mode is not None:
        session.set_airplane_mode(mode=args.airplane_mode > 0)
    elif args.launch:
        package = ADBSession.get_package_name(args.launch)
        if not package:
            log.error("APK not installed")
            return 1
        proc = ADBProcess(package, session)
        try:
            proc.launch("about:blank", launch_timeout=60)
            assert proc.is_running(), "browser not running?!"
            log.info("Launched")
            proc.wait()
        finally:
            proc.close()
            if args.logs:
                proc.save_logs(args.logs)
            proc.cleanup()
    else:
        parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
