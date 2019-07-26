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
        "--launch", help="Path to APK to launch")
    parser.add_argument(
        "--logs", help="Location to save logs")
    parser.add_argument(
        "--ip", help="IP address of target device")
    parser.add_argument(
        "--non-root", action="store_true",
        help="Connect as non-root user")
    parser.add_argument(
        "--port", default=5555, type=int,
        help="ADB listening port on target device")
    parser.add_argument(
        "--prep", help="Prepare the device for fuzzing. Path to APK")
    args = parser.parse_args(argv)
    if not any((args.airplane_mode is not None, args.install, args.launch, args.prep)):
        parser.error("No options selected")
        return 1

    log.debug("opening a session")
    session = ADBSession.create(args.ip, args.port, as_root=not args.non_root)
    if session is None:
        log.error("Failed to connect to IP:%r port:%r", args.ip, args.port)
        return 1
    try:
        if args.prep is not None:
            log.info("Preparing device...")
            session.set_enforce(0)
            args.airplane_mode = True
            args.install = args.prep
        if args.airplane_mode is not None:
            if args.airplane_mode > 0:
                log.info("Enabling airplane mode...")
            else:
                log.info("Disabling airplane mode...")
            session.set_airplane_mode(mode=args.airplane_mode > 0)
            log.info("Done.")
        if args.install is not None:
            log.info("Installing %r ...", args.install)
            package = session.install(args.install)
            if not package:
                log.error("Could not install %r", args.install)
                return 1
            log.info("Installed %r.", package)
        if args.launch:
            package = ADBSession.get_package_name(args.launch)
            if not package:
                log.error("APK not installed")
                return 1
            proc = ADBProcess(package, session)
            try:
                proc.launch("about:blank", launch_timeout=60)
                assert proc.is_running(), "browser not running?!"
                log.info("Launched.")
                proc.wait()
            finally:
                proc.close()
                if args.logs:
                    proc.save_logs(args.logs)
                proc.cleanup()
                log.info("Closed.")
    finally:
        session.disconnect()
    return 0


if __name__ == "__main__":
    sys.exit(main())
