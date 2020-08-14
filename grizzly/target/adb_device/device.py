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

    # sanity check the APK
    for apk in (args.install, args.launch, args.prep):
        if apk is not None and not os.path.isfile(apk):
            log.error("Invalid APK %r", apk)
            return 1

    log.debug("opening a session")
    session = ADBSession.create(args.ip, args.port, as_root=not args.non_root)
    if session is None:
        log.error("Failed to connect to IP:%r port:%r", args.ip, args.port)
        return 1
    try:
        if args.prep is not None:
            log.info("Preparing device...")
            args.airplane_mode = 1
            args.install = args.prep
            asan_opts = {
                "abort_on_error": "0",
                "log_path": "'%s'" % session.SANITIZER_LOG_PREFIX}
            session.sanitizer_options("asan", asan_opts)
        if args.airplane_mode is not None:
            if args.airplane_mode > 0:
                log.info("Enabling airplane mode...")
            else:
                log.info("Disabling airplane mode...")
            session.airplane_mode = bool(args.airplane_mode)
            log.info("Done.")
        if args.install is not None:
            pkg_name = ADBSession.get_package_name(args.install)
            if pkg_name is None:
                log.error("Failed to lookup package name in %r", args.install)
                return 1
            if session.uninstall(pkg_name):
                log.info("Uninstalled existing version")
            log.info("Installing %s (%r)...", pkg_name, args.install)
            package = session.install(args.install)
            if not package:
                log.error("Could not install %s", args.install)
                return 1
            session.call(["shell", "am", "set-debug-app", "--persistent", package])
            log.info("Installed %s.", package)
        if args.launch:
            pkg_name = ADBSession.get_package_name(args.launch)
            if pkg_name is None:
                log.error("Failed to lookup package name in %r", args.install)
                return 1
            proc = ADBProcess(pkg_name, session)
            try:
                proc.launch("about:blank", launch_timeout=360)
                assert proc.is_running(), "browser not running?!"
                log.info("Launched.")
                proc.wait()
            except KeyboardInterrupt:
                pass
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
