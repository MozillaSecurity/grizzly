from argparse import ArgumentParser
from logging import DEBUG, INFO, basicConfig, getLogger
from os import getenv
from os.path import isfile

from .adb_process import ADBProcess
from .adb_session import ADBSession

LOG = getLogger("adb_device")

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


def main(argv=None):  # pylint: disable=missing-docstring
    # set output verbosity
    if bool(getenv("DEBUG")):
        log_level = DEBUG
        log_fmt = "%(levelname).1s %(name)s [%(asctime)s] %(message)s"
    else:
        log_level = INFO
        log_fmt = "[%(asctime)s] %(message)s"
    basicConfig(format=log_fmt, datefmt="%Y-%m-%d %H:%M:%S", level=log_level)

    parser = ArgumentParser(description="ADB Device Wrapper")
    parser.add_argument(
        "--airplane-mode",
        default=None,
        type=int,
        help="Enable(1) or disable(0) airplane mode",
    )
    parser.add_argument("--install", help="Path to APK to install")
    parser.add_argument("--launch", help="Path to APK to launch")
    parser.add_argument("--logs", help="Location to save logs")
    parser.add_argument("--ip", help="IP address of target device")
    parser.add_argument(
        "--non-root", action="store_true", help="Connect as non-root user"
    )
    parser.add_argument(
        "--port", default=5555, type=int, help="ADB listening port on target device"
    )
    parser.add_argument("--prep", help="Prepare the device for fuzzing. Path to APK")
    args = parser.parse_args(argv)
    if not any((args.airplane_mode is not None, args.install, args.launch, args.prep)):
        parser.error("No options selected")

    # sanity check the APK
    for apk in (args.install, args.launch, args.prep):
        if apk is not None and not isfile(apk):
            LOG.error("Invalid APK %r", apk)
            return 1

    LOG.debug("opening a session")
    session = ADBSession.create(args.ip, args.port, as_root=not args.non_root)
    if session is None:
        LOG.error("Failed to connect to IP:%r port:%r", args.ip, args.port)
        return 1
    try:
        if args.prep is not None:
            LOG.info("Preparing device...")
            args.airplane_mode = 1
            args.install = args.prep
            session.sanitizer_options("asan", {"abort_on_error": "0"})
        if args.airplane_mode is not None:
            if args.airplane_mode > 0:
                LOG.info("Enabling airplane mode...")
            else:
                LOG.info("Disabling airplane mode...")
            session.airplane_mode = bool(args.airplane_mode)
            LOG.info("Done.")
        if args.install is not None:
            pkg_name = ADBSession.get_package_name(args.install)
            if pkg_name is None:
                LOG.error("Failed to lookup package name in %r", args.install)
                return 1
            if session.uninstall(pkg_name):
                LOG.info("Uninstalled existing version")
            LOG.info("Installing %s (%r)...", pkg_name, args.install)
            package = session.install(args.install)
            if not package:
                LOG.error("Could not install %s", args.install)
                return 1
            session.call(["shell", "am", "set-debug-app", "--persistent", package])
            LOG.info("Installed %s.", package)
        if args.launch:
            pkg_name = ADBSession.get_package_name(args.launch)
            if pkg_name is None:
                LOG.error("Failed to lookup package name in %r", args.install)
                return 1
            proc = ADBProcess(pkg_name, session)
            try:
                proc.launch("about:blank", launch_timeout=360)
                assert proc.is_running(), "browser not running?!"
                LOG.info("Launched.")
                proc.wait()
            except KeyboardInterrupt:
                pass
            finally:
                proc.close()
                if args.logs:
                    proc.save_logs(args.logs)
                proc.cleanup()
                LOG.info("Closed.")
    finally:
        session.disconnect()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
