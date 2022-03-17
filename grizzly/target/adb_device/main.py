# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from argparse import ArgumentParser
from logging import DEBUG, ERROR, INFO, WARNING, getLogger
from os.path import isfile

from ...common.utils import configure_logging
from .adb_process import ADBProcess
from .adb_session import ADBSession

LOG = getLogger("adb_device")

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


def parse_args(argv=None):
    log_level_map = {"ERROR": ERROR, "WARN": WARNING, "INFO": INFO, "DEBUG": DEBUG}

    parser = ArgumentParser(description="ADB Device Wrapper")
    parser.add_argument(
        "--airplane-mode",
        choices=(0, 1),
        type=int,
        help="Enable(1) or disable(0) airplane mode",
    )
    parser.add_argument("--install", help="Path to APK to install")
    parser.add_argument("--launch", help="Path to APK to launch")
    parser.add_argument(
        "--log-level",
        choices=sorted(log_level_map),
        default="INFO",
        help="Configure console logging (default: %(default)s)",
    )
    parser.add_argument("--logs", help="Location to save logs")
    parser.add_argument("--ip", help="IP address of target device")
    parser.add_argument(
        "--non-root", action="store_true", help="Connect as non-root user"
    )
    parser.add_argument(
        "--port", default=5555, type=int, help="ADB listening port on target device"
    )
    parser.add_argument("--prep", help="Prepare the device for fuzzing. Path to APK")

    # sanity check args
    args = parser.parse_args(argv)
    if not any((args.airplane_mode is not None, args.install, args.launch, args.prep)):
        parser.error("No options selected")
    for apk in (args.install, args.launch, args.prep):
        if apk is not None and not isfile(apk):
            parser.error("Invalid APK %r" % (apk,))
    args.log_level = log_level_map[args.log_level]
    return args


def main(args):  # pylint: disable=missing-docstring
    configure_logging(args.log_level)
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
            LOG.debug("Setting airplane mode (%d)...", args.airplane_mode)
            session.airplane_mode = args.airplane_mode == 1
            LOG.info(
                "Airplane mode %s.", "enabled" if args.airplane_mode else "disabled"
            )
        if args.install is not None:
            pkg_name = ADBSession.get_package_name(args.install)
            if pkg_name is None:
                LOG.error("Failed to lookup package name in %r", args.install)
                return 1
            if session.uninstall(pkg_name):
                LOG.info("Uninstalled existing %r.", pkg_name)
            LOG.info("Installing %r from %r...", pkg_name, args.install)
            package = session.install(args.install)
            if not package:
                LOG.error("Could not install %r", args.install)
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
            except KeyboardInterrupt:  # pragma: no cover
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
