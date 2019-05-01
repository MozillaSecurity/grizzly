#!/usr/bin/env python

import argparse
import json
import multiprocessing
import os
import socket


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Android Debug Bridge version ... Well really it's Fake ADB")
    parser.add_argument(
        "cmd",
        help="ADB command to execute")
    parser.add_argument(
        "extra", action="append", default=list(), nargs=argparse.REMAINDER,
        help="Extra args")
    return parser.parse_args(argv)


class FakeADBState(object):
    STATE_FILE = os.path.join(os.path.dirname(__file__), "fake-adb-state.json")

    def __init__(self):
        self.connected = False
        self.devices = True  # devices command will return devices
        self.root_allowed = True
        self.root_enabled = False
        self.unavailable = False

    @classmethod
    def load(cls):
        state = cls()
        if not os.path.isfile(cls.STATE_FILE):
            if "DEBUG" in os.environ:
                print("=== FakeADB State FILE NOT FOUND: %r ===" % cls.STATE_FILE)
            return state
        with open(cls.STATE_FILE, "r") as jfp:
            loaded = json.load(jfp)
        if "connected" in loaded:
            state.connected = loaded["connected"]
        if "root_allowed" in loaded:
            state.root_allowed = loaded["root_allowed"]
        if "root_enabled" in loaded:
            state.root_enabled = loaded["root_enabled"]
        if "unavailable" in loaded:
            state.unavailable = loaded["unavailable"]
        if "DEBUG_FAKEADB" in os.environ:
            print("=== FakeADB State Loaded START===")
            print("> connected: %r" % state.connected)
            print("> root_allowed: %r" % state.root_allowed)
            print("> root_enabled: %r" % state.root_enabled)
            print("> unavailable: %r" % state.unavailable)
            print("=== FakeADB State Loaded END===")
        return state

    def save(self):
        with open(self.STATE_FILE, "w") as jfp:
            json.dump({
                "connected":self.connected,
                "root_allowed":self.root_allowed,
                "root_enabled":self.root_enabled,
                "unavailable":self.unavailable}, jfp, indent=2)


def main(argv=None):  # pylint: disable=missing-docstring
    args = parse_args(argv)
    state = FakeADBState.load()

    #print(args)
    if args.cmd == "connect":
        # sanity check
        if len(args.extra[0]) != 1:
            print("invalid arg count for %r" % args.cmd)
            print("unable to connect")  # adb response
            return 1
        ip_addr, port = args.extra[0][0].split(":")
        if ip_addr != "localhost" and len(ip_addr.split(".")) != 4:
            print("invalid ip")
            print("unable to connect")  # adb response
            return 1
        if int(port) > 65535 or int(port) < 1024:
            print("invalid port")
            print("unable to connect")  # adb response
            return 1
        if state.connected:
            # TODO: get full message
            print("already connected")
        elif state.unavailable:
            # TODO: get full message
            print("unable to connect")
            return 1
        state.connected = True
        state.save()
        return 0

    elif args.cmd == "devices":
        if args.extra[0]:
            print("invalid arg count for %r" % args.cmd)
            return 1
        print("List of devices attached")
        print("* daemon not running; starting now at tcp:5037")
        print("* daemon started successfully")
        if state.devices:
            print("emulator-5554   device")
        return 0

    elif args.cmd == "disconnect":
        if len(args.extra[0]) != 1:
            print("invalid arg count for %r" % args.cmd)
            print("No such device")  # adb response
            return 1
        state.connected = False
        state.save()
        return 0

    elif args.cmd == "install":
        if len(args.extra[0]) != 2:
            print("invalid arg count for %r" % args.cmd)
            print("unable to connect")  # adb response
            return 1
        if args.extra[0][0] != "-r":
            return 1
        if len(args.extra[0][1]) < 1:
            return 1
        print("Success")
        return 0

    elif args.cmd == "logcat":
        if len(args.extra[0]) == 1 and args.extra[0][0] == "--clear":
            return 0
        if len(args.extra[0]) == 2 or len(args.extra[0]) == 3 and args.extra[0][2] == "--pid=9990":
            print("07-27 12:10:15.414  9990  9990 W art     : Unexpected CPU variant for X86 using defaults: x86")
            print("07-27 12:10:15.430  9990  9990 I GeckoApplication: zerdatime 3349725 - application start")
            print("07-27 12:10:15.442  9990  4714 I GeckoThread: preparing to run Gecko")
            print("07-27 12:10:15.442  9990  4714 E GeckoLibLoad: Load sqlite start")
            print("07-27 12:10:15.496  9990  9990 I GRALLOC-DRM: create pipe for driver vmwgfx")
            print("07-27 12:10:15.505  9990  4713 E GeckoApp: An error occurred during restore, switching to backup file")
            print("07-27 12:10:15.520  9990  4719 I EGL-DRI2: found extension DRI_Core version 1")
            print("07-27 12:10:15.521  9990  4719 I OpenGLRenderer: Initialized EGL, version 1.4")
            print("07-27 12:10:15.528  9990  4714 E GeckoLibLoad: Load sqlite done")
            print("07-27 12:10:15.529  9990  4707 W art     : Suspending all threads took: 8.966ms")
            print("07-27 12:10:15.533  9990  4714 E GeckoLibLoad: Load nss done")
        if len(args.extra[0]) == 2: # all
            print("07-27 12:39:27.188  3049  3049 W Finsky  : [1] com.google.android.finsky.wear.dx.run(8): Dropping command=auto_uninstall due to Gms not connected")
            print("07-27 12:39:27.239  1887  1994 I InputReader: Reconfiguring input devices.  changes=0x00000010")
            print("07-27 12:39:27.286  2767  7142 I Icing   : Usage reports ok 0, Failed Usage reports 0, indexed 0, re")
            print("07-27 12:39:27.440  7128  7128 E android.os.Debug: failed to load memtrack module: -2")
            print("07-27 12:39:27.441  7128  7128 I Radio-JNI: register_android_hardware_Radio DONE")
        return 0

    elif args.cmd == "pull":
        if len(args.extra[0]) != 2:
            print("invalid arg count for %r" % args.cmd)
            print("unable to connect")  # adb response
            return 1
        print(" pulled. ")
        return 0

    elif args.cmd == "push":
        if len(args.extra[0]) != 2:
            print("invalid arg count for %r" % args.cmd)
            print("unable to connect")  # adb response
            return 1
        print(" pushed. ")
        return 0

    elif args.cmd == "reverse":
        if len(args.extra[0]) < 2:
            print("invalid arg count for %r" % args.cmd)
            return 1
        return 0

    elif args.cmd == "root":
        if args.extra[0]:
            print("invalid arg count for %r" % args.cmd)
            return 1
        if state.root_allowed:
            if not state.root_enabled:
                print("restarting adbd as root")
                state.connected = False
                state.root_enabled = True
                state.save()
                return 0
        return 0

    elif args.cmd == "shell" and args.extra[0][0] == "am" and args.extra[0][1] == "start":
        if len(args.extra[0]) < 5:
            print("invalid arg count for %r" % args.cmd)
            return 1
        # only "successfully" launch org.mozilla.fennec_aurora
        if args.extra[0][4].startswith("org.mozilla.fennec_aurora"):
            print("Status: ok")
            host, port = args.extra[0][8].split("//")[-1].split(":")
            def handle_bootstrap(host, port):
                soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    soc.connect((host, port))
                    soc.settimeout(5)  # just in case
                    soc.sendall(b"welp")
                    while soc.recv():
                        pass
                finally:
                    soc.close()
            # launch fake browser
            proc = multiprocessing.Process(target=handle_bootstrap, args=(host, int(port)))
            proc.start()
            return 0
        return 1

    elif args.cmd == "shell" and args.extra[0][0] == "am" and args.extra[0][1] == "force-stop":
        if args.extra[0][2] != "org.mozilla.fennec_aurora":
            return 1
        return 0

    elif args.cmd == "shell" and args.extra[0][0] == "setenforce":
        return 0

    elif args.cmd == "shell" and args.extra[0][0] == "ls" and args.extra[0][1] == "-A":
        if args.extra[0][2] == "missing-dir":
            return 1
        #print(".")
        #print("..")
        print("test")
        return 0

    elif args.cmd == "shell" and args.extra[0][0] == "lsof":
        print("COMMAND     PID       USER   FD      TYPE             DEVICE  SIZE/OFF       NODE NAME")
        if len(args.extra[0]) == 1:
            print("init          1       root  cwd   unknown                                         /proc/1/cwd (readlink: Permission denied)")
            print("lsof      15988      shell  cwd       DIR               0,13       780       4234 /")
            print("lsof      15988      shell  txt       REG                8,1    432284    1696174 /system/bin/toybox")
            print("lsof      15988      shell    4r      DIR                0,4         0     120901 /proc/15988/fd")
        if len(args.extra[0]) == 1 or (args.extra[0][1] == "-p" and "9991" in args.extra[0][2].split(",")):
            print("a.fennec_  9991     u0_a80   98r      REG                8,1    306672    1696611 /system/fonts/blah.ttf")
        if len(args.extra[0]) == 1 or (args.extra[0][1] == "-p" and "9990" in args.extra[0][2].split(",")):
            print("a.fennec_  9990     u0_a80  cwd       DIR               0,13       780       4234 /")
            print("a.fennec_  9990     u0_a80  txt       REG                8,1     17948    1695879 /system/bin/app_process32")
            print("a.fennec_  9990     u0_a80  mem   unknown                                         /dev/ashmem/dalvik-main space (deleted)")
            print("a.fennec_  9990     u0_a80  mem       CHR              10,58                 4485 /dev/binder")
            print("a.fennec_  9990     u0_a80  mem   unknown                                         /dev/ashmem/dalvik-allocspace zygote / non moving space live-bitmap 0 (deleted)")
            print("a.fennec_  9990     u0_a80  mem       REG                8,1    152888    1704079 /system/lib/libexpat.so")
            print("a.fennec_  9990     u0_a80   54u      REG                8,1    329632    1769879 /data/data/org.mozilla.fennec_aurora/files/mozilla/0kjujtli.default/browser.db-wal")
            print("a.fennec_  9990     u0_a80   55u     IPv6                          0t0      44549 TCP []:49232->[]:443 (ESTABLISHED)")
            print("a.fennec_  9990     u0_a80   75w     FIFO                0,9       0t0      44634 pipe:[44634]")
            print("a.fennec_  9990     u0_a80   76u     sock                          0t0      44659 socket:[44659]")
            print("a.fennec_  9990     u0_a80   95u      REG                8,1     98304    1769930 /data/data/org.mozilla.fennec_aurora/files/mozilla/0kjujtli.default/permissions.sqlite")
            print("a.fennec_  9990     u0_a80   98r      REG                8,1    306672    1696611 /system/fonts/Roboto-Regular.ttf")
            print("a.fennec_  9990     u0_a80  122u      CHR              10,59       0t0       4498 /dev/ashmem")
            print("a.fennec_  9990     u0_a80  123u     IPv4                          0t0      44706 UDP :1900->:0")
            print("a.fennec_  9990     u0_a80  125u     0000               0,10       0t0       3655 anon_inode:[eventpoll]")
            print("a.fennec_  9990     u0_a80  126u     IPv4                          0t0      44773 TCP :58190->:443 (ESTABLISHED)")
            print("a.fennec_  9990     u0_a80  128u     unix                          0t0      44747 socket")
            print("a.fennec_  9990     u0_a80  130u     IPv4                          0t0      44840 TCP :35274->:443 (SYN_SENT)")
        print("")
        return 0

    elif args.cmd == "shell" and args.extra[0][0] == "mkdir":
        print("")
        return 0

    elif args.cmd == "shell" and args.extra[0][0] == "pm" and args.extra[0][1] == "grant":
        if len(args.extra[0]) != 4:
            return 1
        print("")
        return 0


    elif (args.cmd == "shell" and args.extra[0][0] == "pm" and
          args.extra[0][1] == "list" and args.extra[0][2] == "packages"):
        print("package:org.mozilla.fennec_aurora")
        print("package:org.test.preinstalled")
        print("package:com.android.phone")
        print("package:com.android.shell")
        return 0

    elif args.cmd == "shell" and args.extra[0][0] == "ps":
        # TODO: add root and non-root output
        print("USER      PID   PPID  VSIZE  RSS   WCHAN            PC  NAME")
        if len(args.extra[0]) == 1:
            print("root      1     0     8896   2208  SyS_epoll_ 00000000 S /init")
            print("root      1242  2     0      0         kswapd 00000000 S kswapd0")
            print("test      1337  1772  1024   1024 SyS_epoll_ 00000000 S org.test.preinstalled")
            print("test      1338  1337  1024   1024 SyS_epoll_ 00000000 S org.test.child")
            print("root      1772  1     1620804 122196 poll_sched 00000000 S zygote")
            print("media_rw  2158  1758  0      0              0 00000000 Z sdcard")
            print("audioserver 1773  1     34000  9624  binder_thr 00000000 S /system/bin/audioserver")
            print("root      5847  1     315992 2348  poll_sched 00000000 S /sbin/adbd")
            print("u0_a80    9990  1772  1221212 128064 SyS_epoll_ 00000000 S org.mozilla.fennec_aurora")
            print("root      5944  5847  6280   2360           0 00000000 R ps")
        if len(args.extra[0]) == 3 and args.extra[0][1] == "--ppid" and args.extra[0][2] == "9990":
            print("u0_a80    9991  9990  3332   3331 SyS_epoll_ 00000000 S org.mozilla.fennec_aurora")
        elif len(args.extra[0]) == 2 and args.extra[0][1] == "9990":
            print("u0_a80    9990  1772  1221212 128064 SyS_epoll_ 00000000 S org.mozilla.fennec_aurora")
        print("")
        return 0

    elif args.cmd == "shell" and args.extra[0][0] == "realpath":
        print(args.extra[0][1])
        return 0

    elif args.cmd == "shell" and args.extra[0][0] == "rm":
        print("")
        return 0

    elif args.cmd == "shell" and args.extra[0][0] == "whoami":
        if state.root_enabled:
            print("root")
        else:
            print("shell")
        return 0

    elif args.cmd == "uninstall":
        if len(args.extra[0]) != 1:
            print("invalid arg count for %r" % args.cmd)
            print("unable to connect")
            return 1
        if args.extra[0][0] == "org.test.preinstalled":
            print("Success")
        return 0

    elif args.cmd == "unroot":
        if args.extra[0]:
            print("invalid arg count for %r" % args.cmd)
            return 1
        if state.root_enabled:
            print("restarting adbd as non root")
            state.connected = False
            state.root_enabled = False
            state.save()
        return 0


    print("Android Debug Bridge version 1.0.XX")
    print("Fake ADB: UNKNOWN COMMAND %r" % args.extra)
    return 1


if __name__ == "__main__":
    exit(main())
