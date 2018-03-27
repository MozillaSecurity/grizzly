import logging
import os
import sys
import unittest

from stack_hasher import Stack, StackFrame

logging.basicConfig(level=logging.DEBUG if bool(os.getenv("DEBUG")) else logging.INFO)
log = logging.getLogger("grz_report_test")

class TestCase(unittest.TestCase):

    if sys.version_info.major == 2:

        def assertRegex(self, *args, **kwds):
            return self.assertRegexpMatches(*args, **kwds)

        def assertRaisesRegex(self, *args, **kwds):
            return self.assertRaisesRegexp(*args, **kwds)


class StackTests(TestCase):

    def test_01(self):
        "test creating an empty Stack"
        stack = Stack()
        self.assertIsNone(stack.minor)
        self.assertIsNone(stack.major)
        self.assertTrue(isinstance(stack.frames, list))
        self.assertGreater(stack._major_depth, 0)

    def test_02(self):
        "test creating a Stack with 1 frame"
        frames = list()
        for _ in range(1):
            frames.append(
                StackFrame(function="a", location="b", offset="c", stack_line="0"))
        stack = Stack(frames=frames)
        self.assertIsNotNone(stack.minor)
        self.assertIsNotNone(stack.major)
        # at this point the hashes should match
        self.assertEqual(stack.minor, stack.major)
        self.assertEqual(len(stack.frames), 1)

    def test_03(self):
        "test creating a Stack with 2 frames"
        frames = list()
        for _ in range(2):
            frames.append(
                StackFrame(function="a", location="b", offset="c", stack_line="0"))
        stack = Stack(frames=frames, major_depth=2)
        self.assertIsNotNone(stack.minor)
        self.assertIsNotNone(stack.major)
        # at this point the hashes should not match because offset on the major hash is
        # only added from the top frame
        self.assertNotEqual(stack.minor, stack.major)
        self.assertEqual(len(stack.frames), 2)

    def test_04(self):
        "test creating a Stack with 10 frames exceeding major depth"
        frames = list()
        for line in range(10):
            frames.append(
                StackFrame(function="a", location="b", offset="c", stack_line="%d" % line))
        stack = Stack(frames=frames, major_depth=5)
        self.assertIsNotNone(stack.minor)
        self.assertIsNotNone(stack.major)
        # at this point the hashes should not match because offset on the major hash is
        # only added from the top frame
        self.assertNotEqual(stack.minor, stack.major)
        self.assertEqual(len(stack.frames), 10)
        prev_major = stack.major
        stack = Stack(frames=frames, major_depth=4)
        self.assertNotEqual(prev_major, stack.major)

    def test_05(self):
        "test creating a Stack with 2 frames with a major depth of 0"
        frames = list()
        for line in range(2):
            frames.append(
                StackFrame(function="a", location="b", offset="c", stack_line="%d" % line))
        stack = Stack(frames=frames, major_depth=0)
        self.assertIsNotNone(stack.minor)
        self.assertIsNone(stack.major)
        # at this point the hashes should not match because offset on the major hash is
        # only added from the top frame
        self.assertNotEqual(stack.minor, stack.major)
        self.assertEqual(len(stack.frames), 2)

    def test_06(self):
        "test creating a Stack by calling from_text()"
        input_txt = "" \
            "=================================================================\n" \
            "==7854==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x7fcca620e0ee bp 0x7ffd946b2690 sp 0x7ffd946b25c0 T0)\n" \
            "==7854==blah.\n" \
            "==7854==Hint: blah.\n" \
            "    #0 0x7fcca620e0ed in test::test::test(nsIWa*, nsICa*) /aa/bb/cc/dd/ee/ff/gg/asdf.cpp:5533:14\n" \
            "    #1 0x7fcca3497201 in nsAs::TestTest(mz::dom::El*, int) /aa/bb/cc/dd/ee/ff/nsFilea.cpp:13733:3\n" \
            "    #2 0x7fcca3495b9b in asdf::fasd() /aa/bb/cc/dd/ee/ff/base/nsFileb.cpp:11674:21\n" \
            "    #3 0x7fcca02eb9d8 in nsAasd::PrNeEv(bool, bool*) /aa/bb/cc/dd/ee/xpcom/nsFilec.cpp:1396:14\n" \
            "    #4 0x7fcca0307d40 in R_PNE(asd*, bool) /aa/bb/cc/dd/ee/xpcom/threads/asf.cpp:657:10\n" \
            "    #5 0x2a780b25f65a  (<unknown module>)\n" \
            "\n" \
            "AddressSanitizer can not provide additional info.\n" \
            "SUMMARY: AddressSanitizer: SEGV /aa/bb/cc/dd/ee/ff/asdf.cpp:5533:14 in test::test::test(nsIWa*, nsICa*)\n" \
            "==7854==ABORTI\nNG"
        stack = Stack.from_text(input_txt)
        self.assertEqual(len(stack.frames), 6)
        self.assertNotEqual(stack.minor, stack.major)
        self.assertEqual(stack.frames[0].mode, StackFrame.MODE_ASAN)

    def test_07(self):
        "test creating a Stack by calling from_text() with mixed frames modes"
        input_txt = "" \
        "    #0 0x4d2cde in a_b_c /a/lib/info.c:392:12\n" \
        "    #1 0x491e82 in main /a/b/d_e.c:128:8\n" \
        "    #2 0x7f090384582f in __libc_start_main /build/glibc-glibc-2.23/csu/../csu/libc-start.c:291\n" \
        "#2  0x0000000000400545 in gdb_frame ()\n" \
        "    #3 0x41b228 in _start (bin_name+0x41b228)\n"
        stack = Stack.from_text(input_txt)
        self.assertEqual(len(stack.frames), 4)
        self.assertNotEqual(stack.minor, stack.major)
        self.assertEqual(stack.frames[0].mode, StackFrame.MODE_ASAN)

    def test_08(self):
        "test creating a Stack by calling from_text() with text containing 2 stacks"
        input_txt = "" \
            "    #0 0x0bad0bad in bad::frame0(nsA*, nsB*) /aa/a.cpp:12:1\n" \
            "    #1 0x0bad0bad in bad::frame1(mz::d::EE*, int) /aa/a.cpp:12:1\n" \
            "    #0 0x1badf00d in good::frame0(nsA*, nsB*) /aa/a.cpp:12:1\n" \
            "    #1 0xdeadbeef in good::frame1(mz::d::EE*, int) /aa/a.cpp:12:1\n"
        stack = Stack.from_text(input_txt)
        self.assertEqual(len(stack.frames), 2)
        self.assertEqual(stack.frames[0].function, "good::frame0")
        self.assertEqual(stack.frames[1].function, "good::frame1")
        self.assertNotEqual(stack.minor, stack.major)
        self.assertEqual(stack.frames[0].mode, StackFrame.MODE_ASAN)

    def test_09(self):
        "test creating a Stack by calling from_text() with empty string"
        stack = Stack.from_text("")
        self.assertEqual(len(stack.frames), 0)
        self.assertIsNone(stack.minor)
        self.assertEqual(stack.minor, stack.major)

    def test_10(self):
        "test creating a Stack from an ASan trace with an unsymbolized lib"
        input_txt = "" \
            "    #0 0x4c7702 in realloc asan/asan_malloc_linux.cc:107:3\n" \
            "    #1 0x7f6d056ce7fc  (/lib/x86_64-linux-gnu/libdbus-1.so.3+0x2d7fc)\n" \
            "    #2 0x7ffffffff  (<unknown module>)\n"
        stack = Stack.from_text(input_txt)
        self.assertEqual(len(stack.frames), 3)
        self.assertEqual(stack.frames[0].location, "asan_malloc_linux.cc")
        self.assertEqual(stack.frames[1].location, "libdbus-1.so.3")
        self.assertEqual(stack.frames[2].location, "<unknown module>")
        self.assertNotEqual(stack.minor, stack.major)
        self.assertEqual(stack.frames[0].mode, StackFrame.MODE_ASAN)

    def test_11(self):
        "test creating a Stack from an ASan trace with an unsymbolized lib"
        input_txt = "" \
            "    #0 0x90000223  (/usr/swr_a.so+0x231223)\n" \
            "    #1 0x00000447  (/usr/as.so.1+0x42447)\n" \
            "    #2 0x000098fc in fSasd /src/obj-firefox/dist/include/something.h:102:9\n" \
            "    #3 0x000098fc in mz::as::asdf::SB() /src/Blah.cpp:655\n"
        stack = Stack.from_text(input_txt)
        self.assertEqual(len(stack.frames), 4)
        self.assertEqual(stack.frames[0].location, "swr_a.so")
        self.assertEqual(stack.frames[1].location, "as.so.1")
        self.assertEqual(stack.frames[2].function, "fSasd")
        self.assertEqual(stack.frames[3].function, "mz::as::asdf::SB")
        self.assertNotEqual(stack.minor, stack.major)
        self.assertEqual(stack.frames[0].mode, StackFrame.MODE_ASAN)


class StackFrameTests(TestCase):

    def test_01(self):
        "test creating an empty StackFrame"
        stack = StackFrame()
        self.assertEqual(stack.__str__(), "")

    def test_02(self):
        "test creating a StackFrame from junk"
        self.assertIsNone(StackFrame.from_line("#0      "))
        self.assertIsNone(StackFrame.from_line(" #0 "))
        #with self.assertRaisesRegex(AssertionError, "Input contains unexpected new line(s)"):
        #    StackFrame.from_line("#0 \n \n\n\n#1\n\ntest()!")
        self.assertIsNone(StackFrame.from_line("#0#0#0#0#0#0#0#0"))
        self.assertIsNone(StackFrame.from_line("#a"))
        self.assertIsNone(StackFrame.from_line(""))
        self.assertIsNone(StackFrame.from_line("###"))
        self.assertIsNone(StackFrame.from_line("123"))
        self.assertIsNone(StackFrame.from_line("test()"))


class ASanStackFrameSupportTests(TestCase):
    def test_01(self):
        "test creating a StackFrame from an ASan line with symbols"
        frame = StackFrame.from_line("    #1 0x7f00dad60565 in Abort(char const*) /blah/base/nsDebugImpl.cpp:472")
        self.assertEqual(frame.stack_line, "1")
        self.assertEqual(frame.function, "Abort")
        self.assertEqual(frame.location, "nsDebugImpl.cpp")
        self.assertEqual(frame.offset, "472")
        self.assertEqual(frame.mode, StackFrame.MODE_ASAN)

    def test_02(self):
        "test creating a StackFrame from an ASan line with symbols"
        frame = StackFrame.from_line("    #36 0x48a6e4 in main /app/nsBrowserApp.cpp:399:11")
        self.assertEqual(frame.stack_line, "36")
        self.assertEqual(frame.function, "main")
        self.assertEqual(frame.location, "nsBrowserApp.cpp")
        self.assertEqual(frame.offset, "399")
        self.assertEqual(frame.mode, StackFrame.MODE_ASAN)

    def test_03(self):
        "test creating a StackFrame from an ASan line without symbols"
        frame = StackFrame.from_line("    #1 0x7f00ecc1b33f (/lib/x86_64-linux-gnu/libpthread.so.0+0x1033f)")
        self.assertEqual(frame.stack_line, "1")
        self.assertIsNone(frame.function)
        self.assertEqual(frame.location, "libpthread.so.0")
        self.assertEqual(frame.offset, "0x1033f")
        self.assertEqual(frame.mode, StackFrame.MODE_ASAN)

    def test_04(self):
        "test creating a StackFrame from an ASan line with symbols"
        frame = StackFrame.from_line("    #25 0x7f0155526181 in start_thread (/l/libpthread.so.0+0x8181)")
        self.assertEqual(frame.stack_line, "25")
        self.assertEqual(frame.function, "start_thread")
        self.assertEqual(frame.location, "libpthread.so.0")
        self.assertEqual(frame.offset, "0x8181")
        self.assertEqual(frame.mode, StackFrame.MODE_ASAN)

    def test_05(self):
        "test creating a StackFrame from an ASan line with angle brackets"
        frame = StackFrame.from_line("    #123 0x7f30afea9148 in Call<nsBlah *> /a/b.cpp:356:50")
        self.assertEqual(frame.stack_line, "123")
        self.assertEqual(frame.function, "Call")
        self.assertEqual(frame.location, "b.cpp")
        self.assertEqual(frame.offset, "356")
        self.assertEqual(frame.mode, StackFrame.MODE_ASAN)

    def test_05(self):
        "test creating a StackFrame from a useless frame"
        frame = StackFrame.from_line("    #2 0x7ffffffff  (<unknown module>)")
        self.assertEqual(frame.stack_line, "2")
        self.assertIsNone(frame.function)
        self.assertEqual(frame.location, "<unknown module>")
        self.assertIsNone(frame.offset)
        self.assertEqual(frame.mode, StackFrame.MODE_ASAN)

class GDBStackFrameSupportTests(TestCase):
    def test_01(self):
        "test creating a StackFrame from a GDB line with symbols"
        frame = StackFrame.from_line("#0  __memmove_ssse3_back () at ../d/x86_64/a/memcpy-ssse3-back.S:1654")
        self.assertEqual(frame.stack_line, "0")
        self.assertEqual(frame.function, "__memmove_ssse3_back")
        self.assertEqual(frame.location, "memcpy-ssse3-back.S")
        self.assertEqual(frame.offset, "1654")
        self.assertEqual(frame.mode, StackFrame.MODE_GDB)

    def test_02(self):
        "test creating a StackFrame from a GDB line with symbols but no line numbers"
        frame = StackFrame.from_line("#2  0x0000000000400545 in main ()")
        self.assertEqual(frame.stack_line, "2")
        self.assertEqual(frame.function, "main")
        self.assertIsNone(frame.location)
        self.assertIsNone(frame.offset)
        self.assertEqual(frame.mode, StackFrame.MODE_GDB)

    def test_03(self):
        "test creating a StackFrame from a GDB line with symbols"
        frame = StackFrame.from_line("#3  0x0000000000400545 in main () at test.c:5")
        self.assertEqual(frame.stack_line, "3")
        self.assertEqual(frame.function, "main")
        self.assertEqual(frame.location, "test.c")
        self.assertEqual(frame.offset, "5")
        self.assertEqual(frame.mode, StackFrame.MODE_GDB)

    # windbg support tests
    #print parse_line("006fd6f4 7149b958 xul!nsLayoutUtils::AppUnitWidthOfStringBidi+0x6c")
    #print parse_line("006fd6f4 7149b958 xul!nsLayoutUtils::AppUnitWidthOfStringBidi+0x6c")
    #print parse_line("(Inline) -------- xul!SkTDArray<SkAAClip::Builder::Row>::append+0xc")
