# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import sys
import unittest

from grizzly.stack_hasher import Stack, StackFrame


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
        self.assertGreater(stack._major_depth, 0)  # pylint: disable=protected-access

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
            "==7854==ABORTING\n"
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

    def test_12(self):
        "test"
        input_txt = "" \
            "==4754== \n" \
            "==4754== Use of uninitialised value of size 8\n" \
            "==4754==    at 0x45C6C0: FooBar (decode.c:964)\n" \
            "==4754==    by 0x462A20: main (test.cc:71)\n" \
            "==4754==  Uninitialised value was created by a heap allocation\n" \
            "==4754==    at 0x4C2AB80: malloc (in /usr/lib/test-linux.so)\n" \
            "==4754==    by 0x459455: FooBar (decode.c:757)\n" \
            "==4754==    by 0x462A20: main (test.cc:71)\n" \
            "==4754== \n"
        stack = Stack.from_text(input_txt)
        self.assertEqual(len(stack.frames), 5)
        self.assertEqual(stack.frames[0].location, "decode.c")
        self.assertEqual(stack.frames[1].location, "test.cc")
        self.assertEqual(stack.frames[2].function, "malloc")
        self.assertEqual(stack.frames[3].function, "FooBar")
        self.assertEqual(stack.frames[4].function, "main")
        self.assertNotEqual(stack.minor, stack.major)
        self.assertEqual(stack.frames[0].mode, StackFrame.MODE_VALGRIND)

    def test_13(self):
        "test creating a Stack from Rust trace"
        input_txt = "" \
        "thread '<unnamed>' panicked at 'Invoking Servo_Element_IsDisplayContents on unstyled element', libcore/option.rs:917:5\n" \
        "stack backtrace:\n" \
        "   0:     0x7ff1c65e93d3 - std::sys::unix::backtrace::tracing::imp::unwind_backtrace::h09c1ee131a74b1c4\n" \
        "                               at libstd/sys/unix/backtrace/tracing/gcc_s.rs:49\n" \
        "   1:     0x7ff1c65e81c4 - std::panicking::default_hook::{{closure}}::h945a649c9017832e\n" \
        "                               at libstd/sys_common/backtrace.rs:71\n" \
        "                               at libstd/sys_common/backtrace.rs:59\n" \
        "                               at libstd/panicking.rs:380\n" \
        "   2:     0x7ff1c65e7457 - std::panicking::default_hook::hcc534c2d30fbcda3\n" \
        "                               at libstd/panicking.rs:396\n" \
        "   3:     0x7ff1c65e6de7 - std::panicking::rust_panic_with_hook::h09a7a3a353dc2f38\n" \
        "                               at libstd/panicking.rs:576\n" \
        "   4:     0x7ff1c65e6c95 - std::panicking::begin_panic::h8327f16bde15df70\n" \
        "                               at libstd/panicking.rs:537\n" \
        "   5:     0x7ff1c65e6c29 - std::panicking::begin_panic_fmt::h42ff1d37404632d6\n" \
        "                               at libstd/panicking.rs:521\n" \
        "   6:     0x7ff1c65fa46a - core::panicking::panic_fmt::h0bd854df201d1baf\n" \
        "                               at libstd/panicking.rs:497\n" \
        "   7:     0x7ff1c65ffba8 - core::option::expect_failed::hfa0c8a51e07f7adc\n" \
        "                               at libcore/option.rs:917\n" \
        "   8:     0x7ff1c632d473 - Servo_Element_IsDisplayContents\n" \
        "                               at /checkout/src/libcore/option.rs:302\n" \
        "                               at servo/ports/geckolib/glue.rs:1086\n" \
        "   9:     0x7f44064ee749 - _ZNK7nsFrame24DoGetParentComputedStyleEPP8nsIFrame\n" \
        "                                at /builds/worker/workspace/build/src/layout/generic/nsFrame.cpp:9893\n" \
        "   10:     0x7f4406229749 - _ZN7mozilla14RestyleManager35DoReparentComputedStyleForFirstLineEP8nsIFrameRNS_13ServoStyleSetE\n" \
        "                                at /builds/worker/workspace/build/src/layout/base/RestyleManager.cpp:3407\n" \
        "   11:     0x7f440622a0a5 - _ZN7mozilla14RestyleManager24ReparentFrameDescendantsEP8nsIFrameS2_RNS_13ServoStyleSetE\n" \
        "                                at /builds/worker/workspace/build/src/layout/base/RestyleManager.cpp:3538\n"
        stack = Stack.from_text(input_txt)
        self.assertEqual(len(stack.frames), 12)
        self.assertEqual(stack.frames[0].function, "std::sys::unix::backtrace::tracing::imp::unwind_backtrace")
        self.assertEqual(stack.frames[8].function, "Servo_Element_IsDisplayContents")
        self.assertNotEqual(stack.minor, stack.major)
        self.assertEqual(stack.frames[0].mode, StackFrame.MODE_RUST)


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
        self.assertIsNone(StackFrame.from_line("|||"))
        self.assertIsNone(StackFrame.from_line("==123=="))
        self.assertIsNone(StackFrame.from_line("==1== by 0x0: a ()"))


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

    def test_06(self):
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


class MinidumpStackFrameSupportTests(TestCase):
    def test_01(self):
        "test creating a StackFrame from a Minidump line with symbols"
        frame = StackFrame.from_line("0|2|libtest|main|hg:c.a.org/m-c:a/b/file.cpp:5bf50|114|0x3a")
        self.assertEqual(frame.stack_line, "2")
        self.assertEqual(frame.function, "main")
        self.assertEqual(frame.location, "file.cpp")
        self.assertEqual(frame.offset, "114")
        self.assertEqual(frame.mode, StackFrame.MODE_MINIDUMP)

    def test_02(self):
        "test creating a StackFrame from a Minidump line without symbols"
        frame = StackFrame.from_line("9|42|libpthread-2.26.so||||0x10588")
        self.assertEqual(frame.stack_line, "42")
        self.assertIsNone(frame.function)
        self.assertEqual(frame.location, "libpthread-2.26.so")
        self.assertEqual(frame.offset, "0x10588")
        self.assertEqual(frame.mode, StackFrame.MODE_MINIDUMP)


class ValgrindStackFrameSupportTests(TestCase):
    def test_01(self):
        frame = StackFrame.from_line("==4754==    at 0x45C6C0: FuncName (decode.c:123)")
        self.assertIsNone(frame.stack_line)
        self.assertEqual(frame.function, "FuncName")
        self.assertEqual(frame.location, "decode.c")
        self.assertEqual(frame.offset, "123")
        self.assertEqual(frame.mode, StackFrame.MODE_VALGRIND)

    def test_02(self):
        frame = StackFrame.from_line("==4754==    by 0x462A20: main (foo.cc:71)")
        self.assertIsNone(frame.stack_line)
        self.assertEqual(frame.function, "main")
        self.assertEqual(frame.location, "foo.cc")
        self.assertEqual(frame.offset, "71")
        self.assertEqual(frame.mode, StackFrame.MODE_VALGRIND)

    def test_03(self):
        frame = StackFrame.from_line("==4754==    at 0x4C2AB80: malloc (in /usr/lib/blah-linux.so)")
        self.assertIsNone(frame.stack_line)
        self.assertEqual(frame.function, "malloc")
        self.assertEqual(frame.location, "blah-linux.so")
        self.assertIsNone(frame.offset)
        self.assertEqual(frame.mode, StackFrame.MODE_VALGRIND)

    def test_04(self):
        frame = StackFrame.from_line("==2342==    by 0x4E3E71: (anon ns)::test(b2::a&, int) (main.cpp:49)")
        self.assertIsNone(frame.stack_line)
        self.assertEqual(frame.function, "(anon ns)::test(b2::a&, int)")
        self.assertEqual(frame.location, "main.cpp")
        self.assertEqual(frame.offset, "49")
        self.assertEqual(frame.mode, StackFrame.MODE_VALGRIND)

    def test_05(self):
        frame = StackFrame.from_line("==2342==    at 0xF00D: Foo::Foo(char *, int, bool) (File.h:37)")
        self.assertIsNone(frame.stack_line)
        self.assertEqual(frame.function, "Foo::Foo(char *, int, bool)")
        self.assertEqual(frame.location, "File.h")
        self.assertEqual(frame.offset, "37")
        self.assertEqual(frame.mode, StackFrame.MODE_VALGRIND)


class RRStackFrameSupportTests(TestCase):
    def test_01(self):
        frame = StackFrame.from_line("rr(main+0x244)[0x450b74]")
        self.assertIsNone(frame.stack_line)
        self.assertIsNone(frame.function)
        self.assertEqual(frame.location, "main")
        self.assertEqual(frame.offset, "0x244")
        self.assertEqual(frame.mode, StackFrame.MODE_RR)


class RustStackFrameSupportTests(TestCase):
    def test_01(self):
        "test creating a StackFrame from stack line"
        frame = StackFrame.from_line("  53:    0x7ff1d7e4982f - __libc_start_main")
        self.assertEqual(frame.stack_line, "53")
        self.assertIsNone(frame.location)
        self.assertEqual(frame.function, "__libc_start_main")
        self.assertIsNone(frame.offset)
        self.assertEqual(frame.mode, StackFrame.MODE_RUST)

    def test_02(self):
        "test creating a StackFrame from stack line"
        frame = StackFrame.from_line("  4:    0x10b715a5b - unwind::begin_unwind_fmt::h227376fe1e021a36n3d")
        self.assertEqual(frame.stack_line, "4")
        self.assertIsNone(frame.location)
        self.assertEqual(frame.function, "unwind::begin_unwind_fmt")
        self.assertIsNone(frame.offset)
        self.assertEqual(frame.mode, StackFrame.MODE_RUST)

    # windbg support tests
    #print parse_line("006fd6f4 7149b958 xul!nsLayoutUtils::AppUnitWidthOfStringBidi+0x6c")
    #print parse_line("006fd6f4 7149b958 xul!nsLayoutUtils::AppUnitWidthOfStringBidi+0x6c")
    #print parse_line("(Inline) -------- xul!SkTDArray<SkAAClip::Builder::Row>::append+0xc")
