# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import pytest

from .stack_hasher import Mode, Stack, StackFrame


def test_stack_01():
    """test creating an empty Stack"""
    stack = Stack()
    assert stack.minor is None
    assert isinstance(stack.frames, list)
    assert stack._major_depth > 0  # pylint: disable=protected-access


def test_stack_02():
    """test creating a Stack with 1 frame"""
    frames = [StackFrame(function="a", location="b", offset="c", stack_line="0")]
    stack = Stack(frames=frames)
    assert stack.minor is not None
    assert stack.major is not None
    # at this point the hashes should match
    assert stack.minor == stack.major
    assert len(stack.frames) == 1
    output = str(stack)
    assert "00" in output
    assert "function: 'a'" in output
    assert "location: 'b'" in output
    assert "offset: 'c'" in output


def test_stack_03():
    """test creating a Stack with 2 frames"""
    frames = list()
    for _ in range(2):
        frames.append(
            StackFrame(function="a", location="b", offset="c", stack_line="0")
        )
    stack = Stack(frames=frames, major_depth=2)
    assert stack.minor is not None
    assert stack.major is not None
    # at this point the hashes should not match because offset on the major hash is
    # only added from the top frame
    assert stack.minor != stack.major
    assert len(stack.frames) == 2


def test_stack_04():
    """test creating a Stack with 2 frames with a major depth of 0"""
    frames = list()
    for line in range(2):
        frames.append(
            StackFrame(function="a", location="b", offset="c", stack_line=str(line))
        )
    stack = Stack(frames=frames, major_depth=0)
    assert stack.minor is not None
    assert stack.major is None
    # at this point the hashes should not match because offset on the major hash is
    # only added from the top frame
    assert stack.minor != stack.major
    assert len(stack.frames) == 2


def test_stack_05():
    """test creating a Stack with 10 frames exceeding major depth"""
    frames = list()
    for line in range(10):
        frames.append(
            StackFrame(function="a", location="b", offset="c", stack_line=str(line))
        )
    stack = Stack(frames=frames, major_depth=5)
    assert stack.minor is not None
    assert stack.major is not None
    # at this point the hashes should not match because offset on the major hash is
    # only added from the top frame
    assert stack.minor != stack.major
    assert len(stack.frames) == 10
    assert stack.major != Stack(frames=frames, major_depth=4).major


def test_stack_06():
    """test creating a Stack by calling from_text()"""
    input_txt = (
        "=================================================================\n"
        "==7854==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000"
        " (pc 0x7fcca620e0ee bp 0x7ffd946b2690 sp 0x7ffd946b25c0 T0)\n"
        "==7854==blah.\n"
        "==7854==Hint: blah.\n"
        "    #0 0x7fcca620e0ed in test::test::test(nsIWa*, nsICa*)"
        " /aa/bb/cc/dd/ee/ff/gg/asdf.cpp:5533:14\n"
        "    #1 0x7fcca3497201 in nsAs::TestTest(mz::dom::El*, int)"
        " /aa/bb/cc/dd/ee/ff/nsFilea.cpp:13733:3\n"
        "    #2 0x7fcca3495b9b in asdf::fasd()"
        " /aa/bb/cc/dd/ee/ff/base/nsFileb.cpp:11674:21\n"
        "    #3 0x7fcca02eb9d8 in nsAasd::PrNeEv(bool, bool*)"
        " /aa/bb/cc/dd/ee/xpcom/nsFilec.cpp:1396:14\n"
        "    #4 0x7fcca0307d40 in R_PNE(asd*, bool)"
        " /aa/bb/cc/dd/ee/xpcom/threads/asf.cpp:657:10\n"
        "    #5 0x2a780b25f65a  (<unknown module>)\n"
        "\n"
        "AddressSanitizer can not provide additional info.\n"
        "SUMMARY: AddressSanitizer: SEGV /aa/bb/cc/dd/ee/ff/asdf.cpp:5533:14"
        " in test::test::test(nsIWa*, nsICa*)\n"
        "==7854==ABORTING\n"
    )
    stack = Stack.from_text(input_txt)
    assert len(stack.frames) == 6
    assert stack.minor != stack.major
    assert stack.frames[0].mode == Mode.SANITIZER


def test_stack_07():
    """test creating a Stack by calling from_text() with mixed frames modes"""
    input_txt = (
        ""
        "    #0 0x4d2cde in a_b_c /a/lib/info.c:392:12\n"
        "    #1 0x491e82 in main /a/b/d_e.c:128:8\n"
        "    #2 0x7f090384582f in __libc_start_main /build/glibc-glibc-2.23/csu/"
        "../csu/libc-start.c:291\n"
        "#2  0x0000000000400545 in gdb_frame ()\n"
        "    #3 0x41b228 in _start (bin_name+0x41b228)\n"
    )
    stack = Stack.from_text(input_txt)
    assert len(stack.frames) == 4
    assert stack.minor != stack.major
    assert stack.frames[0].mode == Mode.SANITIZER


def test_stack_08():
    """test creating a Stack by calling from_text() with text containing 2 stacks"""
    input_txt = (
        ""
        "    #0 0x0bad0bad in bad::frame0(nsA*, nsB*) /aa/a.cpp:12:1\n"
        "    #1 0x0bad0bad in bad::frame1(mz::d::EE*, int) /aa/a.cpp:12:1\n"
        "    #0 0x1badf00d in good::frame0(nsA*, nsB*) /aa/a.cpp:12:1\n"
        "    #1 0xdeadbeef in good::frame1(mz::d::EE*, int) /aa/a.cpp:12:1\n"
    )
    stack = Stack.from_text(input_txt)
    assert len(stack.frames) == 2
    assert stack.frames[0].function == "good::frame0"
    assert stack.frames[1].function == "good::frame1"
    assert stack.minor != stack.major
    assert stack.frames[0].mode == Mode.SANITIZER


def test_stack_09():
    """test creating a Stack by calling from_text() with empty string"""
    stack = Stack.from_text("")
    assert not stack.frames
    assert stack.minor is None
    assert stack.major is None


def test_stack_10():
    """test creating a Stack from a Sanitizer trace with an unsymbolized lib"""
    input_txt = (
        ""
        "    #0 0x4c7702 in realloc asan/asan_malloc_linux.cc:107:3\n"
        "    #1 0x7f6d056ce7fc  (/lib/x86_64-linux-gnu/libdbus-1.so.3+0x2d7fc)\n"
        "    #2 0x7ffffffff  (<unknown module>)\n"
    )
    stack = Stack.from_text(input_txt)
    assert len(stack.frames) == 3
    assert stack.frames[0].location == "asan_malloc_linux.cc"
    assert stack.frames[1].location == "libdbus-1.so.3"
    assert stack.frames[2].location == "<unknown module>"
    assert stack.minor != stack.major
    assert stack.frames[0].mode == Mode.SANITIZER


def test_stack_11():
    """test creating a Stack from a Sanitizer trace with an unsymbolized lib"""
    input_txt = (
        ""
        "    #0 0x90000223  (/usr/swr_a.so+0x231223)\n"
        "    #1 0x00000447  (/usr/as.so.1+0x42447)\n"
        "    #2 0x000098fc in fSasd /src/obj-firefox/dist/include/something.h:102:9\n"
        "    #3 0x000098fc in mz::as::asdf::SB() /src/Blah.cpp:655\n"
    )
    stack = Stack.from_text(input_txt)
    assert len(stack.frames) == 4
    assert stack.frames[0].location == "swr_a.so"
    assert stack.frames[1].location == "as.so.1"
    assert stack.frames[2].function == "fSasd"
    assert stack.frames[3].function == "mz::as::asdf::SB"
    assert stack.minor != stack.major
    assert stack.frames[0].mode == Mode.SANITIZER


def test_stack_12():
    """test creating a Stack from a Valgrind trace"""
    input_txt = (
        ""
        "==4754== \n"
        "==4754== Use of uninitialised value of size 8\n"
        "==4754==    at 0x45C6C0: FooBar (decode.c:964)\n"
        "==4754==    by 0x462A20: main (test.cc:71)\n"
        "==4754==  Uninitialised value was created by a heap allocation\n"
        "==4754==    at 0x4C2AB80: malloc (in /usr/lib/test-linux.so)\n"
        "==4754==    by 0x459455: FooBar (decode.c:757)\n"
        "==4754==    by 0x462A20: main (test.cc:71)\n"
        "==4754== \n"
    )
    stack = Stack.from_text(input_txt)
    assert len(stack.frames) == 5
    assert stack.frames[0].location == "decode.c"
    assert stack.frames[1].location == "test.cc"
    assert stack.frames[2].function == "malloc"
    assert stack.frames[3].function == "FooBar"
    assert stack.frames[4].function == "main"
    assert stack.minor != stack.major
    assert stack.frames[0].mode == Mode.VALGRIND


def test_stack_13():
    """test creating a Stack from Rust trace"""
    input_txt = (
        "thread '<unnamed>' panicked at 'Invoking Servo_Element_IsDisplayContents"
        " on unstyled element', libcore/option.rs:917:5\n"
        "stack backtrace:\n"
        "   0:     0x7ff1c65e93d3 - std::sys::unix::backtrace::tracing::imp::unwind_bac"
        "ktrace::h09c1ee131a74b1c4\n"
        "                               at libstd/sys/unix/backtrace/tracing/gcc_s.rs:4"
        "9\n"
        "   1:     0x7ff1c65e81c4 - std::panicking::default_hook::{{closure}}::h945a649"
        "c9017832e\n"
        "                               at libstd/sys_common/backtrace.rs:71\n"
        "                               at libstd/sys_common/backtrace.rs:59\n"
        "                               at libstd/panicking.rs:380\n"
        "   2:     0x7ff1c65e7457 - std::panicking::default_hook::hcc534c2d30fbcda3\n"
        "                               at libstd/panicking.rs:396\n"
        "   3:     0x7ff1c65e6de7 - std::panicking::rust_panic_with_hook::h09a7a3a353dc"
        "2f38\n"
        "                               at libstd/panicking.rs:576\n"
        "   4:     0x7ff1c65e6c95 - std::panicking::begin_panic::h8327f16bde15df70\n"
        "                               at libstd/panicking.rs:537\n"
        "   5:     0x7ff1c65e6c29 - std::panicking::begin_panic_fmt::h42ff1d3740463d6\n"
        "                               at libstd/panicking.rs:521\n"
        "   6:     0x7ff1c65fa46a - core::panicking::panic_fmt::h0bd854df201d1baf\n"
        "                               at libstd/panicking.rs:497\n"
        "   7:     0x7ff1c65ffba8 - core::option::expect_failed::hfa0c8a51e07f7adc\n"
        "                               at libcore/option.rs:917\n"
        "   8:     0x7ff1c632d473 - Servo_Element_IsDisplayContents\n"
        "                               at /checkout/src/libcore/option.rs:302\n"
        "                               at servo/ports/geckolib/glue.rs:1086\n"
        "   9:     0x7f44064ee749 - _ZNK7nsFrame24DoGetParentComputedStyleEPPnsIFrame\n"
        "                                at /builds/worker/workspace/build/src/layout/g"
        "eneric/nsFrame.cpp:9893\n"
        "   10:     0x7f4406229749 - _ZN7mozilla14RestyleManager35DoReparentComputedSty"
        "leForFirstLineEP8nsIFrameRNS_13ServoStyleSetE\n"
        "                                at /builds/worker/workspace/build/src/layout/b"
        "ase/RestyleManager.cpp:3407\n"
        "   11:     0x7f440622a0a5 - _ZN7mozilla14RestyleManager24ReparentFrameDescenda"
        "ntsEP8nsIFrameS2_RNS_13ServoStyleSetE\n"
        "                                at /builds/worker/workspace/build/src/layout/b"
        "ase/RestyleManager.cpp:3538\n"
    )
    stack = Stack.from_text(input_txt)
    assert len(stack.frames) == 12
    assert (
        stack.frames[0].function
        == "std::sys::unix::backtrace::tracing::imp::unwind_backtrace"
    )
    assert stack.frames[8].function == "Servo_Element_IsDisplayContents"
    assert stack.minor != stack.major
    assert stack.frames[0].mode == Mode.RUST


def test_stack_14():
    """test Stack.height_limit"""
    frames = list()
    for num in range(10):
        frames.append(
            StackFrame(function=str(num), location="b", offset="c", stack_line=str(num))
        )
    stack = Stack(frames=frames, major_depth=3)
    assert stack.height_limit is None
    no_lim_minor = stack.minor
    assert no_lim_minor is not None
    no_lim_major = stack.major
    assert no_lim_major is not None
    # set height limit and check hash recalculations
    stack.height_limit = 5
    assert stack.height_limit == 5
    assert stack.minor is not None
    assert no_lim_minor != stack.minor
    assert stack.major is not None
    assert no_lim_major != stack.major
    # remove height limit and check hash recalculations
    stack.height_limit = None
    assert stack.height_limit is None
    assert no_lim_minor == stack.minor
    assert no_lim_major == stack.major


def test_stackframe_01():
    """test creating an empty StackFrame"""
    stack = StackFrame()
    assert not stack.__str__()


def test_stackframe_02():
    """test creating a StackFrame from junk"""
    assert StackFrame.from_line("#0      ") is None
    assert StackFrame.from_line(" #0 ") is None
    with pytest.raises(AssertionError) as exc:
        StackFrame.from_line("#0 \n \n\n\n#1\n\ntest()!")
    assert "Input contains unexpected new line(s)" in str(exc.value)
    assert StackFrame.from_line("#0#0#0#0#0#0#0#0") is None
    assert StackFrame.from_line("#a") is None
    assert StackFrame.from_line("") is None
    assert StackFrame.from_line("###") is None
    assert StackFrame.from_line("123") is None
    assert StackFrame.from_line("test()") is None
    assert StackFrame.from_line("|||") is None
    assert StackFrame.from_line("==123==") is None
    assert StackFrame.from_line("==1== by 0x0: a ()") is None


def test_sanitizer_stackframe_01():
    """test creating a StackFrame from a line with symbols"""
    frame = StackFrame.from_line(
        "    #1 0x7f00dad60565 in Abort(char const*) /blah/base/nsDebugImpl.cpp:472"
    )
    assert frame.stack_line == "1"
    assert frame.function == "Abort"
    assert frame.location == "nsDebugImpl.cpp"
    assert frame.offset == "472"
    assert frame.mode == Mode.SANITIZER


def test_sanitizer_stackframe_02():
    """test creating a StackFrame from a line with symbols"""
    frame = StackFrame.from_line(
        "    #36 0x48a6e4 in main /app/nsBrowserApp.cpp:399:11"
    )
    assert frame.stack_line == "36"
    assert frame.function == "main"
    assert frame.location == "nsBrowserApp.cpp"
    assert frame.offset == "399"
    assert frame.mode == Mode.SANITIZER


def test_sanitizer_stackframe_03():
    """test creating a StackFrame from a line without symbols"""
    frame = StackFrame.from_line(
        "    #1 0x7f00ecc1b33f (/lib/x86_64-linux-gnu/libpthread.so.0+0x1033f)"
    )
    assert frame.stack_line == "1"
    assert frame.function is None
    assert frame.location == "libpthread.so.0"
    assert frame.offset == "0x1033f"
    assert frame.mode == Mode.SANITIZER


def test_sanitizer_stackframe_04():
    """test creating a StackFrame from a line with symbols"""
    frame = StackFrame.from_line(
        "    #25 0x7f0155526181 in start_thread (/l/libpthread.so.0+0x8181)"
    )
    assert frame.stack_line == "25"
    assert frame.function == "start_thread"
    assert frame.location == "libpthread.so.0"
    assert frame.offset == "0x8181"
    assert frame.mode == Mode.SANITIZER


def test_sanitizer_stackframe_05():
    """test creating a StackFrame from a line with angle brackets"""
    frame = StackFrame.from_line(
        "    #123 0x7f30afea9148 in Call<nsBlah *> /a/b.cpp:356:50"
    )
    assert frame.stack_line == "123"
    assert frame.function == "Call"
    assert frame.location == "b.cpp"
    assert frame.offset == "356"
    assert frame.mode == Mode.SANITIZER


def test_sanitizer_stackframe_06():
    """test creating a StackFrame from a useless frame"""
    frame = StackFrame.from_line("    #2 0x7ffffffff  (<unknown module>)")
    assert frame.stack_line == "2"
    assert frame.function is None
    assert frame.location == "<unknown module>"
    assert frame.offset is None
    assert frame.mode == Mode.SANITIZER


def test_sanitizer_stackframe_07():
    """test creating a StackFrame from a line missing a function"""
    frame = StackFrame.from_line(
        "    #0 0x7f0d571e04bd  /a/glibc-2.23/../syscall-template.S:84"
    )
    assert frame.stack_line == "0"
    assert frame.function is None
    assert frame.location == "syscall-template.S"
    assert frame.offset == "84"
    assert frame.mode == Mode.SANITIZER


def test_sanitizer_stackframe_08():
    """test creating a StackFrame from a line with lots of spaces"""
    frame = StackFrame.from_line(
        "    #0 0x48a6e4 in Call<a *> /test path/file name.c:1:2"
    )
    assert frame.stack_line == "0"
    assert frame.function == "Call"
    assert frame.location == "file name.c"
    assert frame.offset == "1"
    assert frame.mode == Mode.SANITIZER


def test_gdb_stackframe_01():
    """test creating a StackFrame from a GDB line with symbols"""
    frame = StackFrame.from_line(
        "#0  __memmove_ssse3_back () at ../d/x86_64/a/memcpy-ssse3-back.S:1654"
    )
    assert frame.stack_line == "0"
    assert frame.function == "__memmove_ssse3_back"
    assert frame.location == "memcpy-ssse3-back.S"
    assert frame.offset == "1654"
    assert frame.mode == Mode.GDB


def test_gdb_stackframe_02():
    """test creating a StackFrame from a GDB line with symbols but no line numbers"""
    frame = StackFrame.from_line("#2  0x0000000000400545 in main ()")
    assert frame.stack_line == "2"
    assert frame.function == "main"
    assert frame.location is None
    assert frame.offset is None
    assert frame.mode == Mode.GDB


def test_gdb_stackframe_03():
    """test creating a StackFrame from a GDB line with symbols"""
    frame = StackFrame.from_line("#3  0x0000000000400545 in main () at test.c:5")
    assert frame.stack_line == "3"
    assert frame.function == "main"
    assert frame.location == "test.c"
    assert frame.offset == "5"
    assert frame.mode == Mode.GDB


def test_minidump_stackframe_01():
    """test creating a StackFrame from a Minidump line with symbols"""
    frame = StackFrame.from_line(
        "0|2|libtest|main|hg:c.a.org/m-c:a/b/file.cpp:5bf50|114|0x3a"
    )
    assert frame.stack_line == "2"
    assert frame.function == "main"
    assert frame.location == "file.cpp"
    assert frame.offset == "114"
    assert frame.mode == Mode.MINIDUMP


def test_minidump_stackframe_02():
    """test creating a StackFrame from a Minidump line without symbols"""
    frame = StackFrame.from_line("9|42|libpthread-2.26.so||||0x10588")
    assert frame.stack_line == "42"
    assert frame.function is None
    assert frame.location == "libpthread-2.26.so"
    assert frame.offset == "0x10588"
    assert frame.mode == Mode.MINIDUMP


def test_minidump_stackframe_03():
    """test creating a StackFrame from a Minidump line without hg repo info"""
    frame = StackFrame.from_line(
        "0|49|libxul.so|foo|/usr/x86_64-linux-gnu/test.h|85|0x5"
    )
    assert frame.stack_line == "49"
    assert frame.function == "foo"
    assert frame.location == "/usr/x86_64-linux-gnu/test.h"
    assert frame.offset == "85"
    assert frame.mode == Mode.MINIDUMP


def test_tsan_stackframe_01():
    """test creating a StackFrame from a symbolized TSan line"""
    frame = StackFrame.from_line("    #0 main race.c:10 (exe+0xa3b4)")
    assert frame.stack_line == "0"
    assert frame.function == "main"
    assert frame.location == "race.c"
    assert frame.offset == "10"
    assert frame.mode == Mode.TSAN


def test_tsan_stackframe_02():
    """test creating a StackFrame from a symbolized TSan line"""
    frame = StackFrame.from_line(
        "    #1 test1 test2 /a b/c.h:51:10 (libxul.so+0x18c9873)"
    )
    assert frame.stack_line == "1"
    assert frame.function == "test1"
    assert frame.location == "c.h"
    assert frame.offset == "51"
    assert frame.mode == Mode.TSAN


def test_tsan_stackframe_03():
    """test creating a StackFrame from an unsymbolized TSan line"""
    frame = StackFrame.from_line("    #2 <null> <null> (0xbad)")
    assert frame.stack_line == "2"
    assert frame.function is None
    assert frame.location is None
    assert frame.offset == "0xbad"
    assert frame.mode == Mode.TSAN


def test_tsan_stackframe_04():
    """test creating a StackFrame from a TSan line missing file"""
    frame = StackFrame.from_line("    #0 func <null> (mod+0x123ac)")
    assert frame.stack_line == "0"
    assert frame.function == "func"
    assert frame.location == "mod"
    assert frame.offset == "0x123ac"
    assert frame.mode == Mode.TSAN


def test_valgrind_stackframe_01():
    frame = StackFrame.from_line("==4754==    at 0x45C6C0: FuncName (decode.c:123)")
    assert frame.stack_line is None
    assert frame.function == "FuncName"
    assert frame.location == "decode.c"
    assert frame.offset == "123"
    assert frame.mode == Mode.VALGRIND


def test_valgrind_stackframe_02():
    frame = StackFrame.from_line("==4754==    by 0x462A20: main (foo.cc:71)")
    assert frame.stack_line is None
    assert frame.function == "main"
    assert frame.location == "foo.cc"
    assert frame.offset == "71"
    assert frame.mode == Mode.VALGRIND


def test_valgrind_stackframe_03():
    frame = StackFrame.from_line(
        "==4754==    at 0x4C2AB80: malloc (in /usr/lib/blah-linux.so)"
    )
    assert frame.stack_line is None
    assert frame.function == "malloc"
    assert frame.location == "blah-linux.so"
    assert frame.offset is None
    assert frame.mode == Mode.VALGRIND


def test_valgrind_stackframe_04():
    frame = StackFrame.from_line(
        "==2342==    by 0x4E3E71: (anon ns)::test(b2::a&, int) (main.cpp:49)"
    )
    assert frame.stack_line is None
    assert frame.function == "(anon ns)::test(b2::a&, int)"
    assert frame.location == "main.cpp"
    assert frame.offset == "49"
    assert frame.mode == Mode.VALGRIND


def test_valgrind_stackframe_05():
    frame = StackFrame.from_line(
        "==2342==    at 0xF00D: Foo::Foo(char *, int, bool) (File.h:37)"
    )
    assert frame.stack_line is None
    assert frame.function == "Foo::Foo(char *, int, bool)"
    assert frame.location == "File.h"
    assert frame.offset == "37"
    assert frame.mode == Mode.VALGRIND


def test_rr_stackframe_01():
    frame = StackFrame.from_line("rr(main+0x244)[0x450b74]")
    assert frame.stack_line is None
    assert frame.function is None
    assert frame.location == "main"
    assert frame.offset == "0x244"
    assert frame.mode == Mode.RR


def test_rust_stackframe_01():
    """test creating a Rust StackFrame from stack line"""
    frame = StackFrame.from_line("  53:    0x7ff1d7e4982f - __libc_start_main")
    assert frame.stack_line == "53"
    assert frame.function == "__libc_start_main"
    assert frame.location is None
    assert frame.offset is None
    assert frame.mode == Mode.RUST


def test_rust_stackframe_02():
    """test creating a Rust StackFrame from stack line"""
    frame = StackFrame.from_line(
        "  4:    0x10b715a5b - unwind::begin_unwind_fmt::h227376fe1e021a36n3d"
    )
    assert frame.stack_line == "4"
    assert frame.location is None
    assert frame.function == "unwind::begin_unwind_fmt"
    assert frame.offset is None
    assert frame.mode == Mode.RUST
