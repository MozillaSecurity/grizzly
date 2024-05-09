# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from pytest import mark

from .stack_hasher import (
    GdbStackFrame,
    MinidumpStackFrame,
    RrStackFrame,
    RustStackFrame,
    SanitizerStackFrame,
    Stack,
    StackFrame,
    ThreadSanitizerStackFrame,
    ValgrindStackFrame,
)


class BasicStackFrame(StackFrame):
    @classmethod
    def from_line(cls, input_line):
        # unused
        pass


def test_stack_01():
    """test creating an empty Stack"""
    stack = Stack([])
    assert stack.minor is None
    assert isinstance(stack.frames, list)
    assert stack._major_depth > 0  # pylint: disable=protected-access


def test_stack_02():
    """test creating a Stack with 1 generic frame"""
    frames = [BasicStackFrame(function="a", location="b", offset="c", stack_line="0")]
    stack = Stack(frames)
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
    frames = [
        BasicStackFrame(function="a", location="b", offset="c", stack_line="0")
        for _ in range(2)
    ]
    stack = Stack(frames, major_depth=2)
    assert stack.minor is not None
    assert stack.major is not None
    # at this point the hashes should not match because offset on the major hash is
    # only added from the top frame
    assert stack.minor != stack.major
    assert len(stack.frames) == 2


def test_stack_04():
    """test creating a Stack with 2 frames with a major depth of 0"""
    frames = [
        BasicStackFrame(function="a", location="b", offset="c", stack_line=str(line))
        for line in range(2)
    ]
    stack = Stack(frames, major_depth=0)
    assert stack.minor is not None
    assert stack.major is None
    # at this point the hashes should not match because offset on the major hash is
    # only added from the top frame
    assert stack.minor != stack.major
    assert len(stack.frames) == 2


def test_stack_05():
    """test creating a Stack with 10 frames exceeding major depth"""
    frames = [
        BasicStackFrame(function="a", location="b", offset="c", stack_line=str(line))
        for line in range(10)
    ]
    stack = Stack(frames, major_depth=5)
    assert stack.minor is not None
    assert stack.major is not None
    # at this point the hashes should not match because offset on the major hash is
    # only added from the top frame
    assert stack.minor != stack.major
    assert len(stack.frames) == 10
    assert stack.major != Stack(frames, major_depth=4).major


def test_stack_06():
    """test Stack.from_text() - single Sanitizer stack"""
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
    assert isinstance(stack.frames[0], SanitizerStackFrame)


def test_stack_07():
    """test Stack.from_text() - mixed frames modes"""
    input_txt = (
        ""
        "    #0 0x4d2cde in a_b_c /a/lib/info.c:392:12\n"
        "    #1 0x491e82 in main /a/b/d_e.c:128:8\n"
        "    #2 0x7f090384582f in __libc_start_main /build/a/../libc-start.c:291\n"
        "#0  0x0000000000400545 in gdb_frame ()\n"
        "    #3 0x41b228 in _start (bin_name+0x41b228)\n"
    )
    stack = Stack.from_text(input_txt)
    assert len(stack.frames) == 4
    assert stack.minor != stack.major
    assert isinstance(stack.frames[0], SanitizerStackFrame)


def test_stack_08():
    """test Stack.from_text() - multiple stacks"""
    input_txt = (
        "=================================================================\n"
        "==5540==ERROR: AddressSanitizer: ...\n"
        "    #0 0x1badf00d in good::frame0(nsA*, nsB*) /aa/a.cpp:12:1\n"
        "    #1 0xdeadbeef in good::frame1(mz::d::EE*, int) /aa/a.cpp:12:1\n\n"
        "0x12876 is located 1024 bytes after 4096-byte region [0x12876,0x12876)\n"
        "freed by thread T5 here:\n"
        "    #0 0x0bad0bad in bad::frame0(nsA*, nsB*) /aa/a.cpp:12:1\n"
        "    #1 0x0bad0bad in bad::frame1(mz::d::EE*, int) /aa/a.cpp:12:1\n\n"
        "0x12876 is located 1024 bytes after 4096-byte region [0x12876,0x12876)\n"
        "previously allocated by thread T0 here:\n"
        "    #0 0x0bad0bad in bad::frame0(nsA*, nsB*) /aa/a.cpp:12:1\n"
        "    #1 0x0bad0bad in bad::frame1(mz::d::EE*, int) /aa/a.cpp:12:1\n\n"
    )
    stack = Stack.from_text(input_txt)
    assert len(stack.frames) == 2
    assert stack.frames[0].function == "good::frame0"
    assert stack.frames[1].function == "good::frame1"
    assert stack.minor != stack.major
    assert isinstance(stack.frames[0], SanitizerStackFrame)


def test_stack_09():
    """test Stack.from_text() - empty string"""
    stack = Stack.from_text("")
    assert not stack.frames
    assert stack.minor is None
    assert stack.major is None


def test_stack_10():
    """test Stack.from_text() - Sanitizer trace with an unsymbolized lib"""
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
    assert isinstance(stack.frames[0], SanitizerStackFrame)


def test_stack_11():
    """test Stack.from_text() - Sanitizer trace with an unsymbolized lib"""
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
    assert isinstance(stack.frames[0], SanitizerStackFrame)


def test_stack_12():
    """test Stack.from_text() - Valgrind trace"""
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
    assert isinstance(stack.frames[0], ValgrindStackFrame)


def test_stack_13():
    """test Stack.from_text() - Rust trace"""
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
    assert isinstance(stack.frames[0], RustStackFrame)


def test_stack_14():
    """test Stack.height_limit"""
    frames = [
        BasicStackFrame(
            function=str(num), location="b", offset="c", stack_line=str(num)
        )
        for num in range(10)
    ]
    stack = Stack(frames, major_depth=3)
    assert stack.height_limit == 0
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
    stack.height_limit = 0
    assert stack.height_limit == 0
    assert no_lim_minor == stack.minor
    assert no_lim_major == stack.major


def test_stack_15():
    """test Stack.from_text() - trace missing #0"""
    stack = Stack.from_text("    #1 0x000098fc in frame1() test/a.cpp:655\n")
    assert len(stack.frames) == 1
    assert stack.frames[0].location == "a.cpp"
    assert stack.frames[0].function == "frame1"
    assert isinstance(stack.frames[0], SanitizerStackFrame)


def test_stack_16():
    """test Stack.from_text() - mixed traces"""
    stack = Stack.from_text(
        ""
        "    #0 0x0001230 in stack_1a() test/a.cpp:12\n"
        "    #2 0x0001231 in stack_2a() test/a.cpp:45\n"
        "    #1 0x0001232 in stack_1b() test/a.cpp:23\n"
        "    #2 0x0001233 in stack_1c() test/a.cpp:34\n"
    )
    assert len(stack.frames) == 1
    assert stack.frames[0].function == "stack_1a"
    assert isinstance(stack.frames[0], SanitizerStackFrame)


def test_stack_17():
    """test Stack.from_text() - contains ignored frames"""
    st_01 = (
        "#0 0x10 in MOZ_Crash /a.h:281:3\n"
        "#1 0x11 in std::panicking::ignored::hd80c17bcc51bbfda /l.rs:96:9\n"
        "#2 0x11 in std::panicking::ignored::hd80c17bcc51bbfda /l.rs:96:9\n"
        "#3 0x11 in foo_a /l.rs:1:9\n"
        "#4 0x11 in foo_b1111 /l.rs:2:9\n"
        "#5 0x11 in foo_c1111 /l.rs:3:9\n"
    )
    stack01 = Stack.from_text(st_01, major_depth=3)
    assert len(stack01.frames) == 6

    st_02 = (
        "#0 0x10 in MOZ_Crash /a.h:281:3\n"
        "#1 0x11 in std::panicking::ignored::hd80c17bcc51bbfda /l.rs:96:9\n"
        "#2 0x11 in std::panicking::ignored::hd80c17bcc51bbfda /l.rs:96:9\n"
        "#3 0x11 in foo_a /l.rs:1:9\n"
        "#4 0x11 in foo_b2222 /l.rs:2:9\n"
        "#5 0x11 in foo_c2222 /l.rs:3:9\n"
    )
    stack02 = Stack.from_text(st_02, major_depth=3)
    assert len(stack02.frames) == 6
    assert stack01.minor != stack02.minor
    assert stack01.major != stack02.major
    assert isinstance(stack01.frames[0], SanitizerStackFrame)


def test_stack_18():
    """test Stack.from_text() - multiple minidump stackwalk traces"""
    stack = Stack.from_text(
        "CPU|x86|GenuineIntel family 6 model 85 stepping 4|8\n"
        "Crash|EXCEPTION_BREAKPOINT|0x67a30091|44\n"
        "42|0|xul.dll|foo_a()|s3:g-g-sources:e/a.cpp:|14302|0x3f1\n"
        "42|1|xul.dll|foo_b()|s3:g-g-sources:e/a.cpp:|14302|0x3f1\n"
        "42|2|xul.dll|foo_c()|s3:g-g-sources:e/a.cpp:|14302|0x3f1\n"
        "43|0|xul.dll|bar_a()|s3:g-g-sources:e/a.cpp:|14302|0x3f1\n"
        "43|1|xul.dll|bar_b()|s3:g-g-sources:e/a.cpp:|14302|0x3f1\n"
        "43|2|xul.dll|bar_c()|s3:g-g-sources:e/a.cpp:|14302|0x3f1\n"
        "44|0|xul.dll|good_a()|s3:g-g-sources:e/a.cpp:|14302|0x3f1\n"
        "44|1|xul.dll|good_a()|s3:g-g-sources:e/a.cpp:|14302|0x3f1\n"
        "44|2|xul.dll|good_c()|s3:g-g-sources:e/a.cpp:|14302|0x3f1\n"
    )
    assert len(stack.frames) == 3
    assert stack.frames[0].function == "good_a()"
    assert isinstance(stack.frames[0], MinidumpStackFrame)


def test_stackframe_01():
    """test creating an empty generic BasicStackFrame"""
    stack = BasicStackFrame()
    assert not str(stack)


@mark.parametrize(
    "frame_class",
    (
        GdbStackFrame,
        MinidumpStackFrame,
        RrStackFrame,
        RustStackFrame,
        SanitizerStackFrame,
        ThreadSanitizerStackFrame,
        ValgrindStackFrame,
    ),
)
@mark.parametrize(
    "input_line",
    (
        "#0      ",
        " #0 ",
        "#0#0#0#0#0#0#0#0",
        "#a",
        "",
        "###",
        "123",
        "test()",
        "|||",
        "||||||",
        "a|b|c|d|e|f|g",
        "==123==",
        "==1== by 0x0: a ()",
        "rr(foo",
        "==1==    at 0x0: ??? (:)",
    ),
)
def test_stackframe_02(frame_class, input_line):
    """test StackFrame.from_line() - junk"""
    assert frame_class.from_line(input_line) is None


def test_sanitizer_stackframe_01():
    """test SanitizerStackFrame.from_line() - with symbols"""
    frame = SanitizerStackFrame.from_line(
        "    #1 0x7f00dad60565 in Abort(char const*) /blah/base/nsDebugImpl.cpp:472"
    )
    assert frame
    assert frame.stack_line == "1"
    assert frame.function == "Abort"
    assert frame.location == "nsDebugImpl.cpp"
    assert frame.offset == "472"


def test_sanitizer_stackframe_02():
    """test SanitizerStackFrame.from_line() - with symbols"""
    frame = SanitizerStackFrame.from_line(
        "    #36 0x48a6e4 in main /app/nsBrowserApp.cpp:399:11"
    )
    assert frame
    assert frame.stack_line == "36"
    assert frame.function == "main"
    assert frame.location == "nsBrowserApp.cpp"
    assert frame.offset == "399"


def test_sanitizer_stackframe_03():
    """test SanitizerStackFrame.from_line() - without symbols"""
    frame = SanitizerStackFrame.from_line(
        "    #1 0x7f00ecc1b33f (/lib/x86_64-linux-gnu/libpthread.so.0+0x1033f)"
    )

    assert frame
    assert frame.stack_line == "1"
    assert frame.function is None
    assert frame.location == "libpthread.so.0"
    assert frame.offset == "0x1033f"


def test_sanitizer_stackframe_04():
    """test SanitizerStackFrame.from_line() - with symbols"""
    frame = SanitizerStackFrame.from_line(
        "    #25 0x7f0155526181 in start_thread (/l/libpthread.so.0+0x8181)"
    )
    assert frame
    assert frame.stack_line == "25"
    assert frame.function == "start_thread"
    assert frame.location == "libpthread.so.0"
    assert frame.offset == "0x8181"


def test_sanitizer_stackframe_05():
    """test SanitizerStackFrame.from_line() - angle brackets"""
    frame = SanitizerStackFrame.from_line(
        "    #123 0x7f30afea9148 in Call<nsBlah *> /a/b.cpp:356:50"
    )
    assert frame
    assert frame.stack_line == "123"
    assert frame.function == "Call"
    assert frame.location == "b.cpp"
    assert frame.offset == "356"


def test_sanitizer_stackframe_06():
    """test SanitizerStackFrame.from_line() - useless frame"""
    frame = SanitizerStackFrame.from_line("    #2 0x7ffffffff  (<unknown module>)")
    assert frame
    assert frame.stack_line == "2"
    assert frame.function is None
    assert frame.location == "<unknown module>"
    assert frame.offset is None


def test_sanitizer_stackframe_07():
    """test SanitizerStackFrame.from_line() - missing a function"""
    frame = SanitizerStackFrame.from_line(
        "    #0 0x7f0d571e04bd  /a/glibc-2.23/../syscall-template.S:84"
    )
    assert frame
    assert frame.stack_line == "0"
    assert frame.function is None
    assert frame.location == "syscall-template.S"
    assert frame.offset == "84"


def test_sanitizer_stackframe_08():
    """test SanitizerStackFrame.from_line() - lots of spaces"""
    frame = SanitizerStackFrame.from_line(
        "    #0 0x48a6e4 in Call<a *> /test path/file name.c:1:2"
    )
    assert frame
    assert frame.stack_line == "0"
    assert frame.function == "Call"
    assert frame.location == "file name.c"
    assert frame.offset == "1"


def test_sanitizer_stackframe_09():
    """test SanitizerStackFrame.from_line() - filename missing path"""
    frame = SanitizerStackFrame.from_line("    #0 0x0000123 in func a.cpp:12")
    assert frame
    assert frame.stack_line == "0"
    assert frame.function == "func"
    assert frame.location == "a.cpp"
    assert frame.offset == "12"


def test_sanitizer_stackframe_10():
    """test SanitizerStackFrame.from_line() - with build id"""
    frame = SanitizerStackFrame.from_line(
        "    #0 0x7f76d25b7fc0  (/usr/lib/x86_64-linux-gnu/dri/swrast_dri.so+0x704fc0) "
        "(BuildId: d04a40e4062a8d444ff6f23d4fe768215b2e32c7)"
    )
    assert frame
    assert frame.stack_line == "0"
    assert frame.function is None
    assert frame.location == "swrast_dri.so"
    assert frame.offset == "0x704fc0"


def test_gdb_stackframe_01():
    """test GdbStackFrame.from_line() - with symbols"""
    frame = GdbStackFrame.from_line(
        "#0  __memmove_ssse3_back () at ../d/x86_64/a/memcpy-ssse3-back.S:1654"
    )
    assert frame
    assert frame.stack_line == "0"
    assert frame.function == "__memmove_ssse3_back"
    assert frame.location == "memcpy-ssse3-back.S"
    assert frame.offset == "1654"


def test_gdb_stackframe_02():
    """test GdbStackFrame.from_line() - with symbols, missing line numbers"""
    frame = GdbStackFrame.from_line("#2  0x0000000000400545 in main ()")
    assert frame
    assert frame.stack_line == "2"
    assert frame.function == "main"
    assert frame.location is None
    assert frame.offset is None


def test_gdb_stackframe_03():
    """test GdbStackFrame.from_line() - with symbols"""
    frame = GdbStackFrame.from_line("#3  0x0000000000400545 in main () at test.c:5")
    assert frame
    assert frame.stack_line == "3"
    assert frame.function == "main"
    assert frame.location == "test.c"
    assert frame.offset == "5"


def test_gdb_stackframe_04():
    """test GdbStackFrame.from_line() - unknown address"""
    frame = GdbStackFrame.from_line("#0  0x00000000 in ?? ()")
    assert frame
    assert frame.stack_line == "0"
    assert frame.function == "??"
    assert frame.location is None
    assert frame.offset is None


def test_gdb_stackframe_05():
    """test GdbStackFrame.from_line() - missing line number"""
    frame = GdbStackFrame.from_line("#3  0x400545 in main () at test.c")
    assert frame
    assert frame.stack_line == "3"
    assert frame.function == "main"
    assert frame.location == "test.c"
    assert frame.offset is None


def test_minidump_stackframe_01():
    """test MinidumpStackFrame.from_line() - with symbols"""
    frame = MinidumpStackFrame.from_line(
        "0|2|libtest|main|hg:c.a.org/m-c:a/b/file.cpp:5bf50|114|0x3a"
    )
    assert frame
    assert frame.stack_line == "2"
    assert frame.function == "main"
    assert frame.location == "file.cpp"
    assert frame.offset == "114"


def test_minidump_stackframe_02():
    """test MinidumpStackFrame.from_line() - without symbols"""
    frame = MinidumpStackFrame.from_line("9|42|libpthread-2.26.so||||0x10588")
    assert frame
    assert frame.stack_line == "42"
    assert frame.function is None
    assert frame.location == "libpthread-2.26.so"
    assert frame.offset == "0x10588"


def test_minidump_stackframe_03():
    """test MinidumpStackFrame.from_line() - without hg repo info"""
    frame = MinidumpStackFrame.from_line(
        "0|49|libxul.so|foo|/usr/x86_64-linux-gnu/test.h|85|0x5"
    )
    assert frame
    assert frame.stack_line == "49"
    assert frame.function == "foo"
    assert frame.location == "/usr/x86_64-linux-gnu/test.h"
    assert frame.offset == "85"


def test_minidump_stackframe_04():
    """test MinidumpStackFrame.from_line() - with s3 repo info"""
    frame = MinidumpStackFrame.from_line(
        "42|0|xul.dll|foo_a() const|s3:g-g-sources:e/a.cpp:|14302|0x3f1"
    )
    assert frame
    assert frame.stack_line == "0"
    assert frame.function == "foo_a() const"
    assert frame.location == "a.cpp"
    assert frame.offset == "14302"


def test_tsan_stackframe_01():
    """test ThreadSanitizerStackFrame.from_line() - symbolized"""
    frame = ThreadSanitizerStackFrame.from_line("    #0 main race.c:10 (exe+0xa3b4)")
    assert frame
    assert frame.stack_line == "0"
    assert frame.function == "main"
    assert frame.location == "race.c"
    assert frame.offset == "10"


def test_tsan_stackframe_02():
    """test ThreadSanitizerStackFrame.from_line() - symbolized"""
    frame = ThreadSanitizerStackFrame.from_line(
        "    #1 test1 test2 /a b/c.h:51:10 (libxul.so+0x18c9873)"
    )
    assert frame
    assert frame.stack_line == "1"
    assert frame.function == "test1"
    assert frame.location == "c.h"
    assert frame.offset == "51"


def test_tsan_stackframe_03():
    """test ThreadSanitizerStackFrame.from_line() - unsymbolized"""
    frame = ThreadSanitizerStackFrame.from_line("    #2 <null> <null> (0xbad)")
    assert frame
    assert frame.stack_line == "2"
    assert frame.function is None
    assert frame.location is None
    assert frame.offset == "0xbad"


def test_tsan_stackframe_04():
    """test ThreadSanitizerStackFrame.from_line() - missing file"""
    frame = ThreadSanitizerStackFrame.from_line("    #0 func <null> (mod+0x123ac)")
    assert frame
    assert frame.stack_line == "0"
    assert frame.function == "func"
    assert frame.location == "mod"
    assert frame.offset == "0x123ac"


def test_valgrind_stackframe_01():
    """test ValgrindStackFrame.from_line()"""
    frame = ValgrindStackFrame.from_line(
        "==4754==    at 0x45C6C0: FuncName (decode.c:123)"
    )
    assert frame
    assert frame.stack_line is None
    assert frame.function == "FuncName"
    assert frame.location == "decode.c"
    assert frame.offset == "123"


def test_valgrind_stackframe_02():
    """test ValgrindStackFrame.from_line()"""
    frame = ValgrindStackFrame.from_line("==4754==    by 0x462A20: main (foo.cc:71)")
    assert frame
    assert frame.stack_line is None
    assert frame.function == "main"
    assert frame.location == "foo.cc"
    assert frame.offset == "71"


def test_valgrind_stackframe_03():
    """test ValgrindStackFrame.from_line()"""
    frame = ValgrindStackFrame.from_line(
        "==4754==    at 0x4C2AB80: malloc (in /usr/lib/blah-linux.so)"
    )
    assert frame
    assert frame.stack_line is None
    assert frame.function == "malloc"
    assert frame.location == "blah-linux.so"
    assert frame.offset is None


def test_valgrind_stackframe_04():
    """test ValgrindStackFrame.from_line()"""
    frame = ValgrindStackFrame.from_line(
        "==2342==    by 0x4E3E71: (anon ns)::test(b2::a&, int) (main.cpp:49)"
    )
    assert frame
    assert frame.stack_line is None
    assert frame.function == "(anon ns)::test(b2::a&, int)"
    assert frame.location == "main.cpp"
    assert frame.offset == "49"


def test_valgrind_stackframe_05():
    """test ValgrindStackFrame.from_line()"""
    frame = ValgrindStackFrame.from_line(
        "==2342==    at 0xF00D: Foo::Foo(char *, int, bool) (File.h:37)"
    )
    assert frame
    assert frame.stack_line is None
    assert frame.function == "Foo::Foo(char *, int, bool)"
    assert frame.location == "File.h"
    assert frame.offset == "37"


def test_valgrind_stackframe_06():
    """test ValgrindStackFrame.from_line()"""
    frame = ValgrindStackFrame.from_line("==4754==    at 0x4C2AB80: ??? (in /bin/a)")
    assert frame
    assert frame.stack_line is None
    assert frame.function == "???"
    assert frame.location == "a"
    assert frame.offset is None


def test_rr_stackframe_01():
    """test RrStackFrame.from_line()"""
    frame = RrStackFrame.from_line("rr(main+0x244)[0x450b74]")
    assert frame
    assert frame.stack_line is None
    assert frame.function is None
    assert frame.location == "main"
    assert frame.offset == "0x244"


def test_rust_stackframe_01():
    """test RustStackFrame.from_line()"""
    frame = RustStackFrame.from_line("  53:    0x7ff1d7e4982f - __libc_start_main")
    assert frame
    assert frame.stack_line == "53"
    assert frame.function == "__libc_start_main"
    assert frame.location is None
    assert frame.offset is None


def test_rust_stackframe_02():
    """test RustStackFrame.from_line()"""
    frame = RustStackFrame.from_line(
        "  4:    0x10b715a5b - unwind::begin_unwind_fmt::h227376fe1e021a36n3d"
    )
    assert frame
    assert frame.stack_line == "4"
    assert frame.location is None
    assert frame.function == "unwind::begin_unwind_fmt"
    assert frame.offset is None
