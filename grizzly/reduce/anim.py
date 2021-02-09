# coding=utf-8
from argparse import ArgumentParser
from pathlib import Path
from subprocess import run
from shlex import quote
from shutil import which
from xml.etree import ElementTree
import re
import sys

from ..common.utils import grz_tmp


PY = quote(sys.executable)
T2SVG = which("termtosvg")


def fix_svg(svg, char_width=8):
    """termtosvg outputs text with `white-space:pre` and internal spaces in <text>
    elements. SVG optimizers don't handle `white-space:pre`, and will collapse all
    internal spaces.

    Split up <text> elements so that white-space changes don't break the output.
    """
    print(f"Fixing {svg}", file=sys.stderr)
    data = svg.read_text()
    subs = []
    for match in re.finditer(r"<text[^>]*>[^<]+</text>", data):
        et = ElementTree.fromstring(match.group(0))
        assert "x" in et.attrib, "missing 'x' attribute"
        x = int(et.attrib["x"])
        text = et.text
        out = []
        pos = 0
        for sub in re.finditer(r"(^|\s)\s+", text):
            if sub.start(0) > pos:
                sl = text[pos : sub.start(0)]
                et.attrib["x"] = str(x + pos * char_width)
                et.attrib["textLength"] = str(len(sl) * char_width)
                et.text = sl
                out.append(ElementTree.tostring(et, encoding="unicode"))
            pos = sub.end(0)
        if pos != len(text):
            sl = text[pos:]
            et.attrib["x"] = str(x + pos * char_width)
            et.attrib["textLength"] = str(len(sl) * char_width)
            et.text = sl
            out.append(ElementTree.tostring(et, encoding="unicode"))
        subs.append(((match.start(0), match.end(0)), "".join(out)))
    # make substitutions from the end to not mess up indices
    while subs:
        (a, b), rep = subs.pop()
        data = data[:a] + rep + data[b:]
    # remove white-space:pre
    data = re.sub(r"white-space:\s*pre;", "", data)
    # remove empty text elements
    data = re.sub(r"<text[^>]*>\s*</text>", "", data)
    # set animation-ease to linear for chrome
    data = re.sub(r"#screen_view\s*{", r"\g<0>animation-ease:linear;", data)
    svg.write_text(data)


def main():
    parser = ArgumentParser()
    parser.add_argument(
        "-i", "--input", type=Path, default=Path(__file__).parent / "anim_testcase.html"
    )
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument(
        "-g", "--screen-geometry", default="100x25", help="see `termtosvg -h`"
    )
    parser.add_argument(
        "-D", "--loop-delay", type=int, default=10000, help="see `termtosvg -h`"
    )
    parser.add_argument(
        "-t", "--template", default="window_frame", help="see `termtosvg -h`"
    )
    parser.add_argument(
        "-m", "--min-frame-duration", type=int, default=75, help="see `termtosvg -h`"
    )
    parser.add_argument("--force", "-f", action="store_true")
    args = parser.parse_args()
    if T2SVG is None:
        parser.error("`termtosvg` not found, is it installed?")
    if not args.input.is_file():
        parser.error("`input` must be a file to reduce")
    if not args.force and args.output.is_file():
        parser.error("`output` exists, pass --force to overwrite")

    if (Path(grz_tmp("reduce")) / "attempt.html").is_file():
        (Path(grz_tmp("reduce")) / "attempt.html").unlink()
    if (Path(grz_tmp("reduce")) / "reduced.html").is_file():
        (Path(grz_tmp("reduce")) / "reduced.html").unlink()
    try:
        run(
            [
                T2SVG,
                "record",
                "-g",
                args.screen_geometry,
                "-c",
                (
                    f"{PY} -m grizzly.reduce.anim_ui "
                    f"{PY} -m grizzly.reduce --platform fake "
                    f"{PY} {quote(str(args.input))}"
                ),
                str(args.output.with_suffix(".ttyrec")),
            ],
            check=True,
        )
    finally:
        # reset terminal
        # bug in termtosvg?
        # ... this means any tracebacks in the sub-command are hidden :(
        run(["reset"], check=True)
    run(
        [
            T2SVG,
            "render",
            "-m",
            str(args.min_frame_duration),
            "-D",
            str(args.loop_delay),
            "-t",
            args.template,
            str(args.output.with_suffix(".ttyrec")),
            str(args.output),
        ],
        check=True,
    )
    fix_svg(args.output)


if __name__ == "__main__":
    main()
