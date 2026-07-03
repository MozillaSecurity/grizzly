# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Grizzly reducer proxy removal strategy definition.

Rewrite ``o[N]`` proxy references to named variables in DOM testcases.

Discovers map files (which define ``class Objects`` + ``const trees = {...}`` +
``const nodes = [...]`` + ``new Proxy(new Objects(nodes), ...)``), then rewrites
every ``o[N]`` in the associated test files (loaded in the same HTML <script>
list or importScripts() chain) to ``o_<TypeName>_<N>``, replicating the proxy's
"fallback to a compatible assigned slot" behavior for reads of slots that were
never written. Variable declarations are inserted inside the enclosing
function / IIFE body so the rewritten locals match the heap shape needed by
heap-shape-sensitive crash reducers (e.g. Firefox gc-parallel).

Map files themselves are left on disk; only the ``<script src="...">`` and
``importScripts("...")`` references to them are removed. Once unreferenced, the
existing file-pruning reducers remove them.
"""

from __future__ import annotations

import json
import re
from logging import getLogger
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import Strategy

if TYPE_CHECKING:
    from collections.abc import Callable, Generator

    from ...common.storage import TestCase

LOG = getLogger(__name__)


def _read_text(path: Path) -> str:
    """Read a file as text, tolerating non-UTF-8 bytes (which may appear in
    fuzzer-generated test files) via surrogate escaping."""
    return path.read_bytes().decode("utf-8", errors="surrogateescape")


def _write_text(path: Path, text: str) -> None:
    """Write text produced from `_read_text`, round-tripping surrogate escapes."""
    path.write_bytes(text.encode("utf-8", errors="surrogateescape"))


MAP_FILE_SIGNATURES = (
    "class Objects",
    "const trees = {",
    "const nodes = [",
    "new Proxy(new Objects(nodes)",
)


def is_map_file(text: str) -> bool:
    return all(sig in text for sig in MAP_FILE_SIGNATURES)


def _extract_balanced_braces(text: str, start: int) -> str:
    """Return the substring text[start:end] covering a balanced { ... } block
    that starts at index `start` (which must point at '{')."""
    if text[start] != "{":
        raise ValueError(f"expected '{{' at position {start}")
    depth = 0
    in_string = False
    string_char = ""
    i = start
    while i < len(text):
        c = text[i]
        if in_string:
            if c == "\\":
                i += 2
                continue
            if c == string_char:
                in_string = False
        elif c in ('"', "'"):
            in_string = True
            string_char = c
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
        i += 1
    raise ValueError("unbalanced braces")


def parse_map(text: str) -> dict[str, Any]:
    """Parse a map file. Returns {'index_to_type', 'trees'}."""
    trees_anchor = re.search(r"const\s+trees\s*=\s*", text)
    if not trees_anchor:
        raise ValueError("no `const trees = ...` found")
    brace_pos = text.index("{", trees_anchor.end())
    trees_literal = _extract_balanced_braces(text, brace_pos)
    trees = json.loads(trees_literal)

    index_to_type: dict[int, str] = {}
    node_re = re.compile(
        r"\{\s*index:\s*(\d+)\s*,\s*tree:\s*trees\[\"([^\"]+)\"\]\s*\}"
    )
    for m in node_re.finditer(text):
        index_to_type[int(m.group(1))] = m.group(2)
    if not index_to_type:
        raise ValueError("no nodes parsed from map file")
    return {"index_to_type": index_to_type, "trees": trees}


def find_map_files(directory: Path) -> list[tuple[Path, dict[str, Any]]]:
    """Return a list of (Path, parsed_map_info) for every map file in dir."""
    out = []
    for p in sorted(directory.glob("*.js")):
        text = _read_text(p)
        if is_map_file(text):
            # JSONDecodeError is a ValueError subclass, so this also covers a
            # malformed `trees` table.
            try:
                out.append((p, parse_map(text)))
            except ValueError as exc:
                LOG.warning("Skipping malformed map file %s: %s", p.name, exc)
    return out


def _sanitize_ident(name: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9_$]", "_", name)
    if sanitized and sanitized[0].isdigit():
        sanitized = "_" + sanitized
    return sanitized or "_"


# `\b` alone would still match `o[N]` after a `.` (the dot is a non-word
# char so the boundary is satisfied), which would falsely rewrite member
# accesses like `foo.o[5]`. The negative lookbehind excludes both word
# characters and `.`.
_O_REF_RE = re.compile(r"(?<![.\w])o\[(\d+)\]")


# Matches the `{` that opens a function / arrow / IIFE body. Anchored so the
# `{` is preceded by either `function NAME?(args)` or `=>` (with optional
# whitespace). Plain block statements like `try {`, `if {`, `for {` are NOT
# matched — those don't introduce a `var` scope of their own.
_FUNC_INTRO_RE = re.compile(
    r"(?:"
    r"\bfunction\s*\w*\s*\([^)]*\)\s*"
    r"|"
    r"\)\s*=>\s*"
    r"|"
    r"\b\w+\s*=>\s*"
    r")\{"
)


def _find_matching_brace(text: str, open_pos: int) -> int:
    """Return the position AFTER the `}` that matches the `{` at `open_pos`,
    tracking strings and line/block comments so braces inside them don't
    affect depth. Returns -1 if no match is found."""
    assert text[open_pos] == "{"
    depth = 0
    in_string = False
    string_char = ""
    in_line_comment = False
    in_block_comment = False
    i = open_pos
    n = len(text)
    while i < n:
        c = text[i]
        if in_line_comment:
            if c == "\n":
                in_line_comment = False
            i += 1
            continue
        if in_block_comment:
            if c == "*" and i + 1 < n and text[i + 1] == "/":
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue
        if in_string:
            if c == "\\":
                i += 2
                continue
            if c == string_char:
                in_string = False
            i += 1
            continue
        if c == "/" and i + 1 < n:
            nx = text[i + 1]
            if nx == "/":
                in_line_comment = True
                i += 2
                continue
            if nx == "*":
                in_block_comment = True
                i += 2
                continue
        if c in ('"', "'", "`"):
            in_string = True
            string_char = c
            i += 1
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


def _find_function_bodies(text: str) -> list[tuple[int, int]]:
    """Return list of (body_open, body_end) ranges, one per function / arrow
    body. body_open is the position of the `{`; body_end is the position
    AFTER the matching `}`."""
    bodies = []
    for m in _FUNC_INTRO_RE.finditer(text):
        body_open = m.end() - 1
        body_end = _find_matching_brace(text, body_open)
        if body_end != -1:
            bodies.append((body_open, body_end))
    return bodies


def _smallest_enclosing_body(
    pos: int, bodies: list[tuple[int, int]]
) -> tuple[int, int] | None:
    """Return (body_open, body_end) of the smallest (deepest) body that
    strictly contains `pos`, or None if `pos` is at module scope."""
    best: tuple[int, int] | None = None
    best_open = -1
    for b in bodies:
        if b[0] < pos < b[1] and b[0] > best_open:
            best = b
            best_open = b[0]
    return best


def _common_ancestor_body(
    scopes: set[tuple[int, int] | None], bodies: list[tuple[int, int]]
) -> tuple[int, int] | None:
    """Given a set of scope keys (each a (body_open, body_end) tuple or
    None), return the smallest body that contains ALL of them, or None if
    no single function body can. Module-scope (`None`) in `scopes` forces
    the result to be `None`."""
    if not scopes or None in scopes:
        return None
    # every scope is non-None here; narrow the type for the checker
    real_scopes = [s for s in scopes if s is not None]
    candidates = [
        b for b in bodies if all(b[0] <= s[0] and b[1] >= s[1] for s in real_scopes)
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda b: b[0])


def _is_write_at(text: str, end_pos: int) -> bool:
    """After an o[N] match ending at end_pos, is the next non-space char an
    assignment '=' (not '==' / '===' / '=>')?"""
    i = end_pos
    while i < len(text) and text[i] in " \t":
        i += 1
    if i >= len(text) or text[i] != "=":
        return False
    nxt = text[i + 1 : i + 2]
    return nxt not in ("=", ">")


def rewrite_test_file(text: str, map_info: dict[str, Any]) -> str:
    """Rewrite all o[N] references in `text` using `map_info`.

    Variable declarations are grouped by their enclosing function / IIFE
    body. A variable used in exactly one function body is declared inside
    that body; one used at module scope is declared at module top; one used
    across multiple distinct scopes is hoisted to module top so all uses
    can see it.
    """
    index_to_type = map_info["index_to_type"]
    trees = map_info["trees"]

    matches = []  # (start, end, idx, is_write)
    for m in _O_REF_RE.finditer(text):
        idx = int(m.group(1))
        is_write = _is_write_at(text, m.end())
        matches.append((m.start(), m.end(), idx, is_write))

    if not matches:
        return text

    bodies = _find_function_bodies(text)
    assigned_slots = sorted({idx for _, _, idx, w in matches if w})

    def varname(t: str, i: int) -> str:
        return f"o_{_sanitize_ident(t)}_{i}"

    substitutions = []  # (start, end, name)
    # name -> set of scope keys ((open, end) tuple or None)
    name_to_scopes: dict[str, set[tuple[int, int] | None]] = {}

    for start, end, idx, is_write in matches:
        own_type = index_to_type.get(idx)
        if own_type is None:
            LOG.warning("o[%d] has no entry in map; leaving as-is", idx)
            continue

        if is_write or idx in assigned_slots:
            target_idx, target_type = idx, own_type
        else:
            target_idx, target_type = idx, own_type  # default: own (undefined)
            own_tree = trees.get(own_type, [own_type])
            for m_idx in assigned_slots:
                m_type = index_to_type.get(m_idx)
                if m_type and m_type in own_tree:
                    target_idx, target_type = m_idx, m_type
                    break

        name = varname(target_type, target_idx)
        substitutions.append((start, end, name))
        name_to_scopes.setdefault(name, set()).add(
            _smallest_enclosing_body(start, bodies)
        )

    if not name_to_scopes:
        return text

    # Each variable is declared in the smallest function body that contains
    # all of its uses (the common ancestor). If no single body covers every
    # use — e.g. uses at module scope and inside a function — fall back to
    # module top.
    # scope key (tuple or None) -> set of names
    scope_to_names: dict[tuple[int, int] | None, set[str]] = {}
    for name, scopes in name_to_scopes.items():
        scope_to_names.setdefault(_common_ancestor_body(scopes, bodies), set()).add(
            name
        )

    # Build var-declaration insertion edits.
    insertions = []  # (pos, decl_text)
    for scope_key, names in scope_to_names.items():
        decl = "var " + ", ".join(sorted(names)) + ";\n"
        if scope_key is not None:
            body_open = scope_key[0]
            i = body_open + 1
            while i < len(text) and text[i] in " \t":
                i += 1
            if i < len(text) and text[i] == "\n":
                i += 1
            insertions.append((i, decl))
        else:
            first_nl = text.find("\n")
            first_line = text[:first_nl] if first_nl != -1 else text
            if first_line.lstrip().startswith("// DDBEGIN"):
                insertions.append((first_nl + 1, decl))
            else:
                insertions.append((0, decl))

    # Apply edits in reverse-position order so earlier positions stay valid.
    # `(pos, length, replacement)` with substitutions having length > 0 and
    # insertions length == 0. Sort by (-pos, -length) so on rare ties the
    # substitution runs first (the inserted var line then lands BEFORE the
    # substituted variable in the final text).
    all_edits = [(s, e - s, name) for s, e, name in substitutions]
    all_edits.extend((pos, 0, decl) for pos, decl in insertions)
    all_edits.sort(key=lambda e: (-e[0], -e[1]))

    out = text
    for pos, length, repl in all_edits:
        out = out[:pos] + repl + out[pos + length :]
    return out


def _strip_matching_lines(text: str, line_pattern: re.Pattern[str]) -> str:
    """Drop every line in `text` matched by `line_pattern.search`."""
    kept = [ln for ln in text.splitlines(keepends=True) if not line_pattern.search(ln)]
    return "".join(kept)


def unreference_map_in_html(text: str, map_basename: str) -> str:
    pat = re.compile(
        r'<script[^>]+\bsrc=["\']' + re.escape(map_basename) + r'["\']',
    )
    return _strip_matching_lines(text, pat)


def unreference_map_in_js(text: str, map_basename: str) -> str:
    pat = re.compile(
        r'importScripts\(\s*["\'](?:[^"\']*/)?'
        + re.escape(map_basename)
        + r'["\']\s*\)'
    )
    return _strip_matching_lines(text, pat)


def unreference_map_in_module(text: str, map_basename: str) -> str:
    """Strip an ES-module `import { ... } from "<map>"` declaration that
    pulls the proxy out of a map file. Multi-line import lists are handled.
    Other imports (e.g. the timeout helper) are left intact."""
    pat = re.compile(
        r'^[ \t]*import\s*\{[^}]*\}\s*from\s*["\'](?:[^"\']*/)?'
        + re.escape(map_basename)
        + r'["\']\s*;?[ \t]*\n?',
        re.MULTILINE,
    )
    return pat.sub("", text)


_HTML_SCRIPT_SRC_RE = re.compile(
    r'<script[^>]+\bsrc=["\']([^"\']+)["\']', re.IGNORECASE
)
_IMPORT_SCRIPTS_RE = re.compile(r'importScripts\(\s*["\']([^"\']+)["\']\s*\)')
_MODULE_IMPORT_RE = re.compile(r'import\s*\{[^}]*\}\s*from\s*["\']([^"\']+)["\']')


def _basenames(paths: list[str]) -> list[str]:
    return [Path(p).name for p in paths]


def find_html_scopes(directory: Path) -> list[dict[str, Any]]:
    out = []
    for p in sorted(directory.glob("*.html")):
        scripts = _basenames(_HTML_SCRIPT_SRC_RE.findall(_read_text(p)))
        if scripts:
            out.append({"path": p, "scripts": scripts})
    return out


def find_sw_scopes(directory: Path) -> list[dict[str, Any]]:
    out = []
    for p in sorted(directory.glob("*.js")):
        scripts = _basenames(_IMPORT_SCRIPTS_RE.findall(_read_text(p)))
        if scripts:
            out.append({"path": p, "scripts": scripts})
    return out


def find_module_scopes(directory: Path) -> list[dict[str, Any]]:
    """Find JS files that load a map via ES-module `import { o } from "..."`
    (e.g. module workers). The owning file is itself a test file."""
    out = []
    for p in sorted(directory.glob("*.js")):
        scripts = _basenames(_MODULE_IMPORT_RE.findall(_read_text(p)))
        if scripts:
            out.append({"path": p, "scripts": scripts})
    return out


def _process_scope(
    directory: Path,
    owner_path: Path,
    scripts: list[str],
    map_basenames: set[str],
    map_by_basename: dict[str, dict[str, Any]],
    owner_is_test_file: bool,
    remove_ref_in_owner: Callable[[str, str], str],
) -> bool:
    """Apply the rewrite for one scope (HTML page or SW importScripts chain).

    `remove_ref_in_owner` is the function (text, basename) -> text that
    removes the map reference from the owner (HTML or SW JS).
    Returns True if any file was modified.
    """
    scope_maps = [s for s in scripts if s in map_basenames]
    if not scope_maps:
        return False
    if len(scope_maps) > 1:
        LOG.warning(
            "multiple map files referenced from %s; using %s",
            owner_path,
            scope_maps[0],
        )
    map_basename = scope_maps[0]
    map_info = map_by_basename[map_basename]

    test_scripts = [s for s in scripts if s != map_basename]
    if owner_is_test_file:
        test_scripts = [owner_path.name, *test_scripts]

    changed = False
    seen = set()
    for script in test_scripts:
        if script in seen:
            continue
        seen.add(script)
        script_path = directory / script
        if not script_path.exists() or script_path.suffix != ".js":
            continue
        original = _read_text(script_path)
        new_text = original
        if _O_REF_RE.search(new_text):
            new_text = rewrite_test_file(new_text, map_info)
        if script_path == owner_path:
            new_text = remove_ref_in_owner(new_text, map_basename)
        if new_text != original:
            _write_text(script_path, new_text)
            LOG.debug("rewrote %s", script_path)
            changed = True

    if not owner_is_test_file:
        original = _read_text(owner_path)
        new_text = remove_ref_in_owner(original, map_basename)
        if new_text != original:
            _write_text(owner_path, new_text)
            LOG.debug("unreferenced map in %s", owner_path)
            changed = True
    return changed


def rewrite_directory(directory: Path) -> bool:
    """Discover map files in `directory` and rewrite proxy references across
    its HTML/SW/module scopes in place.

    Arguments:
        directory: Testcase directory to rewrite.

    Returns:
        True if any file was modified.
    """
    maps = find_map_files(directory)
    if not maps:
        return False

    map_basenames = {p.name for p, _ in maps}
    map_by_basename = {p.name: info for p, info in maps}

    changed = False
    for scope in find_html_scopes(directory):
        changed |= _process_scope(
            directory,
            scope["path"],
            scope["scripts"],
            map_basenames,
            map_by_basename,
            owner_is_test_file=False,
            remove_ref_in_owner=unreference_map_in_html,
        )

    for scope in find_sw_scopes(directory):
        changed |= _process_scope(
            directory,
            scope["path"],
            scope["scripts"],
            map_basenames,
            map_by_basename,
            owner_is_test_file=True,
            remove_ref_in_owner=unreference_map_in_js,
        )

    for scope in find_module_scopes(directory):
        changed |= _process_scope(
            directory,
            scope["path"],
            scope["scripts"],
            map_basenames,
            map_by_basename,
            owner_is_test_file=True,
            remove_ref_in_owner=unreference_map_in_module,
        )

    return changed


class DeProxy(Strategy):
    """Rewrite `o[N]` proxy references to named locals and drop map-file
    references, preserving heap shape for shape-sensitive reducers.
    """

    name = "deproxy"

    def __init__(self, testcases: list[TestCase], dd_markers: bool = False) -> None:
        """Initialize strategy instance.

        Arguments:
            testcases: Testcases to reduce. The object does not take ownership of the
                       testcases.
            dd_markers: Indicate DDBEGIN/DDEND markers have been detected.
        """
        super().__init__(testcases, dd_markers=dd_markers)
        self._current_feedback: bool | None = None

    def update(self, success: bool) -> None:
        """Inform the strategy whether or not the last modification yielded was good.

        Arguments:
            success: Whether or not the last modification was acceptable.

        Returns:
            None
        """
        assert self._current_feedback is None
        self._current_feedback = success

    def __iter__(self) -> Generator[list[TestCase]]:
        """Iterate over potential modifications of testcases according to this strategy.

        The caller should evaluate each testcase set yielded, and call `update` with the
        result. The caller owns the testcases yielded, and should call `cleanup` for
        each.

        Yields:
            Testcases with proxy references rewritten.
        """
        for subdir in sorted(self._testcase_root.iterdir()):
            if not subdir.is_dir() or not find_map_files(subdir):
                continue

            LOG.info("Removing proxy references in %s", subdir.name)
            # snapshot every file in the testcase so a failed attempt can be
            # fully reverted (the transform only edits file contents in place)
            backup = {
                path: path.read_bytes()
                for path in subdir.glob("**/*")
                if path.is_file()
            }

            if not rewrite_directory(subdir):
                LOG.warning("deproxy had no effect on %s, skipping", subdir.name)
                continue

            yield self.reload_testcases()

            assert self._current_feedback is not None, "No feedback for last iteration"
            if self._current_feedback:
                LOG.info("%s was successful", self.name)
            else:
                LOG.warning("%s failed (reverting)", self.name)
                for path, data in backup.items():
                    path.write_bytes(data)
            self._current_feedback = None
