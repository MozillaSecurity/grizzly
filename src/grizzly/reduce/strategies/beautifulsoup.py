# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

from hashlib import sha256
from logging import getLogger
from typing import TYPE_CHECKING

from lithium.testcases import TestcaseLine

try:
    from bs4 import BeautifulSoup
    from bs4.formatter import HTMLFormatter

    HAVE_BEAUTIFULSOUP = True
except ImportError:  # pragma: no cover
    HAVE_BEAUTIFULSOUP = False

from ...common.storage import TestCase
from . import Strategy

if TYPE_CHECKING:
    from collections.abc import Generator

LOG = getLogger(__name__)


class BeautifulSoupStrategy(Strategy):
    all_extensions = frozenset((".htm", ".html", ".xhtml", ".svg"))
    import_available = HAVE_BEAUTIFULSOUP
    import_name = "beautifulsoup4"
    name: str

    def __init__(self, testcases: list[TestCase], dd_markers: bool = False) -> None:
        """Initialize strategy instance.

        Arguments:
            testcases: Testcases to reduce. The object does not take ownership of the
                       testcases.
            dd_markers: Indicate DDBEGIN/DDEND markers have been detected.
        """
        super().__init__(testcases, dd_markers=dd_markers)
        self._current_feedback: bool | None = None
        self._files_to_process = self.actionable_files(extensions=self.all_extensions)

    def update(self, success: bool) -> None:
        """Inform the strategy whether or not the last modification yielded was good.

        Arguments:
            success: Whether or not the last modification was acceptable.

        Returns:
            None
        """
        assert self._current_feedback is None
        self._current_feedback = success


class BeautifulSoupPrettify(BeautifulSoupStrategy):
    name = "beautifulsoup"

    def __iter__(self) -> Generator[list[TestCase]]:
        """Iterate over potential modifications of testcases according to this strategy.

        The caller should evaluate each testcase set yielded, and call `update` with the
        result. The caller owns the testcases yielded, and should call `cleanup` for
        each.

        Yields:
            Testcases with modifications.
        """
        if not self.import_available:
            LOG.warning("%s not available, skipping strategy.", self.import_name)
            return

        LOG.info("BeautifulSoup prettifying %d files", len(self._files_to_process))
        for file_no, file in enumerate(self._files_to_process, start=1):
            LOG.info(
                "BeautifulSoup prettifying %s (file %d/%d)",
                file.relative_to(self._testcase_root),
                file_no,
                len(self._files_to_process),
            )

            # Use Lithium just to split the file at DDBEGIN/END.
            # Lithium already has the right logic for DDBEGIN/END.
            lith_tc = TestcaseLine()
            lith_tc.load(file)
            if not lith_tc.parts:
                LOG.warning("No data to prettify, skipping")
                continue

            data = b"".join(lith_tc.parts)
            org_hash = sha256(data).digest()

            # do initial prettify pass
            data = BeautifulSoup(data.decode(), features="html.parser").prettify(
                formatter=HTMLFormatter(indent=0), encoding="utf-8"
            )

            # collapse empty tags, for example '<p>\n</p>' should be '<p></p>'
            soup = BeautifulSoup(data, features="html.parser")
            for tag in soup.find_all():
                if tag.string is not None and tag.string.strip() == "":
                    tag.string = ""

            data = soup.encode(encoding="utf-8")
            if sha256(data).digest() == org_hash:
                LOG.warning("Prettifying had no effect on the file, skipping")
                continue

            with file.open("wb") as testcase_fp:
                testcase_fp.write(lith_tc.before)
                testcase_fp.write(data)
                testcase_fp.write(lith_tc.after)

            yield [TestCase.load(x) for x in sorted(self._testcase_root.iterdir())]

            assert self._current_feedback is not None, "No feedback for last iteration"
            if self._current_feedback:
                LOG.info("%s was successful", self.name)
            else:
                LOG.warning("%s failed (reverting)", self.name)
                lith_tc.dump(file)
            self._current_feedback = None


class BeautifulSoupCSSMerge(BeautifulSoupStrategy):
    name = "css-merge"

    def __iter__(self) -> Generator[list[TestCase]]:
        """Iterate over potential modifications of testcases according to this strategy.

        The caller should evaluate each testcase set yielded, and call `update` with the
        result. The caller owns the testcases yielded, and should call `cleanup` for
        each.

        Yields:
            Testcases with modifications.
        """
        if not self.import_available:
            LOG.warning("%s not available, skipping strategy.", self.import_name)
            return

        LOG.info("BeautifulSoup CSS Merge %d files", len(self._files_to_process))
        for file_no, file in enumerate(self._files_to_process, start=1):
            LOG.info(
                "BeautifulSoup CSS Merge %s (file %d/%d)",
                file.relative_to(self._testcase_root),
                file_no,
                len(self._files_to_process),
            )

            # Use Lithium just to split the file at DDBEGIN/END.
            # Lithium already has the right logic for DDBEGIN/END.
            lith_tc = TestcaseLine()
            lith_tc.load(file)
            if not lith_tc.parts:
                LOG.warning("No data to prettify, skipping")
                continue
            data = b"".join(lith_tc.parts)

            style_data: list[str] = []
            soup = BeautifulSoup(data.decode(), features="html.parser")
            for tag in soup.find_all():
                attr_value = tag.attrs.pop("style", None)
                # collect style data and prepare it to be added to a style tag
                if isinstance(attr_value, str) and attr_value:
                    tag_id = tag.get("id")
                    if tag_id is None:
                        # only move style data to a tag if id is available
                        continue
                    style_data.append(f"#{tag_id} {{ {attr_value} }}")

            if not style_data:
                LOG.warning("CSS merge did not detect content to merge, skipping")
                continue

            # add style data to a style tag (create one if needed)
            style_tag = soup.find("style")
            if style_tag is None:
                style_tag = soup.new_tag("style")
                soup.append("\n")
                soup.append(style_tag)
                soup.append("\n")
            new_styles = "\n".join(style_data)
            existing_styles = style_tag.string or ""
            style_tag.string = f"{existing_styles.rstrip()}\n{new_styles}\n"

            with file.open("wb") as testcase_fp:
                testcase_fp.write(lith_tc.before)
                testcase_fp.write(soup.encode(encoding="utf-8"))
                testcase_fp.write(lith_tc.after)

            yield [TestCase.load(x) for x in sorted(self._testcase_root.iterdir())]

            assert self._current_feedback is not None, "No feedback for last iteration"
            if self._current_feedback:
                LOG.info("%s was successful", self.name)
            else:
                LOG.warning("%s failed (reverting)", self.name)
                lith_tc.dump(file)
            self._current_feedback = None
