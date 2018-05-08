# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import absolute_import
import argparse
import ConfigParser as configparser
import copy
import hashlib
import io
import jsbeautifier
import logging
import os
import re
import shutil
import tempfile
import time
import zipfile
from FTB.ProgramConfiguration import ProgramConfiguration
from FTB.Signatures.CrashInfo import CrashInfo
import fasteners
from fuzzfetch import Fetcher, BuildFlags
import lithium
from . import common
from .ffp import FFPInteresting


log = logging.getLogger("reduce")  # pylint: disable=invalid-name


# testcase quality values
REDUCED_RESULT = 0  # the final reduced testcase
REDUCED_ORIGINAL = 1  # the original used for successful reduction
REPRODUCIBLE = 4  # the testcase was reproducible
UNREDUCED = 5  # haven't attempted reduction yet
REDUCER_BROKE = 8  # the testcase was reproducible, but broke during reduction
REDUCER_ERROR = 9  # reducer error
NOT_REPRODUCIBLE = 10  # could not reproduce the testcase


class ReducerError(Exception):
    pass


class PushDir(object):  # pylint: disable=too-few-public-methods
    """
    Context manager which changes directory and remembers the original
    directory at time of creation. When exited, it will chdir back to
    the original.
    """

    def __init__(self, chd):
        self.new_dir = chd
        self.old_dir = os.getcwd()
        log.debug("")

    def __enter__(self):
        os.chdir(self.new_dir)
        return self

    def __exit__(self, _exc_type, _exc_val, _exc_tb):
        os.chdir(self.old_dir)
        return False


class TempCWD(PushDir):  # pylint: disable=too-few-public-methods
    """
    Context manager which creates a temp directory, chdirs to it, and when
    the context is exited will chdir back to the cwd at time of creation, and
    delete the temp directory.

    All arguments are passed through to tempfile.mkdtemp.
    """

    def __init__(self, *args, **kwds):
        tmp_dir = tempfile.mkdtemp(*args, **kwds)
        self._no_delete = False
        super(TempCWD, self).__init__(tmp_dir)

    def no_delete(self):
        self._no_delete = True

    def __exit__(self, exc_type, exc_val, exc_tb):
        result = super(TempCWD, self).__exit__(exc_type, exc_val, exc_tb)
        if not self._no_delete:
            shutil.rmtree(self.new_dir)
        return result


def _testcase_contents():
    for dir_name, _, dir_files in os.walk("."):
        arc_path = os.path.relpath(dir_name, ".")
        # skip tmp folders
        if re.match(r"^tmp.+$", arc_path.split(os.sep, 1)[0]) is not None:
            continue
        # skip core files
        if re.match(r"^core.\d+$", os.path.basename(arc_path)) is not None:
            continue
        for file_name in dir_files:
            if arc_path == ".":
                yield file_name
            else:
                yield os.path.join(arc_path, file_name)


def _update_build(build_dir, fetch_args):
    # use a lock to ensure that only one worker process tries updating each build type at a time
    with fasteners.InterProcessLock(build_dir + ".lock"):
        dl = Fetcher(*fetch_args)
        latest_version = "%.8s-%.12s" % (dl.build_info["buildid"], dl.build_info["moz_source_stamp"])
        if os.path.isdir(build_dir):
            if os.path.isfile(os.path.join(build_dir, "firefox.fuzzmanagerconf")):
                cfg = configparser.RawConfigParser()
                cfg.read(os.path.join(build_dir, "firefox.fuzzmanagerconf"))
                have_version = cfg.get("Main", "product_version")
                if have_version == latest_version:
                    return os.path.realpath(build_dir)
                log.info("have version: %s, latest is %s", have_version, latest_version)
            os.unlink(build_dir)
        # need to download it
        out_dir = build_dir + dl.build_info["moz_source_stamp"][:12]
        if os.path.isdir(out_dir):
            # previous download failed? remove it
            shutil.rmtree(out_dir)
        os.mkdir(out_dir)
        try:
            dl.extract_build(out_dir)
            os.symlink(out_dir, build_dir)
        except Exception:
            shutil.rmtree(out_dir)
            raise
        return os.path.realpath(build_dir)


class ReductionJob(object):
    DEFAULT_PREFS = os.path.join(os.path.expanduser("~"), "fuzzing-no-e10s.prefs.js")
    DEFAULT_EXTENSION = os.path.join(os.path.expanduser("~"), "fuzzpriv")

    def __init__(self, message, report=True, extension_path=None, prefs_path=None):
        """
        MessageBody format (json):
        {
            "crash": {crash_id},
            "signature": "{sig}",
            "reduced": {crash_id}|null
        }
        """
        self.crash_id = message.crash
        self.task_sig = message.signature
        self.reduced_id = None
        self.skipped = False
        self.ignored = False
        self.report = report
        self.report_cb = None
        self.extension = extension_path or self.DEFAULT_EXTENSION
        self.prefs = prefs_path or self.DEFAULT_PREFS

        self.other_crashes = {}
        self.tool = None

    def message(self):
        if self.skipped:
            return None
        elif self.ignored:
            return {"crash": self.crash_id, "signature": self.task_sig, "reduced": None, "ignored": True}
        return {"crash": self.crash_id, "signature": self.task_sig, "reduced": self.reduced_id, "ignored": False}

    def _gather_reduced_crash_info(self, target_binary, testcase_fn):
        # find the interesting log

        # get all lithium tmp dirs in descending order
        # the final reduced testcase is the highest numbered testcase marked "interesting"
        # in the highest numbered tmp folder
        tmps = sorted([entry for entry in os.listdir(".")
                       if os.path.isdir(entry) and re.match(r"^tmp\d+$", entry) is not None],
                      key=lambda x: -int(x[3:]))
        for tmp in tmps:
            interestings = sorted([entry for entry in os.listdir(tmp)
                                   if re.match(r"^\d+-interesting\.", entry)],
                                  key=lambda x: -int(x.split("-", 1)[0]))
            if interestings:
                interesting = interestings[0]
                break
        else:
            raise RuntimeError("no interesting files found")
        err_fn = os.path.join(tmp, interesting.split("-", 1)[0]) + "_stderr.txt"
        out_fn = os.path.join(tmp, interesting.split("-", 1)[0]) + "_stdout.txt"
        crash_fn = os.path.join(tmp, interesting.split("-", 1)[0]) + "_crashdata.txt"
        interesting = os.path.join(tmp, interesting)
        assert os.path.isfile(err_fn), "no stderr file for %s" % interesting
        assert os.path.isfile(out_fn), "no stdout file for %s" % interesting

        # check that the interesting file we found in tmp matches the one that was written as output
        with io.open(interesting, "rb") as last_inter_fp, io.open(testcase_fn, "rb") as testcase_fp:
            while True:
                interesting_chunk = last_inter_fp.read(64 * 1024)
                testcase_chunk = testcase_fp.read(64 * 1024)
                assert interesting_chunk == testcase_chunk, \
                    "interesting file %s doesn't match resulting testcase" % interesting
                if not interesting_chunk:
                    break

        # create a crashinfo
        if os.path.isfile(crash_fn):
            with io.open(crash_fn, "rb") as crash_fp:
                crash_lines = crash_fp.read().splitlines()
        else:
            crash_lines = None
        with io.open(err_fn, "rb") as err_fp, io.open(out_fn, "rb") as out_fp:
            err_lines = err_fp.read().splitlines()
            out_lines = out_fp.read().splitlines()
            # XXX: should insert the lithium reduction summary here if possible
            crash_info = CrashInfo.fromRawCrashData(
                out_lines,
                err_lines,
                ProgramConfiguration.fromBinary(target_binary),
                auxCrashData=crash_lines)

        return crash_info

    def _report_result(self, crash_info, quality, check_signature=False):
        # search for a cached signature match and if the signature
        # is already in the cache and marked as frequent, don't bother submitting
        if check_signature:
            cache_signature = common.FM_COLLECTOR.search(crash_info)[1]
            if cache_signature is not None and cache_signature['frequent']:  # XXX: this should be looser
                log.info("Crash matched existing signature: %s", cache_signature["shortDescription"])
                return None

        # add results to a zip file
        zip_name = "%d_reduced.zip" % self.crash_id
        with zipfile.ZipFile(zip_name, mode="w", compression=zipfile.ZIP_DEFLATED) as zip_fp:
            for file_name in _testcase_contents():
                if file_name == zip_name:
                    continue
                zip_fp.write(file_name)

        # insert original crash id in the log
        crash_info.rawStderr.insert(0, b"Reduced to quality %d from crash %d" % (quality, self.crash_id))

        if self.report_cb is not None:
            self.report_cb(crash_info, zip_name, quality)

        if not self.report:
            return None

        # submit results to the FuzzManager server
        tool_collector = copy.copy(common.FM_COLLECTOR)
        tool_collector.tool = self.tool
        new_entry = tool_collector.submit(crash_info, testCase=zip_name, testCaseQuality=quality)

        # remove zipfile
        os.unlink(zip_name)

        log.info("Logged new crash %d with quality %d", new_entry["id"], quality)

        return new_entry["id"]

    def _change_quality(self, quality):
        if not self.report:
            return
        log.info("updating crash %d to quality %d", self.crash_id, quality)
        try:
            common.FM_COLLECTOR.patch(common.FM_URL + "rest/crashes/%d/" % self.crash_id,
                                      data={"testcase_quality": quality})
        except RuntimeError as exc:
            # let 404's go .. evidently the crash was deleted
            if str(exc) != "Unexpected HTTP response: 404":
                raise

    def _other_crash_found(self, crash_info):
        """
        If we hit an alternate crash, store the report in a tmp folder.
        If the same crash is encountered again, only keep the newest one.
        """
        this_sig = crash_info.createCrashSignature(maxFrames=5)
        crash_hash = hashlib.sha256(this_sig.rawSignature).hexdigest()[:10]
        tmpd = "tmpalt%s" % crash_hash
        if crash_hash in self.other_crashes:
            shutil.rmtree(self.other_crashes[crash_hash]["tmpd"])
            log.info("Found alternate crash (newer): %s", crash_info.createShortSignature())
        else:
            log.info("Found alternate crash: %s", crash_info.createShortSignature())
        os.mkdir(tmpd)
        for file_name in _testcase_contents():
            out = os.path.join(tmpd, file_name)
            out_dir = os.path.dirname(out)
            if not os.path.isdir(out_dir):
                os.makedirs(out_dir)
            shutil.copyfile(file_name, out)
        self.other_crashes[crash_hash] = {"tmpd": os.path.realpath(tmpd), "crash": crash_info}

    def _report_other_crashes(self):
        """
        After reduce is finished, report any alternate results (if they don't match the collector cache).
        """
        for key in list(self.other_crashes):
            entry = self.other_crashes.pop(key)
            with PushDir(entry["tmpd"]):
                self._report_result(entry["crash"], UNREDUCED, check_signature=True)

    def run(self, firefox=None, condition_args=None):
        """
        firefox: override the firefox binary to use, instead of downloading the latest
        condition_args: list of command line arguments to pass to ffp.py
        """
        condition_args = condition_args or []

        def was_reproducible():
            self._change_quality(REPRODUCIBLE)
            reducer.conditionScript.interesting_result_cb = None

        try:
            if self.task_sig and "stack overflow" in self.task_sig.lower():
                self.ignored = True
                log.info("Ignored token \"stack overflow\" found in signature")
                return None

            # download the testcase
            # XXX: should detect 404 and signal the monitor not to retry
            testcase_fn, crash = common.FM_COLLECTOR.download(self.crash_id)
            crash = common.AttrDict(crash)
            if crash.testcase_quality != UNREDUCED:
                log.warning("crash %d was already quality %d, skipped", self.crash_id, crash.testcase_quality)
                self.skipped = True
                return True
            crash_info = common.crash_to_crashinfo(crash)

            # if crash matches the ignore list, don't try to reducec
            cache_signature = common.SIG_IGNORE_COLLECTOR.search(crash_info)[1]
            if cache_signature is not None:
                self.ignored = True
                log.info("Crash matched ignored signature: %s", cache_signature["shortDescription"])
                return None

            orig_sig = crash_info.createCrashSignature(maxFrames=5)
            self.tool = crash.tool

            # extract the testcase
            assert testcase_fn.endswith(".zip")
            with zipfile.ZipFile(testcase_fn) as zip_fp:
                zip_fp.extractall()
            os.unlink(testcase_fn)

            if firefox is not None:
                builds_to_try = [(os.path.dirname(firefox), None, [])]

            else:
                # Fetcher args are (target, branch, build, flags) where flags is (asan, debug, fuzzing)
                # try opt first because it is small and will fail fast, if that doesn't repro then try debug too.
                flags_asan = BuildFlags(asan=True, debug=False, fuzzing=True, coverage=False)
                flags_debug = BuildFlags(asan=False, debug=True, fuzzing=True, coverage=False)
                # get build type -- either central or inbound
                build_type = crash.product.split("-", 1)[1]
                builds_to_try = (("%s-asan" % build_type, ("firefox", build_type, "latest", flags_asan), []),
                                 ("%s-asan" % build_type, ("firefox", build_type, "latest", flags_asan),
                                  ["--no-harness"]),
                                 ("%s-debug" % build_type, ("firefox", build_type, "latest", flags_debug), []),
                                 ("%s-debug" % build_type, ("firefox", build_type, "latest", flags_debug),
                                  ["--no-harness"]))

            for build_dir, fetch_args, condition_args_loop in builds_to_try:
                if firefox is None:
                    # get latest build of same type to reduce with (if not already downloaded)
                    build_dir = os.path.join(os.path.expanduser("~"), "builds", build_dir)
                    build_dir = _update_build(build_dir, fetch_args)

                # iterate from 0 up for each test case in download cache
                entries = set(os.listdir("."))
                if "test_info.txt" in entries:
                    dirs = ["."]
                else:
                    dirs = sorted([entry for entry in entries if os.path.isdir(entry)],
                                  key=lambda x: int(x.rsplit('-', 1)[1]))
                for tcdir in dirs:
                    with PushDir(tcdir):
                        ff_bin = os.path.join(build_dir, "firefox").encode("utf-8")

                        # set up lithium
                        reducer = lithium.Lithium()
                        reducer.conditionScript = FFPInteresting()
                        reducer.conditionScript.alt_crash_cb = self._other_crash_found
                        # touch binary so the folder is not deleted
                        reducer.conditionScript.interesting_cb = lambda: os.utime(ff_bin, None)
                        reducer.conditionScript.interesting_result_cb = was_reproducible
                        reducer.conditionScript.orig_sig = orig_sig
                        if os.path.isfile("prefs.js"):
                            prefs = "prefs.js"
                        else:
                            prefs = self.prefs
                        if os.path.isfile("env_vars.txt"):
                            env_args = ["--environ", "env_vars.txt"]
                        else:
                            env_args = []
                        reducer.conditionArgs = condition_args + condition_args_loop + env_args + \
                            ["--xvfb",
                             "-e", self.extension,
                             "-p", prefs,
                             "--repeat", "3",
                             "-m", "7000",
                             "--ignore-timeouts",
                             "--reduce-file", "reducefile_placeholder",
                             ff_bin,
                             "testcase_placeholder"]

                        # parse test_info.txt for landing page
                        with io.open("test_info.txt", encoding="utf-8") as info:
                            for line in info:
                                if line.lower().startswith("landing page: "):
                                    landing_page = line.split(": ", 1)[1].strip().encode("utf-8")
                                    break
                            else:
                                raise ReducerError("Couldn't find landing page in %s!" % os.path.abspath(info.name))
                        reducer.conditionArgs[-1] = landing_page

                        # find all files for reduction
                        files_to_reduce = [landing_page]
                        for file_name in _testcase_contents():
                            if file_name == landing_page:
                                continue
                            with open(file_name, "rb") as tc_fp:
                                for line in tc_fp:
                                    if b"DDBEGIN" in line:
                                        files_to_reduce.append(file_name)
                                        break
                        if len(files_to_reduce) > 1:
                            # sort by descending size
                            files_to_reduce.sort(key=lambda fn: os.stat(fn).st_size, reverse=True)
                        original_size = sum(os.stat(fn).st_size for fn in files_to_reduce)

                        # run lithium reduce with strategies
                        # XXX: should check the DDBEGIN/DDEND lines to see whether it looks like markup
                        #      or script and adjust cutBefore/cutAfter accordingly
                        reduce_stages = (
                            (lithium.Minimize, lithium.TestcaseLine),
                            # CheckOnly is used in conjunction with beautification stage
                            # This verifies that beautification didn't break the testcase
                            (lithium.CheckOnly, lithium.TestcaseLine),
                            (lithium.CollapseEmptyBraces, lithium.TestcaseLine),
                            # (lithium.MinimizeSurroundingPairs, lithium.TestcaseSymbol),
                            # (lithium.MinimizeBalancedPairs, lithium.TestcaseSymbol),
                            # (lithium.Minimize, lithium.TestcaseChar),
                            (lithium.Minimize, lithium.TestcaseJsStr),
                        )
                        report_quality = None
                        for stage_num, (strategy_type, testcase_type) in enumerate(reduce_stages):
                            files_reduced = 0
                            for testcase_path in files_to_reduce:
                                if stage_num == 1:
                                    if testcase_path.endswith(".js"):
                                        # Beautify testcase
                                        with open(testcase_path) as f:
                                            original_testcase = f.read()

                                        beautified_testcase = jsbeautifier.beautify(original_testcase)
                                        # All try/catch pairs will be expanded on their own lines
                                        # Collapse these pairs when only a single instruction is contained within
                                        regex = r"(\s*try {)\n\s*(.*)\n\s*(}\s*catch.*)"
                                        beautified_testcase = re.sub(regex, r"\1 \2 \3", beautified_testcase)
                                        with open(testcase_path, 'w') as f:
                                            f.write(beautified_testcase)
                                        reducer.conditionArgs[-3] = testcase_path
                                        reducer.strategy = strategy_type()
                                        reducer.testcase = testcase_type()
                                        reducer.testcase.readTestcase(testcase_path)
                                        log.info("Attempting to beautify %s", testcase_path)
                                        result = reducer.run()
                                        if result == 0:
                                            log.info("Beautification succeeded")
                                        else:
                                            log.info("Beautification failed")
                                            with open(testcase_path, 'w') as f:
                                                f.write(original_testcase)
                                    else:
                                        # lithium.CollapseEmptyBraces is only effective with JS files
                                        continue
                                else:
                                    log.info("Reducing %s with %s on %ss",
                                             testcase_path, strategy_type.name, testcase_type.atom)
                                    reducer.conditionArgs[-3] = testcase_path
                                    reducer.strategy = strategy_type()
                                    reducer.testcase = testcase_type()
                                    reducer.testcase.readTestcase(testcase_path)
                                    result = reducer.run()
                                    if result != 0:
                                        break
                                    files_reduced += 1
                            if result != 0:
                                # reducer failed to repro the crash
                                if stage_num == 0 and files_reduced == 0:
                                    # first stage, couldn't repro at all
                                    break  # try the next one
                                else:
                                    # subsequent stage, reducing broke the testcase?
                                    # unclear how to recover from this.
                                    # just report failure and hopefully we have another to try
                                    self._change_quality(REDUCER_BROKE)
                                    log.warning("%s + %s(%s) failed to reproduce. Previous stage broke the testcase?"
                                                % (strategy_type.__name__,
                                                   testcase_type.__name__,
                                                   os.path.abspath(files_to_reduce[files_reduced])))
                                    return False
                        else:
                            # all stages succeeded
                            report_quality = REDUCED_RESULT
                        if report_quality is not None:
                            reduced_size = sum(os.stat(fn).st_size for fn in files_to_reduce)
                            if reduced_size == original_size:
                                raise ReducerError("Reducer succeeded but nothing was reduced!")
                            crash_info = self._gather_reduced_crash_info(os.path.join(build_dir, "firefox"),
                                                                         landing_page)
                            self.reduced_id = self._report_result(crash_info, report_quality)
                            # change original quality so unbucketed crashes don't reduce again
                            self._change_quality(REDUCED_ORIGINAL)
                            return True
            log.warning("Could not reduce: None of the testcases were reproducible")
            self._change_quality(NOT_REPRODUCIBLE)
            return False
        except ReducerError as exc:
            log.warning("Could not reduce: %s", exc)
            self._change_quality(REDUCER_ERROR)
            return False
        except Exception:
            log.exception("Exception during reduce")
            self.reduced_id = None
            return False
        finally:
            self._report_other_crashes()


def parse_args(args=None):
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("firefox", help="Path to the firefox binary to use")
    arg_parser.add_argument("crash_id", type=int, help="FuzzManager crash ID to use")
    arg_parser.add_argument("--report", action="store_true", help="Report results to FuzzManager")
    arg_parser.add_argument("--no-harness", action="store_true", help="Don't use harness for timeout detection")
    arg_parser.add_argument("-v", "--verbose", action="store_true", help="Show more information for debugging")
    arg_parser.add_argument("-e", "--extension", required=True, help="Path to domfuzz extension")
    arg_parser.add_argument("-p", "--prefs", help="Path to prefs file to use if none in testcase")
    result = arg_parser.parse_args(args)
    if not os.path.isfile(result.firefox):
        arg_parser.error("File not found: " + result.firefox)
    if os.path.basename(result.firefox) != "firefox":
        arg_parser.error("Firefox bin not named 'firefox' .. not supported yet.")
    if not os.path.isdir(result.extension):
        arg_parser.error("Extension must be a folder")
    return result


def main(args=None):
    args = parse_args(args)
    logging.basicConfig(format="[%(asctime)s:%(levelname).1s] %(message)s",
                        level=logging.DEBUG if args.verbose else logging.INFO)
    while True:
        save_path = os.path.join(os.path.realpath(os.getcwd()), time.strftime("reduce-results-%Y%m%d%H%M%S"))
        try:
            os.mkdir(save_path)
            break
        except OSError:
            time.sleep(1)
    log.info("Reduce results will be written to: %s", save_path)
    results = [0]

    def save_results(crash_info, test_case, quality):
        results[0] += 1
        folder = "q%d - %s" % (quality, crash_info.createShortSignature())
        # sanitize path name
        folder = re.sub(r", (at )?(/[^/]+)+:\d+$", "", folder)
        folder = re.sub(r"[?*/]", "_", folder)
        folder = folder.replace("\\", "_")
        folder = os.path.join(save_path, folder)
        os.mkdir(folder)
        shutil.copyfile(test_case, os.path.join(folder, "testcase.zip"))
        with open(os.path.join(folder, "crash_info.txt"), "wb") as out:
            out.write(str(crash_info))
        if crash_info.rawStderr:
            with open(os.path.join(folder, "stderr.txt"), "wb") as out:
                out.write(b"\n".join(crash_info.rawStderr))
        if crash_info.rawStdout:
            with open(os.path.join(folder, "stdout.txt"), "wb") as out:
                out.write(b"\n".join(crash_info.rawStdout))
        if crash_info.rawCrashData:
            with open(os.path.join(folder, "crash_data.txt"), "wb") as out:
                out.write(b"\n".join(crash_info.rawCrashData))

    try:
        ffp_args = []
        if args.no_harness:
            ffp_args.append("--no-harness")
        failure_tmpd = None
        with TempCWD(prefix="reducer") as tmpd:
            job = ReductionJob(common.AttrDict(crash=args.crash_id, signature=None), report=args.report,
                               extension_path=args.extension, prefs_path=args.prefs)
            job.report_cb = save_results
            if not job.run(firefox=args.firefox, condition_args=ffp_args):
                tmpd.no_delete()
                failure_tmpd = tmpd.new_dir
        if failure_tmpd is not None:
            results[0] += 1
            tmp_result = os.path.join(save_path, os.path.basename(failure_tmpd))
            try:
                os.rename(failure_tmpd, tmp_result)
            except OSError:
                shutil.copytree(failure_tmpd, tmp_result)
                try:
                    shutil.rmtree(failure_tmpd)
                except OSError as exc:
                    log.warning("Error removing temporary folder: %s", exc.strerror)
            log.warning("Error during reduce, reduce working files stored under %s", tmp_result)
    finally:
        if not results[0]:
            log.info("No results, removing %s", save_path)
            shutil.rmtree(save_path)


if __name__ == "__main__":
    main()
