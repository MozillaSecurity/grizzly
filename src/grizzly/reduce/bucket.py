# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from ..replay.bucket import bucket_main
from .args import ReduceFuzzManagerIDQualityArgs
from .crash import main as crash_main


def main() -> int:
    """Wrapper for bucket_main() which is the CLI for `grizzly.reduce.bucket`.

    Arguments:
        None

    Returns:
        Exit.SUCCESS (0) for success otherwise a different Exit code is returned.
    """
    return bucket_main(ReduceFuzzManagerIDQualityArgs().parse_args(), crash_main)


if __name__ == "__main__":
    raise SystemExit(main())
