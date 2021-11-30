# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

if __name__ == "__main__":
    from ..replay.bucket import bucket_main
    from .args import ReduceFuzzManagerIDQualityArgs
    from .crash import main

    raise SystemExit(bucket_main(ReduceFuzzManagerIDQualityArgs().parse_args(), main))
