# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import subprocess
import fixtures


@fixtures.fixture
def dfilter_cmd(cmd_tshark, capture_file, request):
    def wrapped(dfilter):
        return (
            cmd_tshark,
            "-n",       # No name resolution
            "-r",       # Next arg is trace file to read
            capture_file(request.instance.trace_file),
            "-Y",       # packet display filter (used to be -R)
            dfilter
        )
    return wrapped


@fixtures.fixture
def checkDFilterCount(dfilter_cmd, base_env):
    def checkDFilterCount_real(dfilter, expected_count):
        """Run a display filter and expect a certain number of packets."""
        output = subprocess.check_output(dfilter_cmd(dfilter),
                                         universal_newlines=True,
                                         stderr=subprocess.STDOUT,
                                         env=base_env)

        dfp_count = output.count("\n")
        msg = "Expected %d, got: %s" % (expected_count, dfp_count)
        assert dfp_count == expected_count, msg
    return checkDFilterCount_real


@fixtures.fixture
def checkDFilterFail(dfilter_cmd, base_env):
    def checkDFilterFail_real(dfilter):
        """Run a display filter and expect tshark to fail."""
        exitcode = subprocess.call(dfilter_cmd(dfilter),
                                   stdout=subprocess.DEVNULL,
                                   stderr=subprocess.STDOUT,
                                   env=base_env)
        assert exitcode == 2, 'Expected process to fail, got %d' % (exitcode,)
    return checkDFilterFail_real
