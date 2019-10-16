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


@fixtures.fixture(scope='session')
def cmd_dftest(program):
    return program('dftest')


@fixtures.fixture
def checkDFilterCount(dfilter_cmd, base_env):
    def checkDFilterCount_real(dfilter, expected_count):
        """Run a display filter and expect a certain number of packets."""
        output = subprocess.check_output(dfilter_cmd(dfilter),
                                         universal_newlines=True,
                                         stderr=subprocess.STDOUT,
                                         env=base_env)

        dfp_count = output.count("\n")
        msg = "Expected %d, got: %s\noutput: %r" % \
            (expected_count, dfp_count, output)
        assert dfp_count == expected_count, msg
    return checkDFilterCount_real


@fixtures.fixture
def checkDFilterFail(cmd_dftest, base_env):
    def checkDFilterFail_real(dfilter, error_message):
        """Run a display filter and expect dftest to fail."""
        proc = subprocess.Popen([cmd_dftest, dfilter],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                universal_newlines=True,
                                env=base_env)
        outs, errs = proc.communicate()
        assert errs.strip() == 'dftest: %s' % (error_message,), \
            'Unexpected dftest stderr:\n%s\nstdout:\n%s' % (errs, outs)
        assert proc.returncode == 2, \
            'Unexpected dftest exit code: %d. stdout:\n%s\n' % \
            (proc.returncode, outs)
    return checkDFilterFail_real
