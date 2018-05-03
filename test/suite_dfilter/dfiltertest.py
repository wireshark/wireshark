# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import config
import os.path
import subprocesstest

class DFTestCase(subprocesstest.SubprocessTestCase):
    """Base class for all tests in this dfilter-test collection."""


    def runDFilter(self, dfilter, expected_return=0):
        # Create the tshark command
        return self.assertRun((config.cmd_tshark,
            "-n",       # No name resolution
            "-r",       # Next arg is trace file to read
            os.path.join(config.capture_dir, self.trace_file),
            "-Y",       # packet display filter (used to be -R)
            dfilter
        ), expected_return=expected_return)


    def assertDFilterCount(self, dfilter, expected_count):
        """Run a display filter and expect a certain number of packets."""

        dfilter_proc = self.runDFilter(dfilter)

        dfp_count = self.countOutput()
        msg = "Expected %d, got: %s" % (expected_count, dfp_count)
        self.assertEqual(dfp_count, expected_count, msg)

    def assertDFilterFail(self, dfilter):
        """Run a display filter and expect tshark to fail"""

        dfilter_proc = self.runDFilter(dfilter, expected_return=self.exit_error)
