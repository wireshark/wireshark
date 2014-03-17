# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


import os
import tempfile
import unittest

from dftestlib import util

# The binaries to use. We assume we are running
# from the top of the wireshark distro
TSHARK = os.path.join(".", "tshark")

class DFTest(unittest.TestCase):
    """Base class for all tests in this dfilter-test collection."""

    # Remove these file when finished (in tearDownClass)
    files_to_remove = []

    @classmethod
    def setUpClass(cls):
        """Create the trace file to be used in the tests."""
        assert cls.trace_file

        # if the class sets the 'trace_file' field, then it
        # names the trace file to use for the tests. It *should*
        # reside in dftestfiles
        assert not os.path.isabs(cls.trace_file)
        cls.trace_file = os.path.join(".", "tools", "dftestfiles",
                cls.trace_file)

    @classmethod
    def tearDownClass(cls):
        """Remove the trace file used in the tests."""
        for filename in cls.files_to_remove:
            if os.path.exists(filename):
                try:
                    os.remove(filename)
                except OSError:
                    pass


    def runDFilter(self, dfilter):
        # Create the tshark command
        cmdv = [TSHARK,
                "-n",       # No name resolution
                "-r",       # Next arg is trace file to read
                self.trace_file,
                "-Y",       # packet display filter (used to be -R)
                dfilter]

        (status, output) = util.exec_cmdv(cmdv)
        return status, output


    def assertDFilterCount(self, dfilter, expected_count):
        """Run a display filter and expect a certain number of packets."""
        
        (status, output) = self.runDFilter(dfilter)

        # tshark must succeed
        self.assertEqual(status, util.SUCCESS, output)
        
        # Split the output (one big string) into lines, removing
        # empty lines (extra newline at end of output)
        lines = [L for L in output.split("\n") if L != ""]

        msg = "Expected %d, got: %s" % (expected_count, output)
        self.assertEqual(len(lines), expected_count, msg)

    def assertDFilterFail(self, dfilter):
        """Run a display filter and expect tshark to fail"""

        (status, output) = self.runDFilter(dfilter)

        # tshark must succeed
        self.assertNotEqual(status, util.SUCCESS, output)
