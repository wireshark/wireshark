# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later


from dftestlib import dftest

class testTimeRelative(dftest.DFTest):
    trace_file = "nfs.pcap"

    def test_relative_time_1(self):
        dfilter = "frame.time_delta == 0.7"
        self.assertDFilterCount(dfilter, 1)

    def test_relative_time_2(self):
        dfilter = "frame.time_delta > 0.7"
        self.assertDFilterCount(dfilter, 0)

    def test_relative_time_3(self):
        dfilter = "frame.time_delta < 0.7"
        self.assertDFilterCount(dfilter, 1)

