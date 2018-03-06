# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later


from dftestlib import dftest

class testUINT64(dftest.DFTest):
    trace_file = "nfs.pcap"

    def test_uint64_1(self):
        dfilter = "nfs.fattr3.size == 264032"
        self.assertDFilterCount(dfilter, 1)

    def test_uint64_2(self):
        dfilter = "nfs.fattr3.size == 264000"
        self.assertDFilterCount(dfilter, 0)
