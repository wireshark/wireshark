# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later


from dftestlib import dftest

class testInteger1Byte(dftest.DFTest):

    trace_file = "ipx_rip.pcap"

    def test_ipx_1(self):
        dfilter = "ipx.src.net == 0x28"
        self.assertDFilterCount(dfilter, 1)

    def test_ipx_2(self):
        dfilter = "ipx.src.net == 0x29"
        self.assertDFilterCount(dfilter, 0)
