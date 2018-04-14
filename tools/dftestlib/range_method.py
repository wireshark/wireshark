# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later


from dftestlib import dftest

class testRange(dftest.DFTest):
    trace_file = "ipx_rip.pcap"

    def test_slice_1_pos(self):
        dfilter = "ipx.src.node[1] == aa"
        self.assertDFilterCount(dfilter, 1)

    def test_slice_1_neg(self):
        dfilter = "ipx.src.node[1] == bb"
        self.assertDFilterCount(dfilter, 0)

    def test_slice_1_hex_pos(self):
        dfilter = "ipx.src.node[1] == 0xaa"
        self.assertDFilterCount(dfilter, 1)

    def test_slice_1_hex_neg(self):
        dfilter = "ipx.src.node[1] == 0xbb"
        self.assertDFilterCount(dfilter, 0)

    def test_slice_2_pos(self):
        dfilter = "ipx.src.node[3:2] == a3:e3"
        self.assertDFilterCount(dfilter, 1)

    def test_slice_2_neg(self):
        dfilter = "ipx.src.node[3:2] == cc:dd"
        self.assertDFilterCount(dfilter, 0)
