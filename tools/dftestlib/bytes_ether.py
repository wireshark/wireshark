# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

from dftestlib import dftest

class testBytesEther(dftest.DFTest):
    trace_file = "ipx_rip.pcap"

    ### Note: Bytes test does not yet test FT_INT64.

    def test_eq_1(self):
        dfilter = "eth.dst == ff:ff:ff:ff:ff:ff"
        self.assertDFilterCount(dfilter, 1)

    def test_eq_2(self):
        dfilter = "eth.src == ff:ff:ff:ff:ff:ff"
        self.assertDFilterCount(dfilter, 0)

    def test_ne_1(self):
        dfilter = "eth.dst != ff:ff:ff:ff:ff:ff"
        self.assertDFilterCount(dfilter, 0)

    def test_ne_2(self):
        dfilter = "eth.src != ff:ff:ff:ff:ff:ff"
        self.assertDFilterCount(dfilter, 1)

    def test_gt_1(self):
        dfilter = "eth.src > 00:aa:00:a3:e3:ff"
        self.assertDFilterCount(dfilter, 0)

    def test_gt_2(self):
        dfilter = "eth.src > 00:aa:00:a3:e3:a4"
        self.assertDFilterCount(dfilter, 0)

    def test_gt_3(self):
        dfilter = "eth.src > 00:aa:00:a3:e3:00"
        self.assertDFilterCount(dfilter, 1)

    def test_ge_1(self):
        dfilter = "eth.src >= 00:aa:00:a3:e3:ff"
        self.assertDFilterCount(dfilter, 0)

    def test_ge_2(self):
        dfilter = "eth.src >= 00:aa:00:a3:e3:a4"
        self.assertDFilterCount(dfilter, 1)

    def test_ge_3(self):
        dfilter = "eth.src >= 00:aa:00:a3:e3:00"
        self.assertDFilterCount(dfilter, 1)

    def test_lt_1(self):
        dfilter = "eth.src < 00:aa:00:a3:e3:ff"
        self.assertDFilterCount(dfilter, 1)

    def test_lt_2(self):
        dfilter = "eth.src < 00:aa:00:a3:e3:a4"
        self.assertDFilterCount(dfilter, 0)

    def test_lt_3(self):
        dfilter = "eth.src < 00:aa:00:a3:e3:00"
        self.assertDFilterCount(dfilter, 0)

    def test_le_1(self):
        dfilter = "eth.src <= 00:aa:00:a3:e3:ff"
        self.assertDFilterCount(dfilter, 1)

    def test_le_2(self):
        dfilter = "eth.src <= 00:aa:00:a3:e3:a4"
        self.assertDFilterCount(dfilter, 1)

    def test_le_3(self):
        dfilter = "eth.src <= 00:aa:00:a3:e3:00"
        self.assertDFilterCount(dfilter, 0)

    def test_slice_1(self):
        dfilter = "eth.src[0:3] == 00:aa:00"
        self.assertDFilterCount(dfilter, 1)

    def test_slice_2(self):
        dfilter = "eth.src[-3:3] == a3:e3:a4"
        self.assertDFilterCount(dfilter, 1)

    def test_slice_3(self):
        dfilter = "eth.src[1:4] == aa:00:a3:e3"
        self.assertDFilterCount(dfilter, 1)

    def test_slice_4(self):
        dfilter = "eth.src[0] == 00"
        self.assertDFilterCount(dfilter, 1)

    def test_contains_1(self):
        dfilter = "ipx.src.node contains a3"
        self.assertDFilterCount(dfilter, 1)

    def test_contains_2(self):
        dfilter = "ipx.src.node contains a3:e3"
        self.assertDFilterCount(dfilter, 1)

    def test_contains_3(self):
        dfilter = "ipx.src.node contains 00:aa:00:a3:e3:a4"
        self.assertDFilterCount(dfilter, 1)

    def test_contains_4(self):
        dfilter = "ipx.src.node contains aa:e3"
        self.assertDFilterCount(dfilter, 0)
