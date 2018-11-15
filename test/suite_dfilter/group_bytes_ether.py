# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import unittest
import fixtures
from suite_dfilter.dfiltertest import *


@fixtures.uses_fixtures
class case_bytes_ether(unittest.TestCase):
    trace_file = "ipx_rip.pcap"

    ### Note: Bytes test does not yet test FT_INT64.

    def test_eq_1(self, checkDFilterCount):
        dfilter = "eth.dst == ff:ff:ff:ff:ff:ff"
        checkDFilterCount(dfilter, 1)

    def test_eq_2(self, checkDFilterCount):
        dfilter = "eth.src == ff:ff:ff:ff:ff:ff"
        checkDFilterCount(dfilter, 0)

    def test_ne_1(self, checkDFilterCount):
        dfilter = "eth.dst != ff:ff:ff:ff:ff:ff"
        checkDFilterCount(dfilter, 0)

    def test_ne_2(self, checkDFilterCount):
        dfilter = "eth.src != ff:ff:ff:ff:ff:ff"
        checkDFilterCount(dfilter, 1)

    def test_gt_1(self, checkDFilterCount):
        dfilter = "eth.src > 00:aa:00:a3:e3:ff"
        checkDFilterCount(dfilter, 0)

    def test_gt_2(self, checkDFilterCount):
        dfilter = "eth.src > 00:aa:00:a3:e3:a4"
        checkDFilterCount(dfilter, 0)

    def test_gt_3(self, checkDFilterCount):
        dfilter = "eth.src > 00:aa:00:a3:e3:00"
        checkDFilterCount(dfilter, 1)

    def test_ge_1(self, checkDFilterCount):
        dfilter = "eth.src >= 00:aa:00:a3:e3:ff"
        checkDFilterCount(dfilter, 0)

    def test_ge_2(self, checkDFilterCount):
        dfilter = "eth.src >= 00:aa:00:a3:e3:a4"
        checkDFilterCount(dfilter, 1)

    def test_ge_3(self, checkDFilterCount):
        dfilter = "eth.src >= 00:aa:00:a3:e3:00"
        checkDFilterCount(dfilter, 1)

    def test_lt_1(self, checkDFilterCount):
        dfilter = "eth.src < 00:aa:00:a3:e3:ff"
        checkDFilterCount(dfilter, 1)

    def test_lt_2(self, checkDFilterCount):
        dfilter = "eth.src < 00:aa:00:a3:e3:a4"
        checkDFilterCount(dfilter, 0)

    def test_lt_3(self, checkDFilterCount):
        dfilter = "eth.src < 00:aa:00:a3:e3:00"
        checkDFilterCount(dfilter, 0)

    def test_le_1(self, checkDFilterCount):
        dfilter = "eth.src <= 00:aa:00:a3:e3:ff"
        checkDFilterCount(dfilter, 1)

    def test_le_2(self, checkDFilterCount):
        dfilter = "eth.src <= 00:aa:00:a3:e3:a4"
        checkDFilterCount(dfilter, 1)

    def test_le_3(self, checkDFilterCount):
        dfilter = "eth.src <= 00:aa:00:a3:e3:00"
        checkDFilterCount(dfilter, 0)

    def test_slice_1(self, checkDFilterCount):
        dfilter = "eth.src[0:3] == 00:aa:00"
        checkDFilterCount(dfilter, 1)

    def test_slice_2(self, checkDFilterCount):
        dfilter = "eth.src[-3:3] == a3:e3:a4"
        checkDFilterCount(dfilter, 1)

    def test_slice_3(self, checkDFilterCount):
        dfilter = "eth.src[1:4] == aa:00:a3:e3"
        checkDFilterCount(dfilter, 1)

    def test_slice_4(self, checkDFilterCount):
        dfilter = "eth.src[0] == 00"
        checkDFilterCount(dfilter, 1)

    def test_contains_1(self, checkDFilterCount):
        dfilter = "ipx.src.node contains a3"
        checkDFilterCount(dfilter, 1)

    def test_contains_2(self, checkDFilterCount):
        dfilter = "ipx.src.node contains a3:e3"
        checkDFilterCount(dfilter, 1)

    def test_contains_3(self, checkDFilterCount):
        dfilter = "ipx.src.node contains 00:aa:00:a3:e3:a4"
        checkDFilterCount(dfilter, 1)

    def test_contains_4(self, checkDFilterCount):
        dfilter = "ipx.src.node contains aa:e3"
        checkDFilterCount(dfilter, 0)
