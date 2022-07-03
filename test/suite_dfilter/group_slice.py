# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import unittest
import fixtures
from suite_dfilter.dfiltertest import *


@fixtures.uses_fixtures
class case_range(unittest.TestCase):
    trace_file = "ipx_rip.pcap"

    def test_slice_1_pos(self, checkDFilterCount):
        dfilter = "ipx.src.node[1] == aa"
        checkDFilterCount(dfilter, 1)

    def test_slice_2_pos(self, checkDFilterCount):
        dfilter = "ipx.src.node[1] == bb"
        checkDFilterCount(dfilter, 0)

    def test_slice_1_neg(self, checkDFilterCount):
        dfilter = "ipx[-2:] == 04:53"
        checkDFilterCount(dfilter, 1)

    def test_slice_1_hex_pos(self, checkDFilterCount):
        dfilter = "ipx.src.node[1] == 0xaa"
        checkDFilterCount(dfilter, 1)

    def test_slice_1_hex_neg(self, checkDFilterCount):
        dfilter = "ipx.src.node[1] == 0xbb"
        checkDFilterCount(dfilter, 0)

    def test_slice_2_pos(self, checkDFilterCount):
        dfilter = "ipx.src.node[3:2] == a3:e3"
        checkDFilterCount(dfilter, 1)

    def test_slice_2_neg(self, checkDFilterCount):
        dfilter = "ipx.src.node[3:2] == cc:dd"
        checkDFilterCount(dfilter, 0)

    def test_slice_string_1(self, checkDFilterFail):
        dfilter = "frame == \"00\"[1]"
        checkDFilterFail(dfilter, "Range is not supported for entity")

    def test_slice_unparsed_1(self, checkDFilterFail):
        dfilter = "frame == b[1]"
        checkDFilterFail(dfilter, "Range is not supported for entity")

    def test_slice_func_1(self, checkDFilterSucceed):
        dfilter = "string(ipx.src.node)[3:2] == \"cc:dd\""
        checkDFilterSucceed(dfilter)

    # [i:j]    i = start_offset, j = length
    # [i-j]    i = start_offset, j = end_offset, inclusive.
    # [i]      i = start_offset, length = 1
    # [:j]     start_offset = 0, length = j
    # [i:]     start_offset = i, end_offset = end_of_field

    def test_slice_range_1(self, checkDFilterSucceed):
        # :5 is a length
        dfilter = "frame[5:5] == 11:22:33:44:55"
        checkDFilterSucceed(dfilter)

    def test_slice_range_2(self, checkDFilterSucceed):
        # end offset is inclusive
        dfilter = "frame[5-10] == 11:22:33:44:55:66"
        checkDFilterSucceed(dfilter)

    def test_slice_range_3(self, checkDFilterSucceed):
        dfilter = "frame[5] == 11"
        checkDFilterSucceed(dfilter)

    def test_slice_range_4(self, checkDFilterSucceed):
        dfilter = "frame[:20] contains be:ef"
        checkDFilterSucceed(dfilter)

    def test_slice_range_5(self, checkDFilterSucceed):
        dfilter = "frame[20:] contains :12345678"
        checkDFilterSucceed(dfilter)

    def test_slice_exists_1(self, checkDFilterCount):
        dfilter = "frame[59]"
        checkDFilterCount(dfilter, 1)

    def test_slice_exists_2(self, checkDFilterCount):
        dfilter = "frame[60]"
        checkDFilterCount(dfilter, 0)

    def test_slice_exists_3(self, checkDFilterCount):
        dfilter = "frame[50-59]"
        checkDFilterCount(dfilter, 1)

    def test_slice_exists_4(self, checkDFilterCount):
        dfilter = "frame[50-60]"
        checkDFilterCount(dfilter, 0)
