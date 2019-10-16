# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
# -*- coding: utf-8 -*-
#
# SPDX-License-Identifier: GPL-2.0-or-later

import unittest
import fixtures
from suite_dfilter.dfiltertest import *


@fixtures.uses_fixtures
class case_string(unittest.TestCase):
    trace_file = "http.pcap"

    def test_eq_1(self, checkDFilterCount):
        dfilter = 'http.request.method == "HEAD"'
        checkDFilterCount(dfilter, 1)

    def test_eq_2(self, checkDFilterCount):
        dfilter = 'http.request.method == "POST"'
        checkDFilterCount(dfilter, 0)

    def test_gt_1(self, checkDFilterCount):
        dfilter = 'http.request.method > "HEAC"'
        checkDFilterCount(dfilter, 1)

    def test_gt_2(self, checkDFilterCount):
        dfilter = 'http.request.method > "HEAD"'
        checkDFilterCount(dfilter, 0)

    def test_gt_3(self, checkDFilterCount):
        dfilter = 'http.request.method > "HEAE"'
        checkDFilterCount(dfilter, 0)

    def test_ge_1(self, checkDFilterCount):
        dfilter = 'http.request.method >= "HEAC"'
        checkDFilterCount(dfilter, 1)

    def test_ge_2(self, checkDFilterCount):
        dfilter = 'http.request.method >= "HEAD"'
        checkDFilterCount(dfilter, 1)

    def test_ge_3(self, checkDFilterCount):
        dfilter = 'http.request.method >= "HEAE"'
        checkDFilterCount(dfilter, 0)

    def test_lt_1(self, checkDFilterCount):
        dfilter = 'http.request.method < "HEAC"'
        checkDFilterCount(dfilter, 0)

    def test_lt_2(self, checkDFilterCount):
        dfilter = 'http.request.method < "HEAD"'
        checkDFilterCount(dfilter, 0)

    def test_lt_3(self, checkDFilterCount):
        dfilter = 'http.request.method < "HEAE"'
        checkDFilterCount(dfilter, 1)

    def test_le_1(self, checkDFilterCount):
        dfilter = 'http.request.method <= "HEAC"'
        checkDFilterCount(dfilter, 0)

    def test_le_2(self, checkDFilterCount):
        dfilter = 'http.request.method <= "HEAD"'
        checkDFilterCount(dfilter, 1)

    def test_le_3(self, checkDFilterCount):
        dfilter = 'http.request.method <= "HEAE"'
        checkDFilterCount(dfilter, 1)

    def test_slice_1(self, checkDFilterCount):
        dfilter = 'http.request.method[0] == "H"'
        checkDFilterCount(dfilter, 1)

    def test_slice_2(self, checkDFilterCount):
        dfilter = 'http.request.method[0] == "P"'
        checkDFilterCount(dfilter, 0)

    def test_slice_3(self, checkDFilterCount):
        dfilter = 'http.request.method[0:4] == "HEAD"'
        checkDFilterCount(dfilter, 1)

    def test_slice_4(self, checkDFilterCount):
        dfilter = 'http.request.method[0:4] != "HEAD"'
        checkDFilterCount(dfilter, 0)

    def test_slice_5(self, checkDFilterCount):
        dfilter = 'http.request.method[1:2] == "EA"'
        checkDFilterCount(dfilter, 1)

    def test_slice_6(self, checkDFilterCount):
        dfilter = 'http.request.method[1:2] > "EA"'
        checkDFilterCount(dfilter, 0)

    def test_slice_7(self, checkDFilterCount):
        dfilter = 'http.request.method[-1] == "D"'
        checkDFilterCount(dfilter, 1)

    def test_slice_8(self, checkDFilterCount):
        dfilter = 'http.request.method[-2] == "D"'
        checkDFilterCount(dfilter, 0)

    def xxxtest_stringz_1(self):
            return self.DFilterCount(pkt_tftp,
                    'tftp.type == "octet"', 1)

    def xxxtest_stringz_2(self):
            return self.DFilterCount(pkt_tftp,
                    'tftp.type == "junk"', 0)

    def test_contains_1(self, checkDFilterCount):
        dfilter = 'http.request.method contains "E"'
        checkDFilterCount(dfilter, 1)

    def test_contains_2(self, checkDFilterCount):
        dfilter = 'http.request.method contains "EA"'
        checkDFilterCount(dfilter, 1)

    def test_contains_3(self, checkDFilterCount):
        dfilter = 'http.request.method contains "HEAD"'
        checkDFilterCount(dfilter, 1)

    def test_contains_4(self, checkDFilterCount):
        dfilter = 'http.request.method contains "POST"'
        checkDFilterCount(dfilter, 0)

    def test_contains_5(self, checkDFilterCount):
        dfilter = 'http.request.method contains 50:4f:53:54' # "POST"
        checkDFilterCount(dfilter, 0)

    def test_contains_6(self, checkDFilterCount):
        dfilter = 'http.request.method contains 48:45:41:44' # "HEAD"
        checkDFilterCount(dfilter, 1)

    def test_contains_fail_0(self, checkDFilterCount):
        dfilter = 'http.user_agent contains "update"'
        checkDFilterCount(dfilter, 0)

    def test_contains_fail_1(self, checkDFilterCount):
        dfilter = 'http.user_agent contains "UPDATE"'
        checkDFilterCount(dfilter, 0)

    def test_contains_upper_0(self, checkDFilterCount):
        dfilter = 'upper(http.user_agent) contains "UPDATE"'
        checkDFilterCount(dfilter, 1)

    def test_contains_upper_1(self, checkDFilterCount):
        dfilter = 'upper(http.user_agent) contains "update"'
        checkDFilterCount(dfilter, 0)

    def test_contains_upper_2(self, checkDFilterFail):
        dfilter = 'upper(tcp.seq) == 4'
        error = 'Only strings can be used in upper() or lower() or len()'
        checkDFilterFail(dfilter, error)

    def test_contains_lower_0(self, checkDFilterCount):
        dfilter = 'lower(http.user_agent) contains "UPDATE"'
        checkDFilterCount(dfilter, 0)

    def test_contains_lower_1(self, checkDFilterCount):
        dfilter = 'lower(http.user_agent) contains "update"'
        checkDFilterCount(dfilter, 1)

    def test_eq_lower_1(self, checkDFilterFail):
        dfilter = 'lower(tcp.seq) == 4'
        error = 'Only strings can be used in upper() or lower() or len()'
        checkDFilterFail(dfilter, error)

    def test_string_len(self, checkDFilterCount):
        dfilter = 'len(http.request.method) == 4'
        checkDFilterCount(dfilter, 1)

    def test_eq_unicode(self, checkDFilterCount):
        dfilter = 'tcp.flags.str == "·······AP···"'
        checkDFilterCount(dfilter, 1)

    def test_contains_unicode(self, checkDFilterCount):
        dfilter = 'tcp.flags.str contains "·······AP···"'
        checkDFilterCount(dfilter, 1)
