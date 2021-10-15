# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import unittest
import fixtures
from suite_dfilter.dfiltertest import *


@fixtures.uses_fixtures
class case_syntax(unittest.TestCase):
    trace_file = "http.pcap"

    def test_exists_1(self, checkDFilterCount):
        dfilter = "frame"
        checkDFilterCount(dfilter, 1)

    def test_commute_1(self, checkDFilterCount):
        dfilter = "ip.proto == 6"
        checkDFilterCount(dfilter, 1)

    def test_commute_2(self, checkDFilterCount):
        dfilter = "6 == ip.proto"
        checkDFilterCount(dfilter, 1)

    def test_func_1(self, checkDFilterCount):
        dfilter = "len(frame) == 207"
        checkDFilterCount(dfilter, 1)

    def test_value_string_1(self, checkDFilterSucceed):
        dfilter = 'eth.fcs.status=="Bad"'
        checkDFilterSucceed(dfilter)

    def test_matches_1(self, checkDFilterSucceed):
        dfilter = 'http.request.method matches "^HEAD"'
        checkDFilterSucceed(dfilter)

    def test_matches_2(self, checkDFilterFail):
        dfilter = 'http.request.method matches HEAD'
        checkDFilterFail(dfilter, 'Expected a string')

    def test_matches_3(self, checkDFilterFail):
        dfilter = 'http.request.method matches "^HEAD" matches "^POST"'
        checkDFilterFail(dfilter, '"matches" was unexpected in this context.')

    def test_matches_4(self, checkDFilterCount):
        dfilter = r'http.host matches r"update\.microsoft\.c.."'
        checkDFilterCount(dfilter, 1)
