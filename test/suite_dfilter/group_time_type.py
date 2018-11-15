# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import unittest
import fixtures
from suite_dfilter.dfiltertest import *


@fixtures.uses_fixtures
class case_time(unittest.TestCase):
    trace_file = "http.pcap"

    def test_eq_1(self, checkDFilterCount):
        dfilter = 'frame.time == "Dec 31, 2002 13:55:31.3"'
        checkDFilterCount(dfilter, 1)

    def test_eq_2(self, checkDFilterCount):
        dfilter = 'frame.time == "Jan 31, 2002 13:55:31.3"'
        checkDFilterCount(dfilter, 0)

    def test_ne_1(self, checkDFilterCount):
        dfilter = 'frame.time != "Dec 31, 2002 13:55:31.3"'
        checkDFilterCount(dfilter, 0)

    def test_ne_2(self, checkDFilterCount):
        dfilter = 'frame.time != "Jan 31, 2002 13:55:31.3"'
        checkDFilterCount(dfilter, 1)

    def test_gt_1(self, checkDFilterCount):
        dfilter = 'frame.time > "Dec 31, 2002 13:54:31.3"'
        checkDFilterCount(dfilter, 1)

    def test_gt_2(self, checkDFilterCount):
        dfilter = 'frame.time > "Dec 31, 2002 13:55:31.3"'
        checkDFilterCount(dfilter, 0)

    def test_gt_3(self, checkDFilterCount):
        dfilter = 'frame.time > "Dec 31, 2002 13:56:31.3"'
        checkDFilterCount(dfilter, 0)

    def test_ge_1(self, checkDFilterCount):
        dfilter = 'frame.time >= "Dec 31, 2002 13:54:31.3"'
        checkDFilterCount(dfilter, 1)

    def test_ge_2(self, checkDFilterCount):
        dfilter = 'frame.time >= "Dec 31, 2002 13:55:31.3"'
        checkDFilterCount(dfilter, 1)

    def test_ge_3(self, checkDFilterCount):
        dfilter = 'frame.time >= "Dec 31, 2002 13:56:31.3"'
        checkDFilterCount(dfilter, 0)

    def test_lt_1(self, checkDFilterCount):
        dfilter = 'frame.time < "Dec 31, 2002 13:54:31.3"'
        checkDFilterCount(dfilter, 0)

    def test_lt_2(self, checkDFilterCount):
        dfilter = 'frame.time < "Dec 31, 2002 13:55:31.3"'
        checkDFilterCount(dfilter, 0)

    def test_lt_3(self, checkDFilterCount):
        dfilter = 'frame.time < "Dec 31, 2002 13:56:31.3"'
        checkDFilterCount(dfilter, 1)

    def test_le_1(self, checkDFilterCount):
        dfilter = 'frame.time <= "Dec 31, 2002 13:54:31.3"'
        checkDFilterCount(dfilter, 0)

    def test_le_2(self, checkDFilterCount):
        dfilter = 'frame.time <= "Dec 31, 2002 13:55:31.3"'
        checkDFilterCount(dfilter, 1)

    def test_le_3(self, checkDFilterCount):
        dfilter = 'frame.time <= "Dec 31, 2002 13:56:31.3"'
        checkDFilterCount(dfilter, 1)

