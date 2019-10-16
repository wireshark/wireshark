# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import unittest
import fixtures
from suite_dfilter.dfiltertest import *


@fixtures.uses_fixtures
class case_time_relative(unittest.TestCase):
    trace_file = "nfs.pcap"

    def test_relative_time_1(self, checkDFilterCount):
        dfilter = "frame.time_delta == 0.7"
        checkDFilterCount(dfilter, 1)

    def test_relative_time_2(self, checkDFilterCount):
        dfilter = "frame.time_delta > 0.7"
        checkDFilterCount(dfilter, 0)

    def test_relative_time_3(self, checkDFilterCount):
        dfilter = "frame.time_delta < 0.7"
        checkDFilterCount(dfilter, 1)

