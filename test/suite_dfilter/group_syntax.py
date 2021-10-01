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
