# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import unittest
import fixtures
from suite_dfilter.dfiltertest import *


@fixtures.uses_fixtures
class case_integer_1_byte(unittest.TestCase):

    trace_file = "ipx_rip.pcap"

    def test_ipx_1(self, checkDFilterCount):
        dfilter = "ipx.src.net == 0x28"
        checkDFilterCount(dfilter, 1)

    def test_ipx_2(self, checkDFilterCount):
        dfilter = "ipx.src.net == 0x29"
        checkDFilterCount(dfilter, 0)
