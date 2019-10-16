# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import unittest
import fixtures
from suite_dfilter.dfiltertest import *


@fixtures.uses_fixtures
class case_stringz(unittest.TestCase):
    trace_file = "tftp.pcap"

    def test_stringz_1(self, checkDFilterCount):
        dfilter = 'tftp.type == octet'
        checkDFilterCount(dfilter, 1)

    def test_stringz_2(self, checkDFilterCount):
        dfilter = 'tftp.type == "octet"'
        checkDFilterCount(dfilter, 1)

    def test_stringz_3(self, checkDFilterCount):
        dfilter = 'tftp.type == junk'
        checkDFilterCount(dfilter, 0)

