# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import unittest
import fixtures
from suite_dfilter.dfiltertest import *


@fixtures.uses_fixtures
class case_uint64(unittest.TestCase):
    trace_file = "nfs.pcap"

    def test_uint64_1(self, checkDFilterCount):
        dfilter = "nfs.fattr3.size == 264032"
        checkDFilterCount(dfilter, 1)

    def test_uint64_2(self, checkDFilterCount):
        dfilter = "nfs.fattr3.size == 264000"
        checkDFilterCount(dfilter, 0)
