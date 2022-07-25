# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import unittest
import fixtures
from suite_dfilter.dfiltertest import *


@fixtures.uses_fixtures
class case_double(unittest.TestCase):

    trace_file = "icmp.pcapng.gz"

    def test_eq_1(self, checkDFilterCount):
        dfilter = "icmp.resptime == 492.204"
        checkDFilterCount(dfilter, 1)

    def test_eq_2(self, checkDFilterCount):
        dfilter = "icmp.resptime == 492.205"
        checkDFilterCount(dfilter, 0)

    def test_eq_3(self, checkDFilterCount):
        dfilter = "icmp.resptime == 492204e-3"
        checkDFilterCount(dfilter, 1)

    def test_eq_4(self, checkDFilterCount):
        dfilter = "icmp.resptime == 492205e-3"
        checkDFilterCount(dfilter, 0)

    def test_ne_1(self, checkDFilterCount):
        dfilter = "icmp.resptime != 492.204"
        checkDFilterCount(dfilter, 0)

    def test_ne_2(self, checkDFilterCount):
        dfilter = "icmp.resptime != 492.205"
        checkDFilterCount(dfilter, 1)

    def test_ne_3(self, checkDFilterCount):
        dfilter = "icmp.resptime != 492204e-3"
        checkDFilterCount(dfilter, 0)

    def test_ne_4(self, checkDFilterCount):
        dfilter = "icmp.resptime != 492205e-3"
        checkDFilterCount(dfilter, 1)

    def test_gt_1(self, checkDFilterCount):
        dfilter = "icmp.resptime > 492"
        checkDFilterCount(dfilter, 1)

    def test_gt_2(self, checkDFilterCount):
        dfilter = "icmp.resptime > 492.203"
        checkDFilterCount(dfilter, 1)

    def test_gt_3(self, checkDFilterCount):
        dfilter = "icmp.resptime > 493"
        checkDFilterCount(dfilter, 0)

    def test_ge_1(self, checkDFilterCount):
        dfilter = "icmp.resptime >= 493"
        checkDFilterCount(dfilter, 0)

    def test_ge_2(self, checkDFilterCount):
        dfilter = "icmp.resptime >= 492"
        checkDFilterCount(dfilter, 1)

    def test_ge_3(self, checkDFilterCount):
        dfilter = "icmp.resptime >= 492.204"
        checkDFilterCount(dfilter, 1)

    def test_lt_1(self, checkDFilterCount):
        dfilter = "icmp.resptime < 493"
        checkDFilterCount(dfilter, 1)

    def test_lt_2(self, checkDFilterCount):
        dfilter = "icmp.resptime < 492"
        checkDFilterCount(dfilter, 0)

    def test_lt_3(self, checkDFilterCount):
        dfilter = "icmp.resptime < 492.204"
        checkDFilterCount(dfilter, 0)

    def test_le_1(self, checkDFilterCount):
        dfilter = "icmp.resptime <= 492.204"
        checkDFilterCount(dfilter, 1)

    def test_le_2(self, checkDFilterCount):
        dfilter = "icmp.resptime <= 493"
        checkDFilterCount(dfilter, 1)

    def test_le_3(self, checkDFilterCount):
        dfilter = "icmp.resptime <= 492"
        checkDFilterCount(dfilter, 0)
