# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest
from suite_dfilter.dfiltertest import *


class TestDfilterDouble:

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

    def test_inf_1(self, checkDFilterCount):
        dfilter = "icmp.resptime < inf"
        checkDFilterCount(dfilter, 1)

    def test_inf_2(self, checkDFilterCount):
        dfilter = "icmp.resptime > -infinity"
        checkDFilterCount(dfilter, 1)

    def test_inf_3(self, checkDFilterCount):
        # A protocol can't have the name inf or infinity, but a field can
        # This is just to check that the filter compiles without error
        dfilter = "dvmrp.infinity == 255"
        checkDFilterCount(dfilter, 0)

    def test_nan(self, checkDFilterCount):
        # XXX - We compare NaNs oddly
        dfilter = "icmp.resptime == nan"
        checkDFilterCount(dfilter, 1)
