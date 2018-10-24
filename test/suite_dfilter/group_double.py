# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import unittest

from suite_dfilter import dfiltertest

class case_double(dfiltertest.DFTestCase):

    trace_file = "icmp.pcapng.gz"

    def test_eq_1(self):
        dfilter = "icmp.resptime == 492.204"
        self.assertDFilterCount(dfilter, 1)

    def test_eq_2(self):
        dfilter = "icmp.resptime == 492.205"
        self.assertDFilterCount(dfilter, 0)

    def test_gt_1(self):
        dfilter = "icmp.resptime > 492"
        self.assertDFilterCount(dfilter, 1)

    def test_gt_2(self):
        dfilter = "icmp.resptime > 492.203"
        self.assertDFilterCount(dfilter, 1)

    def test_gt_3(self):
        dfilter = "icmp.resptime > 493"
        self.assertDFilterCount(dfilter, 0)

    def test_ge_1(self):
        dfilter = "icmp.resptime >= 493"
        self.assertDFilterCount(dfilter, 0)

    def test_ge_2(self):
        dfilter = "icmp.resptime >= 492"
        self.assertDFilterCount(dfilter, 1)

    def test_ge_3(self):
        dfilter = "icmp.resptime >= 492.204"
        self.assertDFilterCount(dfilter, 1)

    def test_lt_1(self):
        dfilter = "icmp.resptime < 493"
        self.assertDFilterCount(dfilter, 1)

    def test_lt_2(self):
        dfilter = "icmp.resptime < 492"
        self.assertDFilterCount(dfilter, 0)

    def test_lt_3(self):
        dfilter = "icmp.resptime < 492.204"
        self.assertDFilterCount(dfilter, 0)

    def test_le_1(self):
        dfilter = "icmp.resptime <= 492.204"
        self.assertDFilterCount(dfilter, 1)

    def test_le_2(self):
        dfilter = "icmp.resptime <= 493"
        self.assertDFilterCount(dfilter, 1)

    def test_le_3(self):
        dfilter = "icmp.resptime <= 492"
        self.assertDFilterCount(dfilter, 0)
