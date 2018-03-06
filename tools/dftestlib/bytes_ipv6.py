# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

from dftestlib import dftest

class testBytesIPv6(dftest.DFTest):
    trace_file = "ipv6.pcap"

    def test_eq_1(self):
        dfilter = "ipv6.dst == ff05::9999"
        self.assertDFilterCount(dfilter, 1)

    def test_eq_2(self):
        dfilter = "ipv6.dst == ff05::9990"
        self.assertDFilterCount(dfilter, 0)

    def test_ne_1(self):
        dfilter = "ipv6.dst != ff05::9990"
        self.assertDFilterCount(dfilter, 1)

    def test_ne_2(self):
        dfilter = "ipv6.dst != ff05::9999"
        self.assertDFilterCount(dfilter, 0)

    def test_gt_1(self):
        dfilter = "ipv6.dst > ff05::0000"
        self.assertDFilterCount(dfilter, 1)

    def test_gt_2(self):
        dfilter = "ipv6.dst > ff05::9999"
        self.assertDFilterCount(dfilter, 0)

    def test_ge_1(self):
        dfilter = "ipv6.dst >= ff05::9999"
        self.assertDFilterCount(dfilter, 1)

    def test_ge_2(self):
        dfilter = "ipv6.dst >= ff05::a000"
        self.assertDFilterCount(dfilter, 0)

    def test_lt_1(self):
        dfilter = "ipv6.dst < ff05::a000"
        self.assertDFilterCount(dfilter, 1)

    def test_lt_2(self):
        dfilter = "ipv6.dst < ff05::9999"
        self.assertDFilterCount(dfilter, 0)

    def test_le_1(self):
        dfilter = "ipv6.dst <= ff05::9999"
        self.assertDFilterCount(dfilter, 1)

    def test_le_2(self):
        dfilter = "ipv6.dst <= ff05::9998"
        self.assertDFilterCount(dfilter, 0)

    def test_cidr_eq_1(self):
        dfilter = "ipv6.dst == ff05::9999/128"
        self.assertDFilterCount(dfilter, 1)

    def test_cidr_eq_2(self):
        dfilter = "ipv6.dst == ff05::0/64"
        self.assertDFilterCount(dfilter, 1)

    def test_cidr_eq_3(self):
        dfilter = "ipv6.dst == ff05::ffff/112"
        self.assertDFilterCount(dfilter, 1)

    def test_cidr_eq_4(self):
        dfilter = "ipv6.dst == ff04::0/64"
        self.assertDFilterCount(dfilter, 0)

    def test_cidr_ne_1(self):
        dfilter = "ipv6.dst != ff05::9999/128"
        self.assertDFilterCount(dfilter, 0)

    def test_cidr_ne_2(self):
        dfilter = "ipv6.dst != ff05::0/64"
        self.assertDFilterCount(dfilter, 0)

    def test_cidr_ne_3(self):
        dfilter = "ipv6.dst != ff05::ffff/112"
        self.assertDFilterCount(dfilter, 0)

    def test_cidr_ne_4(self):
        dfilter = "ipv6.dst != ff04::00/64"
        self.assertDFilterCount(dfilter, 1)

    def test_slice_1(self):
        dfilter = "ipv6.dst[14:2] == 99:99"
        self.assertDFilterCount(dfilter, 1)

    def test_slice_2(self):
        dfilter = "ipv6.dst[14:2] == 00:00"
        self.assertDFilterCount(dfilter, 0)

    def test_slice_3(self):
        dfilter = "ipv6.dst[15:1] == 99"
        self.assertDFilterCount(dfilter, 1)

    def test_slice_4(self):
        dfilter = "ipv6.dst[15:1] == 00"
        self.assertDFilterCount(dfilter, 0)
