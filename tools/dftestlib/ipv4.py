# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later


from dftestlib import dftest

class testIPv4(dftest.DFTest):
    trace_file = "nfs.pcap"

    def test_uint64_1(self):
        dfilter = "nfs.fattr3.size == 264032"
        self.assertDFilterCount(dfilter, 1)

    def test_eq_1(self):
        dfilter = "ip.src == 172.25.100.14"
        self.assertDFilterCount(dfilter, 1)

    def test_eq_2(self):
        dfilter = "ip.src == 255.255.255.255"
        self.assertDFilterCount(dfilter, 0)

    def test_ne_1(self):
        dfilter = "ip.src != 172.25.100.14"
        self.assertDFilterCount(dfilter, 1)

    def test_ne_2(self):
        dfilter = "ip.src != 255.255.255.255"
        self.assertDFilterCount(dfilter, 2)

    def test_gt_1(self):
        dfilter = "ip.dst > 198.95.230.200"
        self.assertDFilterCount(dfilter, 0)

    def test_gt_2(self):
        dfilter = "ip.dst > 198.95.230.20"
        self.assertDFilterCount(dfilter, 0)

    def test_gt_3(self):
        dfilter = "ip.dst > 198.95.230.10"
        self.assertDFilterCount(dfilter, 1)

    def test_ge_1(self):
        dfilter = "ip.dst >= 198.95.230.200"
        self.assertDFilterCount(dfilter, 0)

    def test_ge_2(self):
        dfilter = "ip.dst >= 198.95.230.20"
        self.assertDFilterCount(dfilter, 1)

    def test_ge_3(self):
        dfilter = "ip.dst >= 198.95.230.10"
        self.assertDFilterCount(dfilter, 1)

    def test_lt_1(self):
        dfilter = "ip.src < 172.25.100.140"
        self.assertDFilterCount(dfilter, 1)

    def test_lt_2(self):
        dfilter = "ip.src < 172.25.100.14"
        self.assertDFilterCount(dfilter, 0)

    def test_lt_3(self):
        dfilter = "ip.src < 172.25.100.10"
        self.assertDFilterCount(dfilter, 0)

    def test_le_1(self):
        dfilter = "ip.src <= 172.25.100.140"
        self.assertDFilterCount(dfilter, 1)

    def test_le_2(self):
        dfilter = "ip.src <= 172.25.100.14"
        self.assertDFilterCount(dfilter, 1)

    def test_le_3(self):
        dfilter = "ip.src <= 172.25.100.10"
        self.assertDFilterCount(dfilter, 0)

    def test_cidr_eq_1(self):
        dfilter = "ip.src == 172.25.100.14/32"
        self.assertDFilterCount(dfilter, 1)

    def test_cidr_eq_2(self):
        dfilter = "ip.src == 172.25.100.0/24"
        self.assertDFilterCount(dfilter, 1)

    def test_cidr_eq_3(self):
        dfilter = "ip.src == 172.25.0.0/16"
        self.assertDFilterCount(dfilter, 1)

    def test_cidr_eq_4(self):
        dfilter = "ip.src == 172.0.0.0/8"
        self.assertDFilterCount(dfilter, 1)

    def test_cidr_ne_1(self):
        dfilter = "ip.src != 172.25.100.14/32"
        self.assertDFilterCount(dfilter, 1)

    def test_cidr_ne_2(self):
        dfilter = "ip.src != 172.25.100.0/24"
        self.assertDFilterCount(dfilter, 1)

    def test_cidr_ne_3(self):
        dfilter = "ip.src != 172.25.0.0/16"
        self.assertDFilterCount(dfilter, 1)

    def test_cidr_ne_4(self):
        dfilter = "ip.src != 200.0.0.0/8"
        self.assertDFilterCount(dfilter, 2)

    def test_slice_1(self):
         dfilter = "ip.src[0:2] == ac:19"
         self.assertDFilterCount(dfilter, 1)

    def test_slice_2(self):
         dfilter = "ip.src[0:2] == 00:00"
         self.assertDFilterCount(dfilter, 0)

    def test_slice_3(self):
         dfilter = "ip.src[2:2] == 64:0e"
         self.assertDFilterCount(dfilter, 1)

    def test_slice_4(self):
         dfilter = "ip.src[2:2] == ff:ff"
         self.assertDFilterCount(dfilter, 0)
