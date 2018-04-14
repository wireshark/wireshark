# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later


import unittest
from dftestlib import dftest

class testTVB(dftest.DFTest):
    trace_file = "http.pcap"

    def test_eq_1(self):
        # We expect 0 because even though this byte
        # string matches the 'eth' protocol, protocols cannot
        # work in an '==' comparison yet.
        dfilter = "eth == 00:e0:81:00:b0:28:00:09:6b:88:f6:c9:08:00"
        self.assertDFilterCount(dfilter, 0)

    def test_slice_1(self):
        dfilter = "ip[0:2] == 45:00"
        self.assertDFilterCount(dfilter, 1)

    def test_slice_2(self):
        dfilter = "ip[0:2] == 00:00"
        self.assertDFilterCount(dfilter, 0)

    def test_slice_3(self):
        dfilter = "ip[2:2] == 00:c1"
        self.assertDFilterCount(dfilter, 1)

    @unittest.skip("This doesn't work yet in Wireshark")
    def test_slice_4(self):
        dfilter = "ip[-5] == 0x86"
        self.assertDFilterCount(dfilter, 0)

    @unittest.skip("This doesn't work yet in Wireshark")
    def test_slice_5(self):
        dfilter = "ip[-1] == 0x86"
        self.assertDFilterCount(dfilter, 1)

    def test_contains_1(self):
        dfilter = "eth contains 6b"
        self.assertDFilterCount(dfilter, 1)

    def test_contains_2(self):
        dfilter = "eth contains 09:6b:88"
        self.assertDFilterCount(dfilter, 1)

    def test_contains_3(self):
        dfilter = "eth contains 00:e0:81:00:b0:28:00:09:6b:88:f5:c9:08:00"
        self.assertDFilterCount(dfilter, 1)

    def test_contains_4(self):
        dfilter = "eth contains ff:ff:ff"
        self.assertDFilterCount(dfilter, 0)

    def test_contains_5(self):
        dfilter = 'http contains "HEAD"'
        self.assertDFilterCount(dfilter, 1)


