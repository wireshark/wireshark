# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import unittest
import fixtures
from suite_dfilter.dfiltertest import *


@fixtures.uses_fixtures
class case_tvb(unittest.TestCase):
    trace_file = "http.pcap"

    @unittest.skip("Protocol equality doesn't work yet in Wireshark")
    def test_eq_1(self, checkDFilterCount):
        # Protocols cannot work in an '==' comparison yet. The protocol
        # fvalue length runs to the end of the TVBuff. This needs to be fixed.
        dfilter = "eth == 00:e0:81:00:b0:28:00:09:6b:88:f5:c9:08:00"
        checkDFilterCount(dfilter, 1)

    @unittest.skip("Protocol equality doesn't work yet in Wireshark")
    def test_eq_2(self, checkDFilterCount):
        # This is a more stringent test than 'eth' above because TCP has variable length.
        dfilter = "tcp == 0c:c3:00:50:a8:00:76:87:7d:e0:14:02:50:18:fa:f0:ad:62:00:00"
        checkDFilterCount(dfilter, 1)

    def test_slice_1(self, checkDFilterCount):
        dfilter = "ip[0:2] == 45:00"
        checkDFilterCount(dfilter, 1)

    def test_slice_2(self, checkDFilterCount):
        dfilter = "ip[0:2] == 00:00"
        checkDFilterCount(dfilter, 0)

    def test_slice_3(self, checkDFilterCount):
        dfilter = "ip[2:2] == 00:c1"
        checkDFilterCount(dfilter, 1)

    @unittest.skip("Negative offsets don't work yet in Wireshark")
    def test_slice_4(self, checkDFilterCount):
        # Fixing protocol equality would also fix this. Wireshark's understanding
        # of protocol length is wrong so the "offset from the end" is also wrong.
        dfilter = "ip[-1] == 0x5e"
        checkDFilterCount(dfilter, 1)

    def test_contains_1(self, checkDFilterCount):
        dfilter = "eth contains 6b"
        checkDFilterCount(dfilter, 1)

    def test_contains_2(self, checkDFilterCount):
        dfilter = "eth contains 09:6b:88"
        checkDFilterCount(dfilter, 1)

    def test_contains_3(self, checkDFilterCount):
        dfilter = "eth contains 00:e0:81:00:b0:28:00:09:6b:88:f5:c9:08:00"
        checkDFilterCount(dfilter, 1)

    def test_contains_4(self, checkDFilterCount):
        dfilter = "eth contains ff:ff:ff"
        checkDFilterCount(dfilter, 0)

    def test_contains_5(self, checkDFilterCount):
        dfilter = 'http contains "HEAD"'
        checkDFilterCount(dfilter, 1)


