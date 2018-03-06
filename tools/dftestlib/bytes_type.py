# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later


from dftestlib import dftest

class testBytes(dftest.DFTest):
    trace_file = "arp.pcap"

    def test_bytes_1(self):
        dfilter = "arp.dst.hw == 00:64"
        self.assertDFilterCount(dfilter, 1)

    def test_ipv6_2(self):
        dfilter = "arp.dst.hw == 00:00"
        self.assertDFilterCount(dfilter, 0)
