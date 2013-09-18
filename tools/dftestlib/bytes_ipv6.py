# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>

from dftestlib import dftest

class testBytesIPv6(dftest.DFTest):
    trace_file = "ipv6.cap"

    def test_ipv6_1(self):
        dfilter = "ipv6.dst == ff05::9999"
        self.assertDFilterCount(dfilter, 1)

    def test_ipv6_2(self):
        dfilter = "ipv6.dst == ff05::9990"
        self.assertDFilterCount(dfilter, 0)
