# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>

from dftestlib import dftest

class testStringz(dftest.DFTest):
    trace_file = "tftp.cap"

    def test_stringz_1(self):
        dfilter = 'tftp.type == octet'
        self.assertDFilterCount(dfilter, 1)

    def test_stringz_2(self):
        dfilter = 'tftp.type == "octet"'
        self.assertDFilterCount(dfilter, 1)

    def test_stringz_3(self):
        dfilter = 'tftp.type == junk'
        self.assertDFilterCount(dfilter, 0)

