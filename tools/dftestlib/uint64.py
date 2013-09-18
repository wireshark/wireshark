# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>

from dftestlib import dftest

class testUINT64(dftest.DFTest):
    trace_file = "nfs.cap"

    def test_uint64_1(self):
        dfilter = "nfs.fattr3.size == 264032"
        self.assertDFilterCount(dfilter, 1)

    def test_uint64_2(self):
        dfilter = "nfs.fattr3.size == 264000"
        self.assertDFilterCount(dfilter, 0)
