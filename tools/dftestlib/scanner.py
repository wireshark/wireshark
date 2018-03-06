# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later


from dftestlib import dftest

class testScanner(dftest.DFTest):
    trace_file = "http.pcap"

    def test_dquote_1(self):
        dfilter = 'http.request.method == "HEAD"'
        self.assertDFilterCount(dfilter, 1)

    def test_dquote_2(self):
        dfilter = 'http.request.method == "\\x48EAD"'
        self.assertDFilterCount(dfilter, 1)

    def test_dquote_3(self):
        dfilter = 'http.request.method == "\\x58EAD"'
        self.assertDFilterCount(dfilter, 0)

    def test_dquote_4(self):
        dfilter = 'http.request.method == "\\110EAD"'
        self.assertDFilterCount(dfilter, 1)

    def test_dquote_5(self):
        dfilter = 'http.request.method == "\\111EAD"'
        self.assertDFilterCount(dfilter, 0)

    def test_dquote_6(self):
        dfilter = 'http.request.method == "\\HEAD"'
        self.assertDFilterCount(dfilter, 1)
