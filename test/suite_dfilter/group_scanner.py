# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

# from suite_dfilter.dfiltertest import *


class TestDfilterScanner:
    trace_file = "http.pcap"

    def test_dquote_1(self, checkDFilterCount):
        dfilter = 'http.request.method == "HEAD"'
        checkDFilterCount(dfilter, 1)

    def test_dquote_2(self, checkDFilterCount):
        dfilter = 'http.request.method == "\\x48EAD"'
        checkDFilterCount(dfilter, 1)

    def test_dquote_3(self, checkDFilterCount):
        dfilter = 'http.request.method == "\\x58EAD"'
        checkDFilterCount(dfilter, 0)

    def test_dquote_4(self, checkDFilterCount):
        dfilter = 'http.request.method == "\\110EAD"'
        checkDFilterCount(dfilter, 1)

    def test_dquote_5(self, checkDFilterCount):
        dfilter = 'http.request.method == "\\111EAD"'
        checkDFilterCount(dfilter, 0)

    def test_dquote_6(self, checkDFilterFail):
        dfilter = r'http.request.method == "\HEAD"'
        checkDFilterFail(dfilter, 'not a valid character escape sequence')

    def test_case_insensitive_1(self, checkDFilterSucceed):
        # Token matching is case insensitive
        dfilter = 'tcp AnD http'
        checkDFilterSucceed(dfilter)

    def test_case_insensitive_2(self, checkDFilterFail):
        # The resulting matched text is not
        dfilter = 'tcp and hTTp'
        error = '"hTTp" is not a valid protocol or protocol field.'
        checkDFilterFail(dfilter, error)

    def test_case_insensitive_3(self, checkDFilterFail):
        # The resulting matched text is not, function name test
        dfilter = 'http.host == uPPer("myhost")'
        error = "Function 'uPPer' does not exist"
        checkDFilterFail(dfilter, error)

    def test_case_insensitive_4(self, checkDFilterSucceed):
        # A lower case \u UCN has exactly four hex digits; the rest are
        # ASCII literals. Also, a UCN is allowed to represent a value in
        # the basic character set inside a quoted string literal.
        dfilter = 'http.request.uri.query.parameter == "\u0030307011208"'
        checkDFilterSucceed(dfilter)
