# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import unittest
import fixtures
from suite_dfilter.dfiltertest import *


@fixtures.uses_fixtures
class case_syntax(unittest.TestCase):
    trace_file = "http.pcap"

    def test_exists_1(self, checkDFilterCount):
        dfilter = "frame"
        checkDFilterCount(dfilter, 1)

    def test_commute_1(self, checkDFilterCount):
        dfilter = "ip.proto == 6"
        checkDFilterCount(dfilter, 1)

    def test_commute_2(self, checkDFilterCount):
        dfilter = "6 == ip.proto"
        checkDFilterCount(dfilter, 1)

    def test_func_1(self, checkDFilterCount):
        dfilter = "len(frame) == 207"
        checkDFilterCount(dfilter, 1)

    def test_equal_1(self, checkDFilterCount):
        dfilter = 'ip.addr == 10.0.0.5'
        checkDFilterCount(dfilter, 1)

    def test_equal_2(self, checkDFilterCount):
        dfilter = 'ip.addr == 207.46.134.94'
        checkDFilterCount(dfilter, 1)

    def test_equal_3(self, checkDFilterCount):
        dfilter = 'ip.addr == 10.0.0.5 or ip.addr == 207.46.134.94'
        checkDFilterCount(dfilter, 1)

    def test_equal_4(self, checkDFilterCount):
        dfilter = 'ip.addr == 10.0.0.5 and ip.addr == 207.46.134.94'
        checkDFilterCount(dfilter, 1)

    def test_not_equal_1(self, checkDFilterCount):
        dfilter = 'ip.addr != 10.0.0.5'
        checkDFilterCount(dfilter, 0)

    def test_not_equal_2(self, checkDFilterCount):
        dfilter = 'ip.addr != 207.46.134.94'
        checkDFilterCount(dfilter, 0)

    def test_not_equal_3(self, checkDFilterCount):
        dfilter = 'ip.addr != 10.0.0.5 and ip.addr != 207.46.134.94'
        checkDFilterCount(dfilter, 0)

    def test_not_equal_4(self, checkDFilterCount):
        dfilter = 'ip.addr != 10.0.0.5 or ip.addr != 207.46.134.94'
        checkDFilterCount(dfilter, 0)

    def test_deprecated_1(self, checkDFilterSucceed):
        dfilter = "http && udp || tcp"
        checkDFilterSucceed(dfilter, "suggest parentheses around")

    def test_deprecated_2(self, checkDFilterSucceed):
        dfilter = "bootp"
        checkDFilterSucceed(dfilter, "Deprecated tokens: \"bootp\"")

    def test_deprecated_3(self, checkDFilterSucceed):
        dfilter = "ip.version in {4 6}"
        checkDFilterSucceed(dfilter, "Use ',' to separate set elements")
