# Copyright (c) 2019 by Dario Lombardo <lomato@gmail.com>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import unittest
import fixtures
from suite_dfilter.dfiltertest import *

@fixtures.uses_fixtures
class case_dfunction_string(unittest.TestCase):
    trace_file = "dhcp.pcap"

    def test_matches_1(self, checkDFilterCount):
        dfilter = "string(frame.number) matches \"[13579]$\""
        checkDFilterCount(dfilter, 2)

    def test_contains_1(self, checkDFilterCount):
        dfilter = "string(eth.src) contains \"00:08:74\""
        checkDFilterCount(dfilter, 2)

    def test_fail_1(self, checkDFilterFail):
        # Invalid filter (only non-string fields are supported)
        dfilter = "string(dhcp.server) == hostname"
        error = 'String conversion for field "dhcp.server" is not supported'
        checkDFilterFail(dfilter, error)

    def test_fail_2(self, checkDFilterFail):
        # Invalid field: value
        dfilter = "string(123) == \"123\""
        error = 'Only fields can be used as parameter for string()'
        checkDFilterFail(dfilter, error)

    def test_fail_3(self, checkDFilterFail):
        # Invalid field: protocol
        dfilter = "string(dhcp) == hostname"
        error = 'String conversion for field "dhcp" is not supported'
        checkDFilterFail(dfilter, error)

    def test_fail_4(self, checkDFilterFail):
        # Invalid field: bytes
        dfilter = "string(dhcp.option.value) == \"hostname\""
        error = 'String conversion for field "dhcp.option.value" is not supported'
        checkDFilterFail(dfilter, error)

@fixtures.uses_fixtures
class case_dfunction_maxmin(unittest.TestCase):
    trace_file = "sip.pcapng"

    def test_min_1(self, checkDFilterCount):
        dfilter = 'min(udp.srcport, udp.dstport) == 5060'
        checkDFilterCount(dfilter, 5)

    def test_min_2(self, checkDFilterCount):
        dfilter = 'min(udp.srcport, udp.dstport) == 5070'
        checkDFilterCount(dfilter, 0)

    def test_max_1(self, checkDFilterCount):
        dfilter = 'max(udp.srcport, udp.dstport) == 5070'
        checkDFilterCount(dfilter, 3)

    def test_max_2(self, checkDFilterCount):
        dfilter = 'max(udp.srcport, udp.dstport) == 5060'
        checkDFilterCount(dfilter, 2)

    def test_max_3(self, checkDFilterCount):
        dfilter = 'max(udp.srcport, udp.dstport) < 5060'
        checkDFilterCount(dfilter, 1)
