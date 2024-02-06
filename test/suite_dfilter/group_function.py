# Copyright (c) 2019 by Dario Lombardo <lomato@gmail.com>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest
from suite_dfilter.dfiltertest import *

class TestFunctionString:
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

class TestFunctionMaxMin:
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

    def test_max_4(self, checkDFilterCount):
        dfilter = 'max(5060, udp.dstport) == udp.srcport'
        checkDFilterCount(dfilter, 2)

    def test_max_5(self, checkDFilterCount):
        dfilter = 'max(5060, 5070) == udp.srcport'
        checkDFilterCount(dfilter, 1)

class TestFunctionAbs:
    trace_file = "dhcp.pcapng"

    def test_function_abs_1(self, checkDFilterCount):
        dfilter = 'udp.dstport == abs(-67)'
        checkDFilterCount(dfilter, 2)

class TestFunctionLen:
    trace_file = "http.pcap"

    def test_function_len_1(self, checkDFilterCount):
        dfilter = 'len(http.host) == 27'
        checkDFilterCount(dfilter, 1)

    def test_function_len_2(self, checkDFilterCount):
        dfilter = 'len(http.host) != 0'
        checkDFilterCount(dfilter, 1)

    def test_function_len_3(self, checkDFilterCount):
        dfilter = 'len(http.host) == 0'
        checkDFilterCount(dfilter, 0)

    def test_function_len_4(self, checkDFilterCount):
        dfilter = 'len(http.host)'
        checkDFilterCount(dfilter, 1)

    def test_function_len_5(self, checkDFilterCount):
        dfilter = '!len(http.host)'
        checkDFilterCount(dfilter, 0)

class TestFunctionNested:
    trace_file = 'http.pcap'

    def test_function_nested_1(self, checkDFilterCount):
        dfilter = 'abs(min(tcp.srcport, tcp.dstport)) == 80'
        checkDFilterCount(dfilter, 1)

    def test_function_nested_2(self, checkDFilterCount):
        dfilter = 'min(tcp.srcport * 10, tcp.dstport * 10, udp.srcport * 10, udp.dstport * 10) == 800'
        checkDFilterCount(dfilter, 1)

    def test_function_nested_3(self, checkDFilterCount):
        dfilter = 'min(len(tcp.payload), len(udp.payload)) == 153'
        checkDFilterCount(dfilter, 1)

    def test_function_nested_4(self, checkDFilterCount):
        # udp.payload does not exist. Check that len(udp.payload) + 2
        # resolves to NULL, not to 2.
        dfilter = 'min(len(tcp.payload[2:]) + 2, len(udp.payload[2:]) + 2) == 153'
        checkDFilterCount(dfilter, 1)
