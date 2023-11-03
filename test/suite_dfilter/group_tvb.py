# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest
from suite_dfilter.dfiltertest import *


class TestDfilterProtocol:
    trace_file = "http.pcap"

    def test_slice_1(self, checkDFilterCount):
        dfilter = "ip[0:2] == 45:00"
        checkDFilterCount(dfilter, 1)

    def test_slice_2(self, checkDFilterCount):
        dfilter = "ip[0:2] == 00:00"
        checkDFilterCount(dfilter, 0)

    def test_slice_3(self, checkDFilterCount):
        dfilter = "ip[2:2] == 00:c1"
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

    def test_protocol_1(self, checkDFilterSucceed):
        dfilter = 'frame contains aa.bb.ff'
        checkDFilterSucceed(dfilter)

    def test_protocol_2(self, checkDFilterFail):
        dfilter = 'frame contains aa.bb.hh'
        checkDFilterFail(dfilter, '"aa.bb.hh" is not a valid byte string')

    def test_protocol_3(self, checkDFilterFail):
        dfilter = 'ip.port == 5'
        checkDFilterFail(dfilter, '"ip.port" is not a valid protocol or protocol field')
