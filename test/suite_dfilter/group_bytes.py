# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest
from suite_dfilter.dfiltertest import *


class TestDfilterBytes:
    trace_file = "arp.pcap"

    def test_bytes_1(self, checkDFilterCount):
        dfilter = "arp.dst.hw == 00:64"
        checkDFilterCount(dfilter, 1)

    def test_ipv6_2(self, checkDFilterCount):
        dfilter = "arp.dst.hw == 00:00"
        checkDFilterCount(dfilter, 0)
