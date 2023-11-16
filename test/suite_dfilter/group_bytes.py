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

class TestDfilterBytesSyntax:

    def test_oid_1(self, checkDFilterSucceed):
        # OID value on the RHS is similar to a field name with all digits.
        dfilter = "snmp.name == 1.3.6.1.2.1.1.3.0"
        checkDFilterSucceed(dfilter)
