#
# Copyright (c) 2023 by João Valverde <j@v6e.pt>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest
from suite_dfilter.dfiltertest import *

class TestDfilterMacro:
    trace_file = "http.pcap"

    def test_macro_1(self, checkDFilterCount):
        dfilter = "$private_ipv4(ip.src)"
        checkDFilterCount(dfilter, 1)

    def test_macro_2(self, checkDFilterCount):
        dfilter = "${private_ipv4:ip.src}"
        checkDFilterCount(dfilter, 1)
