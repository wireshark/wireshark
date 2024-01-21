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

    def test_macro_3(self, checkDFilterCount):
        dfilter = "${private_ipv4;ip.src}"
        checkDFilterCount(dfilter, 1)

class TestDfilterMacroZeroArg:
    trace_file = "nfs.pcap"

    def test_macro_1(self, checkDFilterCount):
        dfilter = "$nfs()"
        checkDFilterCount(dfilter, 2)

    def test_macro_2(self, checkDFilterCount):
        dfilter = "${nfs}"
        checkDFilterCount(dfilter, 2)

    def test_macro_3(self, checkDFilterCount):
        dfilter = "${nfs:}"
        checkDFilterCount(dfilter, 2)

    def test_macro_wrong_count_1(self, checkDFilterFail):
        dfilter = "${private_ipv4}"
        checkDFilterFail(dfilter, "wrong number of arguments for macro")

    def test_macro_wrong_count_2(self, checkDFilterFail):
        dfilter = "${private_ipv4:}"
        checkDFilterFail(dfilter, "wrong number of arguments for macro")

    def test_macro_wrong_count_3(self, checkDFilterFail):
        dfilter = "$private_ipv4()"
        checkDFilterFail(dfilter, "wrong number of arguments for macro")

class TestDfilterMacroNullArg:
    trace_file = "nfs.pcap"

    def test_macro_works(self, checkDFilterCount):
        dfilter = "$ip(198.95.230.20, 2049)"
        checkDFilterCount(dfilter, 2)

    def test_macro_null_1(self, checkDFilterFail):
        dfilter = "$ip(198.95.230.20,)"
        checkDFilterFail(dfilter, "null argument")

    def test_macro_null_2(self, checkDFilterFail):
        dfilter = "${ip:;2049}"
        checkDFilterFail(dfilter, "null argument")
