# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import unittest
import fixtures
from suite_dfilter.dfiltertest import *


@fixtures.uses_fixtures
class case_bytes_ipv6(unittest.TestCase):
    trace_file = "ipv6.pcap"

    def test_eq_1(self, checkDFilterCount):
        dfilter = "ipv6.dst == ff05::9999"
        checkDFilterCount(dfilter, 1)

    def test_eq_2(self, checkDFilterCount):
        dfilter = "ipv6.dst == ff05::9990"
        checkDFilterCount(dfilter, 0)

    def test_ne_1(self, checkDFilterCount):
        dfilter = "ipv6.dst != ff05::9990"
        checkDFilterCount(dfilter, 1)

    def test_ne_2(self, checkDFilterCount):
        dfilter = "ipv6.dst != ff05::9999"
        checkDFilterCount(dfilter, 0)

    def test_gt_1(self, checkDFilterCount):
        dfilter = "ipv6.dst > ff05::0000"
        checkDFilterCount(dfilter, 1)

    def test_gt_2(self, checkDFilterCount):
        dfilter = "ipv6.dst > ff05::9999"
        checkDFilterCount(dfilter, 0)

    def test_ge_1(self, checkDFilterCount):
        dfilter = "ipv6.dst >= ff05::9999"
        checkDFilterCount(dfilter, 1)

    def test_ge_2(self, checkDFilterCount):
        dfilter = "ipv6.dst >= ff05::a000"
        checkDFilterCount(dfilter, 0)

    def test_lt_1(self, checkDFilterCount):
        dfilter = "ipv6.dst < ff05::a000"
        checkDFilterCount(dfilter, 1)

    def test_lt_2(self, checkDFilterCount):
        dfilter = "ipv6.dst < ff05::9999"
        checkDFilterCount(dfilter, 0)

    def test_le_1(self, checkDFilterCount):
        dfilter = "ipv6.dst <= ff05::9999"
        checkDFilterCount(dfilter, 1)

    def test_le_2(self, checkDFilterCount):
        dfilter = "ipv6.dst <= ff05::9998"
        checkDFilterCount(dfilter, 0)

    def test_cidr_eq_1(self, checkDFilterCount):
        dfilter = "ipv6.dst == ff05::9999/128"
        checkDFilterCount(dfilter, 1)

    def test_cidr_eq_2(self, checkDFilterCount):
        dfilter = "ipv6.dst == ff05::0/64"
        checkDFilterCount(dfilter, 1)

    def test_cidr_eq_3(self, checkDFilterCount):
        dfilter = "ipv6.dst == ff05::ffff/112"
        checkDFilterCount(dfilter, 1)

    def test_cidr_eq_4(self, checkDFilterCount):
        dfilter = "ipv6.dst == ff04::0/64"
        checkDFilterCount(dfilter, 0)

    def test_cidr_ne_1(self, checkDFilterCount):
        dfilter = "ipv6.dst != ff05::9999/128"
        checkDFilterCount(dfilter, 0)

    def test_cidr_ne_2(self, checkDFilterCount):
        dfilter = "ipv6.dst != ff05::0/64"
        checkDFilterCount(dfilter, 0)

    def test_cidr_ne_3(self, checkDFilterCount):
        dfilter = "ipv6.dst != ff05::ffff/112"
        checkDFilterCount(dfilter, 0)

    def test_cidr_ne_4(self, checkDFilterCount):
        dfilter = "ipv6.dst != ff04::00/64"
        checkDFilterCount(dfilter, 1)

    def test_slice_1(self, checkDFilterCount):
        dfilter = "ipv6.dst[14:2] == 99:99"
        checkDFilterCount(dfilter, 1)

    def test_slice_2(self, checkDFilterCount):
        dfilter = "ipv6.dst[14:2] == 00:00"
        checkDFilterCount(dfilter, 0)

    def test_slice_3(self, checkDFilterCount):
        dfilter = "ipv6.dst[15:1] == 99"
        checkDFilterCount(dfilter, 1)

    def test_slice_4(self, checkDFilterCount):
        dfilter = "ipv6.dst[15:1] == 00"

    #
    # Test some addresses are parsed correctly
    #

    def test_unspecified_1(self, checkDFilterCount):
        dfilter = "ipv6.dst == ::"
        checkDFilterCount(dfilter, 0)

    def test_unspecified_2(self, checkDFilterCount):
        dfilter = "ipv6.dst == ::/128"
        checkDFilterCount(dfilter, 0)

    def test_loopback_1(self, checkDFilterCount):
        dfilter = "ipv6.dst == ::1"
        checkDFilterCount(dfilter, 0)

    def test_loopback_2(self, checkDFilterCount):
        dfilter = "ipv6.dst == ::1/128"
        checkDFilterCount(dfilter, 0)

    def test_compress_1(self, checkDFilterCount):
        dfilter = "ipv6.dst == ::2000"
        checkDFilterCount(dfilter, 0)

    def test_compress_2(self, checkDFilterCount):
        dfilter = "ipv6.dst == ::2000/64"
        checkDFilterCount(dfilter, 0)

    def test_compress_3(self, checkDFilterCount):
        dfilter = "ipv6.dst == ::1:2000"
        checkDFilterCount(dfilter, 0)

    def test_compress_4(self, checkDFilterCount):
        dfilter = "ipv6.dst == 2000::"
        checkDFilterCount(dfilter, 0)

    def test_compress_5(self, checkDFilterCount):
        dfilter = "ipv6.dst == 2000::/120"
        checkDFilterCount(dfilter, 0)

    def test_compress_6(self, checkDFilterCount):
        dfilter = "ipv6.dst == 2000:1::"
        checkDFilterCount(dfilter, 0)

    def test_compress_7(self, checkDFilterCount):
        dfilter = "ipv6.dst == 2000:1::2:0"
        checkDFilterCount(dfilter, 0)

    def test_mapped_ipv4_1(self, checkDFilterCount):
        dfilter = "ipv6.dst == ::13.1.68.3"
        checkDFilterCount(dfilter, 0)

    def test_mapped_ipv4_2(self, checkDFilterCount):
        dfilter = "ipv6.dst == ::FFFF:129.144.52.38"
        checkDFilterCount(dfilter, 0)
