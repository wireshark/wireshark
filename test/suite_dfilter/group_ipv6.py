# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest
from suite_dfilter.dfiltertest import *


class TestDfilterIpv6:
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
        dfilter = "ipv6.dst[15:1] == 153"
        checkDFilterCount(dfilter, 1)

    def test_slice_4(self, checkDFilterCount):
        dfilter = "ipv6.dst[15:1] == 99:"
        checkDFilterCount(dfilter, 1)

    #
    # Test some addresses are parsed correctly
    #

    def test_unspecified_1(self, checkDFilterSucceed):
        dfilter = "ipv6.dst == ::"
        checkDFilterSucceed(dfilter)

    def test_unspecified_2(self, checkDFilterSucceed):
        dfilter = "ipv6.dst == ::/128"
        checkDFilterSucceed(dfilter)

    def test_loopback_1(self, checkDFilterSucceed):
        dfilter = "ipv6.dst == ::1"
        checkDFilterSucceed(dfilter)

    def test_loopback_2(self, checkDFilterSucceed):
        dfilter = "ipv6.dst == ::1/128"
        checkDFilterSucceed(dfilter)

    def test_compress_1(self, checkDFilterSucceed):
        dfilter = "ipv6.dst == ::2000"
        checkDFilterSucceed(dfilter)

    def test_compress_2(self, checkDFilterSucceed):
        dfilter = "ipv6.dst == ::2000/64"
        checkDFilterSucceed(dfilter)

    def test_compress_3(self, checkDFilterSucceed):
        dfilter = "ipv6.dst == ::1:2000"
        checkDFilterSucceed(dfilter)

    def test_compress_4(self, checkDFilterSucceed):
        dfilter = "ipv6.dst == 2000::"
        checkDFilterSucceed(dfilter)

    def test_compress_5(self, checkDFilterSucceed):
        dfilter = "ipv6.dst == 2000::/120"
        checkDFilterSucceed(dfilter)

    def test_compress_6(self, checkDFilterSucceed):
        dfilter = "ipv6.dst == 2000:1::"
        checkDFilterSucceed(dfilter)

    def test_ula_1(self, checkDFilterSucceed):
        dfilter = "ipv6.dst == fd93:c15b:7ae0:2e41:0000:0000:0000:0000"
        checkDFilterSucceed(dfilter)

    def test_ula_2(self, checkDFilterSucceed):
        dfilter = "ipv6.dst == fd93:c15b:7ae0:2e41:ffff:ffff:ffff:ffff"
        checkDFilterSucceed(dfilter)

    def test_ula_3(self, checkDFilterSucceed):
        dfilter = "ipv6.dst == fd93:c15b:7ae0:2e41:3f32:35c9:40aa:1243"
        checkDFilterSucceed(dfilter)

    def test_ula_4(self, checkDFilterSucceed):
        dfilter = "ipv6.dst == fd93:c15b:7ae0:2e41::2:1"
        checkDFilterSucceed(dfilter)

    def test_mapped_ipv4_1(self, checkDFilterSucceed):
        dfilter = "ipv6.dst == ::13.1.68.3"
        checkDFilterSucceed(dfilter)

    def test_mapped_ipv4_2(self, checkDFilterSucceed):
        dfilter = "ipv6.dst == ::FFFF:129.144.52.38"
        checkDFilterSucceed(dfilter)
