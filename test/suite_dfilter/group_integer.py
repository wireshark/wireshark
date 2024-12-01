# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest
from suite_dfilter.dfiltertest import *


class TestDfilterInteger:
    trace_file = "ntp.pcap"

    def test_eq_1(self, checkDFilterCount):
        dfilter = "ip.version == 4"
        checkDFilterCount(dfilter, 1)

    def test_eq_2(self, checkDFilterCount):
        dfilter = "ip.version == 6"
        checkDFilterCount(dfilter, 0)

    def test_eq_3(self, checkDFilterFail):
        # Invalid filter (only one equals sign)
        dfilter = "ip.version = 4"
        error = '"=" was unexpected in this context.'
        checkDFilterFail(dfilter, error)

    def test_eq_4(self, checkDFilterFail):
        # Invalid filter
        dfilter = "ip.version == the quick brown fox jumps over the lazy dog"
        error = '"quick" was unexpected in this context.'
        checkDFilterFail(dfilter, error)

    def test_eq_5(self, checkDFilterFail):
        # Invalid filter
        dfilter = "ip.version == 4 the quick brown fox jumps over the lazy dog"
        error = '"the" was unexpected in this context.'
        checkDFilterFail(dfilter, error)

    def test_eq_6(self, checkDFilterCount):
        dfilter = "udp.srcport == 123"
        checkDFilterCount(dfilter, 1)

    def test_eq_7(self, checkDFilterCount):
        dfilter = "udp.srcport == 0173"
        checkDFilterCount(dfilter, 1)

    def test_eq_8(self, checkDFilterCount):
        dfilter = "udp.srcport == 0x7B"
        checkDFilterCount(dfilter, 1)

    def test_eq_9(self, checkDFilterCount):
        dfilter = "udp.srcport == 0b1111011"
        checkDFilterCount(dfilter, 1)

    def test_ne_1(self, checkDFilterCount):
        dfilter = "ip.version != 0"
        checkDFilterCount(dfilter, 1)

    def test_ne_2(self, checkDFilterCount):
        dfilter = "ip.version != 4"
        checkDFilterCount(dfilter, 0)

    def test_u_gt_1(self, checkDFilterCount):
        dfilter = "ip.version > 3"
        checkDFilterCount(dfilter, 1)

    def test_u_gt_2(self, checkDFilterCount):
        dfilter = "ip.version > 4"
        checkDFilterCount(dfilter, 0)

    def test_u_gt_3(self, checkDFilterCount):
        dfilter = "ip.version > 5"
        checkDFilterCount(dfilter, 0)

    def test_u_ge_1(self, checkDFilterCount):
        dfilter = "ip.version >= 3"
        checkDFilterCount(dfilter, 1)

    def test_u_ge_2(self, checkDFilterCount):
        dfilter = "ip.version >= 4"
        checkDFilterCount(dfilter, 1)

    def test_u_ge_3(self, checkDFilterCount):
        dfilter = "ip.version >= 5"
        checkDFilterCount(dfilter, 0)

    def test_u_lt_1(self, checkDFilterCount):
        dfilter = "ip.version < 3"
        checkDFilterCount(dfilter, 0)

    def test_u_lt_2(self, checkDFilterCount):
        dfilter = "ip.version < 4"
        checkDFilterCount(dfilter, 0)

    def test_u_lt_3(self, checkDFilterCount):
        dfilter = "ip.version < 5"
        checkDFilterCount(dfilter, 1)

    def test_u_le_1(self, checkDFilterCount):
        dfilter = "ip.version <= 3"
        checkDFilterCount(dfilter, 0)

    def test_u_le_2(self, checkDFilterCount):
        dfilter = "ip.version <= 4"
        checkDFilterCount(dfilter, 1)

    def test_u_le_3(self, checkDFilterCount):
        dfilter = "ip.version <= 5"
        checkDFilterCount(dfilter, 1)

    def test_s_gt_1(self, checkDFilterCount):
        dfilter = "ntp.precision > -12"
        checkDFilterCount(dfilter, 1)

    def test_s_gt_2(self, checkDFilterCount):
        dfilter = "ntp.precision > -11"
        checkDFilterCount(dfilter, 0)

    def test_s_gt_3(self, checkDFilterCount):
        dfilter = "ntp.precision > -10"
        checkDFilterCount(dfilter, 0)

    def test_s_ge_1(self, checkDFilterCount):
        dfilter = "ntp.precision >= -12"
        checkDFilterCount(dfilter, 1)

    def test_s_ge_2(self, checkDFilterCount):
        dfilter = "ntp.precision >= -11"
        checkDFilterCount(dfilter, 1)

    def test_s_ge_3(self, checkDFilterCount):
        dfilter = "ntp.precision >= -10"
        checkDFilterCount(dfilter, 0)

    def test_s_lt_1(self, checkDFilterCount):
        dfilter = "ntp.precision < -12"
        checkDFilterCount(dfilter, 0)

    def test_s_lt_2(self, checkDFilterCount):
        dfilter = "ntp.precision < -11"
        checkDFilterCount(dfilter, 0)

    def test_s_lt_3(self, checkDFilterCount):
        dfilter = "ntp.precision < -10"
        checkDFilterCount(dfilter, 1)

    def test_s_le_1(self, checkDFilterCount):
        dfilter = "ntp.precision <= -12"
        checkDFilterCount(dfilter, 0)

    def test_s_le_2(self, checkDFilterCount):
        dfilter = "ntp.precision <= -11"
        checkDFilterCount(dfilter, 1)

    def test_s_le_3(self, checkDFilterCount):
        dfilter = "ntp.precision <= -10"
        checkDFilterCount(dfilter, 1)

    def test_s_chained(self, checkDFilterCount):
        dfilter = "-12 < ntp.precision < -2 < ntp.ppoll < 8"
        checkDFilterCount(dfilter, 1)

    def test_bool_eq_1(self, checkDFilterCount):
        dfilter = "ip.flags.df == 0"
        checkDFilterCount(dfilter, 1)

    def test_bool_eq_2(self, checkDFilterCount):
        dfilter = "ip.flags.df == 1"
        checkDFilterCount(dfilter, 0)

    def test_bool_ne_1(self, checkDFilterCount):
        dfilter = "ip.flags.df != 1"
        checkDFilterCount(dfilter, 1)

    def test_bool_ne_2(self, checkDFilterCount):
        dfilter = "ip.flags.df != 0"
        checkDFilterCount(dfilter, 0)

    def test_mixed_gt_1(self, checkDFilterCount):
        # Compare an unsigned integer to a signed integer.
        dfilter = "ip.version > ntp.precision"
        checkDFilterCount(dfilter, 1)

class TestDfilterInteger1Byte:

    trace_file = "ipx_rip.pcap"

    def test_ipx_1(self, checkDFilterCount):
        dfilter = "ipx.src.net == 0x28"
        checkDFilterCount(dfilter, 1)

    def test_ipx_2(self, checkDFilterCount):
        dfilter = "ipx.src.net == 0x29"
        checkDFilterCount(dfilter, 0)

class TestDfilterUint64:
    trace_file = "nfs.pcap"

    def test_uint64_1(self, checkDFilterCount):
        dfilter = "nfs.fattr3.size == 264032"
        checkDFilterCount(dfilter, 1)

    def test_uint64_2(self, checkDFilterCount):
        dfilter = "nfs.fattr3.size == 264000"
        checkDFilterCount(dfilter, 0)
