# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later


from dftestlib import dftest

class testInteger(dftest.DFTest):
    trace_file = "ntp.pcap"

    def test_eq_1(self):
        dfilter = "ip.version == 4"
        self.assertDFilterCount(dfilter, 1)

    def test_eq_2(self):
        dfilter = "ip.version == 6"
        self.assertDFilterCount(dfilter, 0)

    def test_eq_3(self):
	# Invalid filter (only one equals sign)
        dfilter = "ip.version = 4"
        self.assertDFilterFail(dfilter)

    def test_eq_4(self):
	# Invalid filter
        dfilter = "ip.version == the quick brown fox jumps over the lazy dog"
        self.assertDFilterFail(dfilter)

    def test_eq_5(self):
	# Invalid filter
        dfilter = "ip.version == 4 the quick brown fox jumps over the lazy dog"
        self.assertDFilterFail(dfilter)

    def test_ne_1(self):
        dfilter = "ip.version != 0"
        self.assertDFilterCount(dfilter, 1)

    def test_ne_2(self):
        dfilter = "ip.version != 4"
        self.assertDFilterCount(dfilter, 0)

    def test_u_gt_1(self):
        dfilter = "ip.version > 3"
        self.assertDFilterCount(dfilter, 1)

    def test_u_gt_2(self):
        dfilter = "ip.version > 4"
        self.assertDFilterCount(dfilter, 0)

    def test_u_gt_3(self):
        dfilter = "ip.version > 5"
        self.assertDFilterCount(dfilter, 0)

    def test_u_ge_1(self):
        dfilter = "ip.version >= 3"
        self.assertDFilterCount(dfilter, 1)

    def test_u_ge_2(self):
        dfilter = "ip.version >= 4"
        self.assertDFilterCount(dfilter, 1)

    def test_u_ge_3(self):
        dfilter = "ip.version >= 5"
        self.assertDFilterCount(dfilter, 0)

    def test_u_lt_1(self):
        dfilter = "ip.version < 3"
        self.assertDFilterCount(dfilter, 0)

    def test_u_lt_2(self):
        dfilter = "ip.version < 4"
        self.assertDFilterCount(dfilter, 0)

    def test_u_lt_3(self):
        dfilter = "ip.version < 5"
        self.assertDFilterCount(dfilter, 1)

    def test_u_le_1(self):
        dfilter = "ip.version <= 3"
        self.assertDFilterCount(dfilter, 0)

    def test_u_le_2(self):
        dfilter = "ip.version <= 4"
        self.assertDFilterCount(dfilter, 1)

    def test_u_le_3(self):
        dfilter = "ip.version <= 5"
        self.assertDFilterCount(dfilter, 1)

    def test_s_gt_1(self):
        dfilter = "ntp.precision > -12"
        self.assertDFilterCount(dfilter, 1)

    def test_s_gt_2(self):
        dfilter = "ntp.precision > -11"
        self.assertDFilterCount(dfilter, 0)

    def test_s_gt_3(self):
        dfilter = "ntp.precision > -10"
        self.assertDFilterCount(dfilter, 0)

    def test_s_ge_1(self):
        dfilter = "ntp.precision >= -12"
        self.assertDFilterCount(dfilter, 1)

    def test_s_ge_2(self):
        dfilter = "ntp.precision >= -11"
        self.assertDFilterCount(dfilter, 1)

    def test_s_ge_3(self):
        dfilter = "ntp.precision >= -10"
        self.assertDFilterCount(dfilter, 0)

    def test_s_lt_1(self):
        dfilter = "ntp.precision < -12"
        self.assertDFilterCount(dfilter, 0)

    def test_s_lt_2(self):
        dfilter = "ntp.precision < -11"
        self.assertDFilterCount(dfilter, 0)

    def test_s_lt_3(self):
        dfilter = "ntp.precision < -10"
        self.assertDFilterCount(dfilter, 1)

    def test_s_le_1(self):
        dfilter = "ntp.precision <= -12"
        self.assertDFilterCount(dfilter, 0)

    def test_s_le_2(self):
        dfilter = "ntp.precision <= -11"
        self.assertDFilterCount(dfilter, 1)

    def test_s_le_3(self):
        dfilter = "ntp.precision <= -10"
        self.assertDFilterCount(dfilter, 1)

    def test_bool_eq_1(self):
        dfilter = "ip.flags.df == 0"
        self.assertDFilterCount(dfilter, 1)

    def test_bool_eq_2(self):
        dfilter = "ip.flags.df == 1"
        self.assertDFilterCount(dfilter, 0)

    def test_bool_ne_1(self):
        dfilter = "ip.flags.df != 1"
        self.assertDFilterCount(dfilter, 1)

    def test_bool_ne_2(self):
        dfilter = "ip.flags.df != 0"
        self.assertDFilterCount(dfilter, 0)
