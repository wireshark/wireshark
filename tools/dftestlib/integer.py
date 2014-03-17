# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


from dftestlib import dftest

class testInteger(dftest.DFTest):
    trace_file = "ntp.pcap"

    def test_eq_1(self):
        dfilter = "ip.version == 4"
        self.assertDFilterCount(dfilter, 1)

    def test_eq_2(self):
        dfilter = "ip.version == 6"
        self.assertDFilterCount(dfilter, 0)

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
