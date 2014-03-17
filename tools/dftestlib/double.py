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

class testDouble(dftest.DFTest):

    trace_file = "ntp.pcap"

    def test_eq_1(self):
        dfilter = "ntp.rootdelay == 0.0626983642578125"
        self.assertDFilterCount(dfilter, 1)

    def test_eq_2(self):
        dfilter = "ntp.rootdelay == 0.0626"
        self.assertDFilterCount(dfilter, 0)

    def test_gt_1(self):
        dfilter = "ntp.rootdelay > 1.0626"
        self.assertDFilterCount(dfilter, 0)

    def test_gt_2(self):
        dfilter = "ntp.rootdelay >  0.0626983642578125"
        self.assertDFilterCount(dfilter, 0)

    def test_gt_3(self):
        dfilter = "ntp.rootdelay >  0.0026"
        self.assertDFilterCount(dfilter, 1)

    def test_ge_1(self):
        dfilter = "ntp.rootdelay >= 1.0026"
        self.assertDFilterCount(dfilter, 0)

    def test_ge_2(self):
        dfilter = "ntp.rootdelay >=  0.0626983642578125"
        self.assertDFilterCount(dfilter, 1)

    def test_ge_3(self):
        dfilter = "ntp.rootdelay >=  0.0026"
        self.assertDFilterCount(dfilter, 1)

    def test_lt_1(self):
        dfilter = "ntp.rootdelay < 1.0026"
        self.assertDFilterCount(dfilter, 1)

    def test_lt_2(self):
        dfilter = "ntp.rootdelay <  0.0626983642578125"
        self.assertDFilterCount(dfilter, 0)

    def test_lt_3(self):
        dfilter = "ntp.rootdelay <  0.0026"
        self.assertDFilterCount(dfilter, 0)

    def test_le_1(self):
        dfilter = "ntp.rootdelay <= 1.0026"
        self.assertDFilterCount(dfilter, 1)

    def test_le_2(self):
        dfilter = "ntp.rootdelay <=  0.0626983642578125"
        self.assertDFilterCount(dfilter, 1)

    def test_le_3(self):
        dfilter = "ntp.rootdelay <=  0.0026"
        self.assertDFilterCount(dfilter, 0)
