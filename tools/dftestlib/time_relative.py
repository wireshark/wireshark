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

class testTimeRelative(dftest.DFTest):
    trace_file = "nfs.pcap"

    def test_relative_time_1(self):
        dfilter = "frame.time_delta == 0.7"
        self.assertDFilterCount(dfilter, 1)

    def test_relative_time_2(self):
        dfilter = "frame.time_delta > 0.7"
        self.assertDFilterCount(dfilter, 0)

    def test_relative_time_3(self):
        dfilter = "frame.time_delta < 0.7"
        self.assertDFilterCount(dfilter, 1)

