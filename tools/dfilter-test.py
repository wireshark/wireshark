#!/usr/bin/env python
"""
Test-suite to test wireshark's dfilter mechanism.
"""

#
# Copyright (C) 2003-2013 by Gilbert Ramirez <gram@alumni.rice.edu>
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

import os
import sys
import types
import unittest

# Import each test class so unittest.main() can find them
from dftestlib.bytes_type import testBytes
from dftestlib.bytes_ether import testBytesEther
from dftestlib.bytes_ipv6 import testBytesIPv6
from dftestlib.double import testDouble
from dftestlib.integer import testInteger
from dftestlib.integer_1byte import testInteger1Byte
from dftestlib.ipv4 import testIPv4
from dftestlib.range_method import testRange
from dftestlib.scanner import testScanner
from dftestlib.string_type import testString
from dftestlib.stringz import testStringz
from dftestlib.time_type import testTime
from dftestlib.time_relative import testTimeRelative
from dftestlib.tvb import testTVB
from dftestlib.uint64 import testUINT64

if __name__ == "__main__":
    unittest.main(verbosity=2)
