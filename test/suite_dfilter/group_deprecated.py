# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import unittest
import fixtures
from suite_dfilter.dfiltertest import *


@fixtures.uses_fixtures
class case_deprecated(unittest.TestCase):

    def test_deprecated_1(self, checkDFilterSucceed):
        dfilter = "http && udp || tcp"
        checkDFilterSucceed(dfilter, "suggest parentheses around")

    def test_deprecated_2(self, checkDFilterSucceed):
        dfilter = "ip.proto ne 17"
        checkDFilterSucceed(dfilter, "Deprecated tokens: \"ne\"")

    def test_deprecated_3(self, checkDFilterSucceed):
        dfilter = "ip.proto != 17"
        checkDFilterSucceed(dfilter, "Deprecated tokens: \"!=\"")

    def test_deprecated_4(self, checkDFilterSucceed):
        dfilter = "bootp"
        checkDFilterSucceed(dfilter, "Deprecated tokens: \"bootp\"")
