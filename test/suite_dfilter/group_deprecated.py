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
        dfilter = "bootp"
        checkDFilterSucceed(dfilter, "Deprecated tokens: \"bootp\"")
