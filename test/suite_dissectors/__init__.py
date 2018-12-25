#
# Copyright (C) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import os.path
import unittest

# Run by unittest.defaultTestLoader.discover in test.py


def load_tests(loader, standard_tests, pattern):
    this_dir = os.path.dirname(__file__)
    package_tests = loader.discover(start_dir=this_dir, pattern='group_*.py')
    standard_tests.addTests(package_tests)
    return standard_tests
