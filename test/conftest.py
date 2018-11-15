#
# -*- coding: utf-8 -*-
# Wireshark tests
#
# Copyright (c) 2018 Peter Wu <peter@lekensteyn.nl>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''py.test configuration'''

import fixtures

def pytest_addoption(parser):
    parser.addoption('--disable-capture', action='store_true',
        help='Disable capture tests'
    )
    parser.addoption('--capture-interface',
        help='Capture interface index or name.'
    )
    parser.addoption('--program-path', help='Path to Wireshark executables.')

_all_test_groups = None

# this is set only to please case_unittests.test_unit_ctest_coverage
def pytest_collection_modifyitems(items):
    '''Find all test groups.'''
    global _all_test_groups
    suites = []
    for item in items:
        name = item.nodeid.split("::")[0].replace(".py", "").replace("/", ".")
        if name not in suites:
            suites.append(name)
    _all_test_groups = sorted(suites)

# Must enable pytest before importing fixtures_ws.
fixtures.enable_pytest()
from fixtures_ws import *

@fixtures.fixture(scope='session')
def all_test_groups():
    return _all_test_groups
