#
# -*- coding: utf-8 -*-
# Wireshark tests
#
# Copyright (c) 2018 Peter Wu <peter@lekensteyn.nl>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''py.test configuration'''

import os
import sys
import config


# XXX remove globals in config and create py.test-specific fixtures
try:
    _program_path = os.environ['WS_BIN_PATH']
except KeyError:
    print('Please set env var WS_BIN_PATH to the run directory with binaries')
    sys.exit(1)
if not config.setProgramPath(_program_path):
    print('One or more required executables not found at {}\n'.format(_program_path))
    sys.exit(1)

# this is set only to please case_unittests.test_unit_ctest_coverage
def pytest_collection_modifyitems(items):
    '''Find all test groups.'''
    suites = []
    for item in items:
        name = item.nodeid.split("::")[0].replace(".py", "").replace("/", ".")
        if name not in suites:
            suites.append(name)
    config.all_groups = list(sorted(suites))
