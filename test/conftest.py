#
# Wireshark tests
#
# Copyright (c) 2018 Peter Wu <peter@lekensteyn.nl>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''pytest configuration'''


def pytest_addoption(parser):
    parser.addoption('--disable-capture', action='store_true',
        help='Disable capture tests'
    )
    parser.addoption('--disable-gui', action='store_true',
        help='Disable GUI tests'
    )
    parser.addoption('--build-type', default='RelWithDebInfo',
        help='CMake build type for multi-config generators.'
    )
    parser.addoption('--program-path',
        help='Path to Wireshark executables.'
    )
    parser.addoption('--skip-missing-programs',
        help='Skip tests that lack programs from this list instead of failing'
             ' them. Use "all" to ignore all missing programs.'
    )
    parser.addoption('--enable-release', action='store_true',
        help='Enable release tests'
    )

from fixtures_ws import *

