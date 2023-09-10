#
# Wireshark tests
#
# Copyright (c) 2019 Gerald Combs <gerald@wireshark.org>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Release tests'''

import re
import subprocess
import types
import pytest

@pytest.fixture
def wireshark_features(request, cmd_wireshark, make_env):
    '''
    Returns an object describing available features in Wireshark. Tests
    will be skipped unless --enable-release is passed on the command line.
    '''
    enabled = request.config.getoption('--enable-release', default=False)
    if not enabled:
        pytest.skip('Release tests are not enabled via --enable-release')
    disabled = request.config.getoption('--disable-gui', default=False)
    if disabled:
        pytest.skip('GUI tests are disabled via --disable-gui')

    try:
        wireshark_v = subprocess.check_output(
            (cmd_wireshark, '--version'),
            stderr=subprocess.PIPE,
            universal_newlines=True,
            env=make_env()
        )
        wireshark_v = re.sub(r'\s+', ' ', wireshark_v)
    except subprocess.CalledProcessError as ex:
        print('Failed to detect Wireshark features: %s' % (ex,))
        wireshark_v = ''
    return types.SimpleNamespace(
        have_automatic_updates='with automatic updates' in wireshark_v,
    )

class TestReleaseAutomaticUpdates:
    def test_automatic_updates_present(self, wireshark_features):
        '''Checks whether Wireshark was built with automatic updates.'''

        assert wireshark_features.have_automatic_updates
