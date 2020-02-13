#
# -*- coding: utf-8 -*-
# Wireshark tests
#
# Copyright (c) 2019 Gerald Combs <gerald@wireshark.org>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Release tests'''

import fixtures
import re
import subprocess
import subprocesstest
import types

@fixtures.fixture
def wireshark_features(request, cmd_wireshark, make_env):
    '''
    Returns an object describing available features in Wireshark. Tests
    will be skipped unless --enable-release is passed on the command line.
    '''
    enabled = request.config.getoption('--enable-release', default=False)
    if not enabled:
        fixtures.skip('Release tests are not enabled via --enable-release')

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

@fixtures.uses_fixtures
class case_release_automatic_updates(subprocesstest.SubprocessTestCase):
    def test_automatic_updates_present(self, wireshark_features):
        '''Checks whether Wireshark was built with automatic updates.'''

        self.assertTrue(wireshark_features.have_automatic_updates);
